// Copyright (C) 2026, Hanzo AI Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package canonical

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"

	"github.com/luxfi/crypto"
	"github.com/luxfi/geth/common"
)

// ErrNonFiniteEmbedding is returned when an embedding vector contains a NaN or
// ±Inf component. Quantization MUST reject these: float→int conversion of a
// non-finite value is implementation-defined in Go (the spec only guarantees the
// conversion "succeeds" with an "implementation-dependent" result), and the
// hardware truncation instructions disagree — arm64 FCVTZS and wasm
// I64TruncSatF64S saturate (+Inf→0xFF i.e. -1) while amd64/386 CVTTSD2SI yield
// the integer-indefinite (+Inf→0x00 i.e. 0). A non-finite component (reachable
// when two operators' BLAS/FMA contraction differ enough that one overflows to
// ±Inf or NaN) would therefore quantize to DIFFERENT bytes on different operator
// hosts and silently split the embedding quorum — worse, a single ±Inf forces
// scale=±Inf and collapses the ENTIRE vector to zero. Failing closed here turns
// that silent divergence into an explicit per-operator job failure (operator.Run
// propagates the error, so the operator declines to commit rather than committing
// a host-dependent hash). This is the embedding analog of ParseDecision's
// fail-secure discipline.
var ErrNonFiniteEmbedding = errors.New("canonical: embedding contains a non-finite (NaN/Inf) component")

// QuantizeEmbedding deterministically quantizes a float32 embedding to int8 and
// returns the canonical serialization plus the chosen scale. The serialization
// is:
//
//	canonical_serialized_embedding = u32be(dim) || int8[dim] || f32be(scale)
//
// The quantization is symmetric, per-vector:
//
//	scale = max(|v_i|) / 127           (all-zero vector => scale = 1)
//	q_i   = round_half_to_even(v_i / scale)  clamped to [-127, 127]
//
// # Why this exact recipe
//
//   - Symmetric int8 (range [-127,127], not -128) keeps the quantization grid
//     centered on zero and avoids the asymmetric -128 endpoint, so q and -q are
//     always both representable.
//   - round-half-to-even (banker's rounding) is the IEEE default-rounding
//     discipline and, critically, is direction-unbiased: a stream of exact-.5
//     values does not systematically drift up. math.RoundToEven implements it
//     exactly for the .5 case.
//   - The scale is serialized as the SAME float32 used in the division, so a
//     verifier reconstructs the identical grid.
//
// # Cross-hardware fragility (documented; surfaced for RED)
//
// Determinism here is only as strong as the determinism of the inputs. The same
// engine build on the same host produces bit-identical embedding floats
// (proven), so two such operators quantize to identical int8 and identical
// embedding_hash. ACROSS heterogeneous hosts the embedding floats themselves can
// differ in the low bits (different BLAS, FMA contraction, GPU vs CPU). When
// that happens:
//
//   - a component sitting exactly on a quantization boundary (v_i/scale == x.5)
//     on one host but x.4999997 on another rounds to different int8 values, and
//   - the scale (= max|v_i|/127) can itself differ if the max component differs,
//     shifting the WHOLE grid and changing many int8 values at once.
//
// Either flips embedding_hash and excludes the operator from the embedding
// quorum group. The mitigation is policy, not code: operators in one embedding
// quorum MUST run matching engine builds on matching hardware (pinned by
// ModelSpec.RuntimeVersion + EmbeddingModelHash), OR the embedding is carried as
// non-consensus metadata. This boundary is the single most fragile point in the
// wire spec and is called out for the red team explicitly.
func QuantizeEmbedding(v []float32) (serialized []byte, scale float32, err error) {
	dim := len(v)

	// Boundary validation: reject non-finite components BEFORE any arithmetic, so
	// an implementation-defined float→int8 conversion can never reach the wire and
	// make two honest operators disagree. (See ErrNonFiniteEmbedding.)
	for i, x := range v {
		if math.IsNaN(float64(x)) || math.IsInf(float64(x), 0) {
			return nil, 0, fmt.Errorf("%w: component %d = %v", ErrNonFiniteEmbedding, i, x)
		}
	}

	// scale = max(|v_i|) / 127, computed in float32 to match what we serialize.
	var maxAbs float32
	for _, x := range v {
		a := x
		if a < 0 {
			a = -a
		}
		if a > maxAbs {
			maxAbs = a
		}
	}
	scale = maxAbs / 127
	if scale == 0 {
		// All-zero (or empty) vector: avoid div-by-zero and give a well-defined,
		// reproducible grid. Every q_i will be 0.
		scale = 1
	}

	q := make([]int8, dim)
	for i, x := range v {
		// Divide and round in float64 from the float32 scale. Using the float32
		// scale (the serialized value) keeps verifier and prover on the same grid;
		// float64 arithmetic gives the rounding headroom.
		r := math.RoundToEven(float64(x) / float64(scale))
		if r > 127 {
			r = 127
		} else if r < -127 {
			r = -127
		}
		q[i] = int8(r)
	}

	// u32be(dim) || int8[dim] || f32be(scale)
	out := make([]byte, 0, 4+dim+4)
	var d4 [4]byte
	binary.BigEndian.PutUint32(d4[:], uint32(dim))
	out = append(out, d4[:]...)
	for _, qi := range q {
		out = append(out, byte(qi)) // two's-complement int8 -> one byte
	}
	var s4 [4]byte
	binary.BigEndian.PutUint32(s4[:], math.Float32bits(scale))
	out = append(out, s4[:]...)
	return out, scale, nil
}

// EmbeddingHash quantizes the embedding and returns keccak256 of its canonical
// serialization. This is the embedding_hash field bound into the commit. Two
// operators with bit-identical embeddings (same engine, same host) produce the
// same hash; see QuantizeEmbedding for the cross-hardware caveat. Returns
// ErrNonFiniteEmbedding if any component is NaN/Inf (fail-closed; never emits a
// host-dependent hash).
func EmbeddingHash(v []float32) (common.Hash, error) {
	serialized, _, err := QuantizeEmbedding(v)
	if err != nil {
		return common.Hash{}, err
	}
	return common.BytesToHash(crypto.Keccak256(serialized)), nil
}
