// Copyright (C) 2026, Hanzo AI Inc. All rights reserved.
// RED-2: embedding quantization determinism — regression tests for the
// non-finite-component fix (canonical.ErrNonFiniteEmbedding).
//
// THE BUG (pre-fix): QuantizeEmbedding passed each component through int8(r)
// without rejecting NaN/Inf. Go's float→int conversion is implementation-defined
// for non-finite/out-of-range values, and the hardware truncation instructions
// disagree: arm64 FCVTZS and wasm I64TruncSatF64S saturate (+Inf → 0xFF = -1),
// while amd64/386 CVTTSD2SI yield the integer-indefinite (+Inf → 0x00 = 0). A
// non-finite component is reachable when two honest operators' BLAS/FMA
// contraction differ enough that one overflows a value to ±Inf or NaN — and a
// single ±Inf forces scale=±Inf, collapsing the WHOLE vector to zero. Either way
// two honest operators compute different embedding_hash and silently fall out of
// the embedding quorum.
//
// THE FIX: quantization rejects any non-finite component (fail-closed). The
// operator then declines to commit (operator.Run propagates the error) rather
// than committing a host-dependent hash.
//
// Run (pure Go, no engine):  GOWORK=off CGO_ENABLED=1 go test -run RED2_ .
package operator

import (
	"errors"
	"math"
	"testing"

	"github.com/hanzoai/chains/hanzo-evm/operator/canonical"
)

// Every non-finite shape must now be rejected by BOTH QuantizeEmbedding and
// EmbeddingHash. Pre-fix these returned a host-dependent serialization/hash.
func TestRED2_QuantizeRejectsNonFinite(t *testing.T) {
	cases := map[string][]float32{
		"NaN":              {1, float32(math.NaN()), -1},
		"+Inf":             {1, float32(math.Inf(1)), -1},
		"-Inf":             {1, float32(math.Inf(-1)), -1},
		"all-NaN":          {float32(math.NaN()), float32(math.NaN())},
		"Inf-only":         {float32(math.Inf(1))},
		"NaN-payload-qNaN": {math.Float32frombits(0x7fc00000)},
		"NaN-payload-sNaN": {math.Float32frombits(0x7f800001)},
		"overflow-maxmul":  {1, float32(math.Inf(1))}, // a value that overflowed to +Inf upstream
	}
	for name, v := range cases {
		if _, _, err := canonical.QuantizeEmbedding(v); !errors.Is(err, canonical.ErrNonFiniteEmbedding) {
			t.Errorf("QuantizeEmbedding(%s): err = %v, want ErrNonFiniteEmbedding", name, err)
		}
		if _, err := canonical.EmbeddingHash(v); !errors.Is(err, canonical.ErrNonFiniteEmbedding) {
			t.Errorf("EmbeddingHash(%s): err = %v, want ErrNonFiniteEmbedding", name, err)
		}
	}
}

// Finite vectors still quantize and hash deterministically (the fix must not
// regress the happy path), and -0.0 is indistinguishable from +0.0.
func TestRED2_QuantizeFiniteStillDeterministic(t *testing.T) {
	v := []float32{0.1, -0.2, 0.3, 0.9, -0.7, float32(math.MaxFloat32), -float32(math.MaxFloat32)}
	h1, err := canonical.EmbeddingHash(v)
	if err != nil {
		t.Fatalf("EmbeddingHash: %v", err)
	}
	h2, err := canonical.EmbeddingHash(append([]float32(nil), v...))
	if err != nil {
		t.Fatalf("EmbeddingHash: %v", err)
	}
	if h1 != h2 {
		t.Fatalf("finite embedding not deterministic: %s vs %s", h1.Hex(), h2.Hex())
	}
	// MaxFloat32 is finite and must be accepted (it is the boundary just below Inf).
	if _, _, err := canonical.QuantizeEmbedding([]float32{float32(math.MaxFloat32)}); err != nil {
		t.Fatalf("MaxFloat32 wrongly rejected: %v", err)
	}
	// -0.0 vs +0.0 collapse to the same hash.
	negZero := math.Float32frombits(0x80000000)
	a, _ := canonical.EmbeddingHash([]float32{0, 1, -1})
	b, _ := canonical.EmbeddingHash([]float32{negZero, 1, -1})
	if a != b {
		t.Fatal("-0.0 vs +0.0 produced different embedding_hash")
	}
	// dim=0 and nil are well-defined and identical.
	e0, err := canonical.EmbeddingHash([]float32{})
	if err != nil {
		t.Fatalf("dim=0: %v", err)
	}
	eNil, err := canonical.EmbeddingHash(nil)
	if err != nil {
		t.Fatalf("nil: %v", err)
	}
	if e0 != eNil {
		t.Fatal("dim=0 and nil embeddings hash differently")
	}
}
