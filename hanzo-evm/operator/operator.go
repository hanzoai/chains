// Copyright (C) 2026, Hanzo AI Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package operator is the OFF-CHAIN operator side of the LLM quorum-settlement
// system. It runs deterministic inference/embedding through the native Hanzo
// engine (over cgo FFI) and turns the result into the commit/reveal payloads the
// on-chain precompile (precompile/aiquorum) settles.
//
// The determinism lives entirely in the sibling `canonical` package (pure, no
// cgo, byte-identical to the precompile and cross-checked against it). This
// package is the effectful shell: it talks to the engine, draws nonces from a
// CSPRNG, and signs with secp256k1. Clean separation — effects here, truth there.
//
// # Two operator bindings (defense in depth)
//
//   - The COMMIT binds the operator's 20-byte ADDRESS (canonical.Commit). The
//     precompile enforces this at RevealResponse: a peer cannot replay another
//     operator's commit hash because recomputation with their own address
//     differs. This is the on-chain binding.
//   - The REVEAL payload is secp256k1-SIGNED; the operator address is RECOVERED
//     from the signature (SignReveal/RecoverReveal). This binds the reveal to the
//     operator's private KEY at the transport layer, so a relay/gateway cannot
//     forge a reveal on the operator's behalf. This is the off-chain binding.
//
// Together: address-in-commit (on-chain) + key-signed-reveal (off-chain). An
// attacker needs both the address AND the key to impersonate an operator.
//
// Build/run with the native engine:
//
//	HANZO_FFI_MODELS="zen-nano=gguf:/tmp/zen5-weights/zen-5-flash.gguf;zen-embed=embedding:/tmp/zen-embedding-0.6B" \
//	  HANZO_FFI_TOK_DIR=/tmp/zen-nano-fused \
//	  GOWORK=off CGO_ENABLED=1 SDKROOT=$(xcrun --show-sdk-path) CPATH=$SDKROOT/usr/include \
//	  go test .   # (and cmd/quorumproof for the live quorum proof)
package operator

/*
#cgo CFLAGS: -I${SRCDIR}/../../../engine/hanzo-engine-ffi/include
#cgo LDFLAGS: -L${SRCDIR}/../../../engine/target/release -lhanzo_engine_ffi -Wl,-rpath,${SRCDIR}/../../../engine/target/release
#include "hanzo_engine_ffi.h"
#include <stdlib.h>
*/
import "C"

import (
	"crypto/ecdsa"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"unsafe"

	"github.com/hanzoai/chains/hanzo-evm/operator/canonical"
	"github.com/luxfi/crypto"
	"github.com/luxfi/geth/common"
)

// Mode selects how an operator turns model output into the consensus output_hash.
type Mode uint8

const (
	// ModeRaw hashes the deterministic UTF-8 model output verbatim.
	ModeRaw Mode = iota
	// ModeGovernance constrains the model to a structured decision and hashes
	// only {vote, confidence_bucket} bound to the spec (rationale excluded).
	ModeGovernance
)

// Engine errors surfaced from the FFI boundary. The numeric rc values come from
// hanzo_engine_ffi.h: -1 bad args, -2 engine unavailable, -3 op failed.
var (
	ErrEngineNotReady = errors.New("operator: native engine not ready (set HANZO_FFI_MODELS)")
	ErrInferFailed    = errors.New("operator: hanzo_ffi_infer failed")
	ErrEmbedFailed    = errors.New("operator: hanzo_ffi_embed failed")
)

// ---------------------------------------------------------------------------
// FFI boundary (the only cgo in the package; everything else is pure Go)
// ---------------------------------------------------------------------------

func bytePtr(b []byte) *C.uint8_t {
	if len(b) == 0 {
		return nil
	}
	return (*C.uint8_t)(unsafe.Pointer(&b[0]))
}

// EngineReady reports whether the native engine has loaded its configured models.
func EngineReady() bool { return C.hanzo_ffi_ready() == 1 }

// infer runs deterministic (greedy) text generation on `model`. The returned
// bytes are the exact consensus input for ModeRaw and the raw JSON to strict-
// parse for ModeGovernance.
func infer(model string, prompt []byte) ([]byte, error) {
	mb := []byte(model)
	var out *C.uint8_t
	var outLen C.size_t
	rc := C.hanzo_ffi_infer(bytePtr(mb), C.size_t(len(mb)), bytePtr(prompt), C.size_t(len(prompt)), &out, &outLen)
	if rc != 0 {
		return nil, fmt.Errorf("%w (rc=%d)", ErrInferFailed, int(rc))
	}
	defer C.hanzo_ffi_free(out, outLen)
	// Copy out of C memory before the defer frees it.
	return C.GoBytes(unsafe.Pointer(out), C.int(outLen)), nil
}

// embed runs a native embedding on `model`, returning the float32 vector.
func embed(model string, text []byte) ([]float32, error) {
	mb := []byte(model)
	var out *C.float
	var count C.size_t
	rc := C.hanzo_ffi_embed(bytePtr(mb), C.size_t(len(mb)), bytePtr(text), C.size_t(len(text)), &out, &count)
	if rc != 0 {
		return nil, fmt.Errorf("%w (rc=%d)", ErrEmbedFailed, int(rc))
	}
	defer C.hanzo_ffi_free_f32(out, count)
	src := unsafe.Slice((*float32)(unsafe.Pointer(out)), int(count))
	v := make([]float32, int(count))
	copy(v, src) // copy out of C memory
	return v, nil
}

// ---------------------------------------------------------------------------
// Operator identity + nonce
// ---------------------------------------------------------------------------

// Operator is a single staked participant: an secp256k1 key, the engine model
// names it runs, and the ModelSpec it advertises. Its Address (= the key's
// address) is what gets bound into commits and recovered from reveal signatures.
type Operator struct {
	key        *ecdsa.PrivateKey
	addr       common.Address
	inferModel string // HANZO_FFI_MODELS key for the causal model (e.g. "zen-nano")
	embedModel string // HANZO_FFI_MODELS key for the embedding model ("" = none)
	spec       canonical.ModelSpec
}

// NewOperator builds an operator from an secp256k1 private key. The model names
// must match keys loaded in the engine (HANZO_FFI_MODELS). embedModel may be ""
// for inference-only jobs (embedding_hash will be the zero hash).
func NewOperator(key *ecdsa.PrivateKey, inferModel, embedModel string, spec canonical.ModelSpec) *Operator {
	return &Operator{
		key:        key,
		addr:       pubkeyAddress(&key.PublicKey),
		inferModel: inferModel,
		embedModel: embedModel,
		spec:       spec,
	}
}

// pubkeyAddress bridges luxfi/crypto's address type to luxfi/geth/common.Address.
// crypto.PubkeyToAddress returns luxfi/crypto/common.Address; the precompile (and
// thus the whole quorum wire format) speaks luxfi/geth/common.Address. Both are
// [20]byte, so we re-wrap the bytes — the same idiom aimarket/attest.go uses.
func pubkeyAddress(pub *ecdsa.PublicKey) common.Address {
	a := crypto.PubkeyToAddress(*pub)
	return common.BytesToAddress(a[:])
}

// Address is the operator's on-chain identity (secp256k1 pubkey -> 20 bytes).
func (o *Operator) Address() common.Address { return o.addr }

// SpecHash is the model_spec_hash this operator advertises and binds into commits.
func (o *Operator) SpecHash() common.Hash { return o.spec.ModelSpecHash() }

// NewNonce draws a fresh 256-bit commit nonce from the OS CSPRNG. A full 32 bytes
// of entropy is REQUIRED, not optional: in governance mode output_hash has only a
// few dozen possible values, so a low-entropy nonce would let an observer brute-
// force the commit preimage before the reveal window and break hiding. 256 bits
// makes that infeasible. (crypto/rand.Read never returns a short read without an
// error, so a successful call always yields 32 fresh bytes.)
func NewNonce() (common.Hash, error) {
	var n common.Hash
	if _, err := rand.Read(n[:]); err != nil {
		return common.Hash{}, fmt.Errorf("operator: nonce entropy: %w", err)
	}
	return n, nil
}

// ---------------------------------------------------------------------------
// Reveal payload (off-chain transport) + signing
// ---------------------------------------------------------------------------

// Reveal is the operator's revealed commit preimage plus audit metadata and a
// signature. The on-chain RevealResponse consumes (OutputHash, EmbeddingHash,
// Nonce); the rest is off-chain transport/audit. The signature binds the whole
// reveal to the operator's key.
type Reveal struct {
	JobID         common.Hash
	SpecHash      common.Hash
	PromptHash    common.Hash
	OutputHash    common.Hash // consensus field
	EmbeddingHash common.Hash // consensus field
	Operator      common.Address
	Nonce         common.Hash // consensus field

	Mode      Mode
	Decision  *canonical.Decision // present in governance mode (audit metadata)
	OutputRaw []byte              // present in raw mode (the actual model output, audit)

	Commit    common.Hash // canonical.Commit over the consensus fields (operator-bound)
	Signature []byte      // secp256k1 [R||S||V] over revealDigest()
}

// revealDigest is the 32-byte message the operator signs. It is domain-separated
// ("hanzo/aiquorum/reveal/v1") and covers exactly the binding fields the chain
// uses plus the commit, so a signature authenticates "operator O reveals THIS
// (output, embedding, nonce) for THIS job under THIS spec, committing C". The
// audit metadata (rationale) is deliberately NOT in the signed digest — it is not
// consensus-relevant and is authenticated separately by the AuditRecord's own
// canonical form if needed.
func (r *Reveal) revealDigest() common.Hash {
	buf := make([]byte, 0, len("hanzo/aiquorum/reveal/v1")+32*6+20)
	buf = append(buf, "hanzo/aiquorum/reveal/v1"...)
	buf = append(buf, r.JobID.Bytes()...)
	buf = append(buf, r.SpecHash.Bytes()...)
	buf = append(buf, r.PromptHash.Bytes()...)
	buf = append(buf, r.OutputHash.Bytes()...)
	buf = append(buf, r.EmbeddingHash.Bytes()...)
	buf = append(buf, r.Operator.Bytes()...)
	buf = append(buf, r.Nonce.Bytes()...)
	buf = append(buf, r.Commit.Bytes()...)
	return common.BytesToHash(crypto.Keccak256(buf))
}

// sign produces the secp256k1 signature over revealDigest. crypto.Sign yields a
// canonical low-S [R||S||V] signature (the underlying library normalizes S and
// VerifySignature rejects high-S), so the signature is non-malleable.
func (r *Reveal) sign(key *ecdsa.PrivateKey) error {
	sig, err := crypto.Sign(r.revealDigest().Bytes(), key)
	if err != nil {
		return fmt.Errorf("operator: sign reveal: %w", err)
	}
	r.Signature = sig
	return nil
}

// RecoverReveal verifies a reveal's signature and returns the recovered signer
// address. A reveal is authentic iff the recovered address equals r.Operator AND
// that address is the one bound into r.Commit. It also re-derives the commit from
// the consensus fields and checks it matches r.Commit, so a tampered output_hash
// (or any consensus field) is caught here off-chain before the on-chain reveal.
func RecoverReveal(r *Reveal) (common.Address, error) {
	if len(r.Signature) != crypto.SignatureLength { // 65 = R(32)||S(32)||V(1)
		return common.Address{}, errors.New("operator: bad signature length")
	}
	// Defense in depth: reject non-canonical (high-S) and out-of-range signatures
	// before recovery. crypto.Sign already emits low-S, so an honest reveal always
	// passes; a malleated copy is refused here. (Forgery is independently blocked
	// by the signer==Operator check below, since malleating S changes the
	// recovered key — but failing closed on malleability removes the ambiguity
	// entirely rather than relying on a downstream check.)
	rBig := new(big.Int).SetBytes(r.Signature[:32])
	sBig := new(big.Int).SetBytes(r.Signature[32:64])
	v := r.Signature[64]
	if !crypto.ValidateSignatureValues(v, rBig, sBig, true /*homestead: enforce low-S*/) {
		return common.Address{}, errors.New("operator: non-canonical signature (high-S or out of range)")
	}
	pub, err := crypto.SigToPub(r.revealDigest().Bytes(), r.Signature)
	if err != nil {
		return common.Address{}, fmt.Errorf("operator: recover: %w", err)
	}
	signer := pubkeyAddress(pub)
	if signer != r.Operator {
		return common.Address{}, fmt.Errorf("operator: signer %s != reveal.Operator %s", signer.Hex(), r.Operator.Hex())
	}
	// Re-derive the commit from the consensus fields; must match the claimed one.
	want := canonical.Commit(r.JobID, r.SpecHash, r.PromptHash, r.OutputHash, r.EmbeddingHash, r.Operator, r.Nonce)
	if want != r.Commit {
		return common.Address{}, errors.New("operator: commit does not bind the revealed fields")
	}
	return signer, nil
}

// AuditRecord projects the reveal into the storable, RFC-8785-canonical audit
// record. For governance mode it carries the raw confidence and the snapped
// bucket plus the (non-consensus) rationale and citations.
func (r *Reveal) AuditRecord() canonical.AuditRecord {
	rec := canonical.AuditRecord{
		JobID:         r.JobID.Hex(),
		ModelSpecHash: r.SpecHash.Hex(),
		Operator:      r.Operator.Hex(),
		OutputHash:    r.OutputHash.Hex(),
		EmbeddingHash: r.EmbeddingHash.Hex(),
		Nonce:         r.Nonce.Hex(),
		Commit:        r.Commit.Hex(),
	}
	switch r.Mode {
	case ModeGovernance:
		rec.Mode = "governance"
		if r.Decision != nil {
			rec.Vote = r.Decision.Vote.String()
			rec.ConfidenceBps = int64(r.Decision.ConfidenceBps)
			rec.BucketBps = int64(r.Decision.BucketBps())
			rec.Rationale = r.Decision.Rationale
			rec.Citations = r.Decision.Citations
		}
	default:
		rec.Mode = "raw"
	}
	return rec
}

// ---------------------------------------------------------------------------
// The job: run inference -> build operator-bound commit + signed reveal
// ---------------------------------------------------------------------------

// Run executes a quorum job end to end for this operator: it runs the engine
// (deterministic) on `prompt`, computes the consensus output_hash (per mode) and
// embedding_hash, draws a fresh nonce, builds the operator-bound commit, and
// returns a signed Reveal. The prompt the operator infers IS the job's prompt, so
// the commit binds promptHash = PromptHash(prompt) — the honest case.
//
//	prompt        the exact UTF-8 prompt bytes (also hashed by the requester)
//	embedText     text to embed (ignored if the operator has no embed model);
//	              nil/"" -> no embedding (embedding_hash = zero)
func (o *Operator) Run(jobID common.Hash, prompt []byte, embedText []byte, mode Mode) (*Reveal, error) {
	return o.RunForJob(jobID, canonical.PromptHash(prompt), prompt, embedText, mode)
}

// RunForJob is the general engine-to-reveal path: it runs the engine on
// `inferPrompt` but binds `jobPromptHash` into the commit/reveal. This separates
// "what the operator actually computed" (inferPrompt → a REAL engine output_hash)
// from "which job it is committing to" (jobPromptHash, the on-chain job's stored
// prompt hash). Run is the honest special case where jobPromptHash ==
// PromptHash(inferPrompt).
//
// It exists to model a DIVERGENT operator faithfully WITHOUT fabricating any hash:
// a divergent / buggy / malicious operator selected for job J (whose prompt hash
// is jobPromptHash) computes on the WRONG input (inferPrompt != the job's prompt)
// and reports the genuine engine output_hash for that wrong input. Because the
// commit binds jobPromptHash (not PromptHash(inferPrompt)), the on-chain
// RevealResponse — which recomputes using the JOB's stored prompt hash — still
// ACCEPTS the reveal, so the divergent operator participates on-chain but
// contributes a real-but-different output_hash that is excluded from the honest
// plurality. No hash is invented; the divergence is a real engine output for a
// different input.
func (o *Operator) RunForJob(jobID, jobPromptHash common.Hash, inferPrompt, embedText []byte, mode Mode) (*Reveal, error) {
	if !EngineReady() {
		return nil, ErrEngineNotReady
	}
	specHash := o.spec.ModelSpecHash()

	// Embedding (optional). embedding_hash binds into the commit either way.
	embHash := canonical.EmptyEmbeddingHash
	if o.embedModel != "" && len(embedText) > 0 {
		vec, err := embed(o.embedModel, embedText)
		if err != nil {
			return nil, err
		}
		// Fail-closed on a non-finite embedding: rather than committing a
		// host-dependent embedding_hash (which would silently split the quorum),
		// the operator declines the job. See canonical.ErrNonFiniteEmbedding.
		embHash, err = canonical.EmbeddingHash(vec)
		if err != nil {
			return nil, err
		}
	}

	// Consensus output_hash, per mode — a REAL engine output over inferPrompt.
	var (
		outHash  common.Hash
		decision *canonical.Decision
		rawOut   []byte
	)
	switch mode {
	case ModeRaw:
		out, err := infer(o.inferModel, inferPrompt)
		if err != nil {
			return nil, err
		}
		rawOut = out
		outHash = canonical.OutputHashRaw(out)
	case ModeGovernance:
		d, err := o.runGovernance(inferPrompt, specHash)
		if err != nil {
			return nil, err
		}
		decision = &d
		outHash = canonical.OutputHashGovernance(d)
	default:
		return nil, fmt.Errorf("operator: unknown mode %d", mode)
	}

	nonce, err := NewNonce()
	if err != nil {
		return nil, err
	}
	commit := canonical.Commit(jobID, specHash, jobPromptHash, outHash, embHash, o.addr, nonce)

	r := &Reveal{
		JobID:         jobID,
		SpecHash:      specHash,
		PromptHash:    jobPromptHash,
		OutputHash:    outHash,
		EmbeddingHash: embHash,
		Operator:      o.addr,
		Nonce:         nonce,
		Mode:          mode,
		Decision:      decision,
		OutputRaw:     rawOut,
		Commit:        commit,
	}
	if err := r.sign(o.key); err != nil {
		return nil, err
	}
	return r, nil
}

// runGovernance runs the constrained-decision inference and strict-parses it.
// Fail-secure policy: on an invalid decision it retries inference ONCE; if the
// retry is also invalid it ABSTAINS (a real abstain vote at zero confidence)
// rather than crashing the job or guessing. Greedy decoding makes the retry
// identical on the same host, so the retry exists to absorb a transient engine
// error rather than to gamble on different output — but it is the documented,
// bounded recovery path, and the abstain terminal state guarantees Run always
// produces a valid consensus value.
func (o *Operator) runGovernance(prompt []byte, specHash common.Hash) (canonical.Decision, error) {
	govPrompt := buildGovernancePrompt(prompt, specHash)

	raw, err := infer(o.inferModel, govPrompt)
	if err == nil {
		if d, perr := canonical.ParseDecision(raw, specHash); perr == nil {
			return d, nil
		}
	}
	// Retry once (absorbs a transient failure; deterministic engine => same input).
	raw, err = infer(o.inferModel, govPrompt)
	if err == nil {
		if d, perr := canonical.ParseDecision(raw, specHash); perr == nil {
			return d, nil
		}
	}
	// Terminal fail-secure: abstain. This is a valid consensus value; abstaining
	// operators that agree still form a (no-decision) quorum.
	return canonical.Abstain(specHash, "model did not emit a valid structured decision"), nil
}

// buildGovernancePrompt wraps the proposal prompt with the strict-schema
// instruction. The model is told the exact JSON it must emit, including echoing
// the model_spec hex (ParseDecision enforces it). Kept minimal and deterministic.
func buildGovernancePrompt(prompt []byte, specHash common.Hash) []byte {
	instr := `You are a governance voter. Read the proposal and respond with EXACTLY one JSON object and nothing else, in this schema:
{"vote":"yes"|"no"|"abstain","confidence_bps":<integer 0-10000>,"rationale":"<your reasoning>","citations":["<ref>"],"model_spec":"` + specHash.Hex() + `"}
Proposal:
`
	out := make([]byte, 0, len(instr)+len(prompt))
	out = append(out, instr...)
	out = append(out, prompt...)
	return out
}
