// Copyright (C) 2026, Hanzo AI Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package canonical is the SHARED TRUTH for the LLM quorum-settlement wire
// format. It is the piece that makes a quorum actually FORM: two honest
// operators running the same ModelSpec over the same engine must produce
// BYTE-IDENTICAL hashes, or the on-chain precompile never sees agreement and
// the job fails.
//
// # Why this package exists separately from the operator
//
// The operator (sibling package, cgo) talks to the native engine and signs
// payloads. THIS package is pure Go — no cgo, no I/O, no clock, no RNG except
// where a nonce is explicitly drawn by the caller. Everything here is a total
// function from bytes to bytes. That is what lets it be table-tested to the byte
// and cross-checked against the on-chain precompile (precompile/aiquorum) for
// exact equality. Determinism lives here; effects live in the operator.
//
// # The contract with the chain (precompile/aiquorum/aiquorum.go GOVERNS)
//
// Every hash in this package is byte-identical to the precompile's recompute on
// reveal. The precompile is the verifier: at RevealResponse it recomputes the
// commit from the revealed (output_hash, embedding_hash, nonce) and rejects any
// mismatch. If a single byte of ordering, width, or endianness diverges here,
// no honest operator can ever reveal. The functions that MUST match:
//
//	ModelSpecHash  <=> aiquorum.ComputeModelSpecHash
//	Commit         <=> aiquorum.ComputeCommit
//
// crosscheck_test.go (in the operator module) imports the real precompile and
// asserts equality on randomized inputs, so on/off-chain agreement is proven
// against the deployed code, not a transcription of it.
//
// # What the chain agrees on vs. what it never sees
//
// The chain treats output_hash and embedding_hash as opaque 32-byte values. It
// only decides whether >= threshold operators submitted the SAME bytes. The
// MEANING of those bytes is defined entirely here:
//
//	RAW mode        output_hash = keccak256( deterministic UTF-8 model output )
//	GOVERNANCE mode output_hash = keccak256( canonical structured decision )
//
// In GOVERNANCE mode the consensus is deliberately narrowed to a structured
// decision {vote, confidence_bucket} bound to the model_spec_hash. Free-form
// rationale prose is NOT in the consensus hash — see governance.go for the full
// justification. Rationale and citations ride along as non-consensus audit
// metadata, canonicalized by canonicaljson.go (RFC 8785) for storage only.
package canonical
