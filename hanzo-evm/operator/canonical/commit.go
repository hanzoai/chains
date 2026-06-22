// Copyright (C) 2026, Hanzo AI Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package canonical

import (
	"github.com/luxfi/crypto"
	"github.com/luxfi/geth/common"
)

// Commit implements the SHARED WIRE SPEC exactly, byte-identical to
// aiquorum.ComputeCommit:
//
//	keccak256(
//	    job_id(32) || model_spec_hash(32) || prompt_hash(32) ||
//	    output_hash(32) || embedding_hash(32) || operator(20) || nonce(32) )
//
// All fields are fixed width and the order is exact. The operator's 20-byte
// address is bound INTO the commit. That binding is the anti-copy / anti-front-
// run control: a peer who observes operator A's commit hash on the wire cannot
// replay it as their own, because recomputing with their own address yields a
// different digest and the precompile's RevealResponse rejects the mismatch.
//
// # Commit hiding depends on the nonce (critical in GOVERNANCE mode)
//
// In RAW mode output_hash has full entropy, so the commit hides the output even
// with a weak nonce. In GOVERNANCE mode output_hash is one of only a few dozen
// possible values ({vote} x {confidence buckets}). An observer who knows the
// (public) job_id, model_spec_hash, prompt_hash and operator address could
// brute-force (output_hash, nonce) if the nonce were low-entropy, breaking
// hiding before the reveal window. The nonce MUST therefore be a fresh 256-bit
// cryptographically-random value (see operator.NewNonce); with 256 bits of
// entropy the brute force is infeasible and hiding holds in both modes.
func Commit(jobID, modelSpecHash, promptHash, outputHash, embeddingHash common.Hash, operator common.Address, nonce common.Hash) common.Hash {
	buf := make([]byte, 0, 32*5+20+32)
	buf = append(buf, jobID.Bytes()...)
	buf = append(buf, modelSpecHash.Bytes()...)
	buf = append(buf, promptHash.Bytes()...)
	buf = append(buf, outputHash.Bytes()...)
	buf = append(buf, embeddingHash.Bytes()...)
	buf = append(buf, operator.Bytes()...)
	buf = append(buf, nonce.Bytes()...)
	return common.BytesToHash(crypto.Keccak256(buf))
}
