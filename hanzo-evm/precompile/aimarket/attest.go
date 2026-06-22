// Copyright (C) 2026, Hanzo AI Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package aimarket

import (
	"github.com/luxfi/crypto"
	"github.com/luxfi/geth/common"
)

// DefaultAttest is the production settlement attestation verifier.
//
// The operator's on-chain identity is its EVM (secp256k1) address, so an
// attestation is a 65-byte secp256k1 signature [R(32) || S(32) || V(1)] over
// the digest. The precompile recovers the signer and checks it equals the
// operator recorded at meter time — no separate key registry, no trusting
// calldata for the signer. This is the canonical EVM identity proof.
//
// The digest is keccak256(recordId, resultHash); the operator signs it to
// attest "I produced resultHash for this request". Settlement is gated on
// this, not a second credit (funds were escrowed + credited at Meter).
//
// Replacing this with a post-quantum (ML-DSA) or threshold (FROST/CGGMP21)
// verifier is a one-line swap at construction — see marketContract.attest —
// because the accounting logic is decoupled from the signature scheme.
func DefaultAttest(operator common.Address, digest common.Hash, sig []byte) bool {
	if len(sig) != crypto.SignatureLength {
		return false
	}
	pub, err := crypto.SigToPub(digest.Bytes(), sig)
	if err != nil {
		return false
	}
	// crypto.PubkeyToAddress returns luxfi/crypto/common.Address; the
	// precompile speaks luxfi/geth/common.Address. Both are [20]byte — compare
	// by bytes to bridge the two named types.
	recovered := crypto.PubkeyToAddress(*pub)
	return common.BytesToAddress(recovered[:]) == operator
}
