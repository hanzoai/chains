// Copyright (C) 2026, Hanzo AI Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package canonical

import (
	"github.com/luxfi/crypto"
	"github.com/luxfi/geth/common"
)

// OutputHashRaw is the consensus hash for RAW (free-text) jobs:
//
//	output_hash = keccak256( deterministic UTF-8 model output bytes )
//
// The bytes are exactly what hanzo_ffi_infer returns. Greedy decoding on a fixed
// engine build is bit-identical for the same (model, prompt) on the same host
// (proven), so two honest operators produce the same bytes and therefore the
// same hash. Any divergence in the output bytes — a single different token —
// yields a different hash and excludes that operator from the quorum group,
// which is precisely the behavior we want: the chain counts byte-agreement, not
// semantic agreement.
func OutputHashRaw(output []byte) common.Hash {
	return common.BytesToHash(crypto.Keccak256(output))
}

// OutputHashGovernance is the consensus hash for GOVERNANCE jobs. It is computed
// over the CANONICAL STRUCTURED DECISION only — never the free-form rationale:
//
//	canonical_output_bytes = model_spec_hash(32) || vote_byte(1) || u16be(bucket_bps)(2)
//	output_hash            = keccak256( canonical_output_bytes )
//
// See governance.go for the full rationale-exclusion justification and the
// Decision type that produces (vote_byte, bucket_bps). Binding model_spec_hash
// into the preimage means a decision is only ever equal to another decision made
// under the IDENTICAL spec — an operator cannot have its "yes under spec A"
// counted toward a quorum running spec B.
func OutputHashGovernance(d Decision) common.Hash {
	return common.BytesToHash(crypto.Keccak256(d.consensusPreimage()))
}

// EmptyEmbeddingHash is the embedding_hash value a job carries when it has no
// embedding component. The precompile treats embedding_hash as an opaque 32-byte
// field bound into the commit, so a job without embeddings binds the zero hash;
// all operators in such a job use this same value and it drops out of any
// disagreement. (It is the zero hash, stated explicitly so call sites read
// clearly instead of constructing a bare common.Hash{}.)
var EmptyEmbeddingHash = common.Hash{}
