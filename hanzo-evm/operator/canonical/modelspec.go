// Copyright (C) 2026, Hanzo AI Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package canonical

import (
	"encoding/binary"

	"github.com/luxfi/crypto"
	"github.com/luxfi/geth/common"
)

// ModelSpec is the off-chain inference specification a quorum agrees to run
// under. Only its keccak digest (ModelSpecHash) is stored on-chain; the preimage
// is reproduced by every operator. This mirrors aiquorum.ModelSpec field-for-
// field — the two MUST stay structurally identical so the hash matches.
type ModelSpec struct {
	// ModelID is the human-routable model name (utf-8, variable length, length-
	// prefixed in the hash). For the engine this is the HANZO_FFI_MODELS key,
	// e.g. "zen-nano".
	ModelID string
	// ModelHash pins the exact weights (e.g. keccak/sha of the .gguf). Two
	// operators with different weights hash to different specs and never quorum.
	ModelHash common.Hash
	// TokenizerHash pins the tokenizer (the fused tok dir). Tokenizer drift is a
	// silent determinism break; pinning it surfaces the disagreement as a spec
	// mismatch instead of a divergent output.
	TokenizerHash common.Hash
	// RuntimeVersion pins the engine build (utf-8, length-prefixed). Greedy
	// decoding is bit-identical only within one engine build on matching hardware.
	RuntimeVersion string
	// SamplingHash pins the decoding policy (greedy, temperature 0, etc.). For a
	// deterministic quorum this commits to greedy/argmax.
	SamplingHash common.Hash
	// PromptTemplateHash pins the chat/prompt template applied before inference.
	PromptTemplateHash common.Hash
	// EmbeddingModelHash pins the embedding model (separate from the causal
	// model). Zero when the job carries no embedding.
	EmbeddingModelHash common.Hash
}

// ModelSpecHash implements the SHARED WIRE SPEC exactly, byte-identical to
// aiquorum.ComputeModelSpecHash:
//
//	keccak256(
//	    u32be(len(model_id)) || model_id ||
//	    model_hash(32) || tokenizer_hash(32) ||
//	    u32be(len(runtime_version)) || runtime_version ||
//	    sampling_hash(32) || prompt_template_hash(32) || embedding_model_hash(32) )
//
// The two strings carry a 4-byte big-endian length prefix; the six hashes are
// fixed 32-byte. Field order is canonical and load-bearing: reordering any two
// adjacent fields changes the digest while leaving every individual value
// unchanged, which is exactly the class of bug this single shared definition
// exists to prevent.
func (s ModelSpec) ModelSpecHash() common.Hash {
	var lp [4]byte
	buf := make([]byte, 0, 4+len(s.ModelID)+32+32+4+len(s.RuntimeVersion)+32+32+32)

	binary.BigEndian.PutUint32(lp[:], uint32(len(s.ModelID)))
	buf = append(buf, lp[:]...)
	buf = append(buf, s.ModelID...)
	buf = append(buf, s.ModelHash.Bytes()...)
	buf = append(buf, s.TokenizerHash.Bytes()...)

	binary.BigEndian.PutUint32(lp[:], uint32(len(s.RuntimeVersion)))
	buf = append(buf, lp[:]...)
	buf = append(buf, s.RuntimeVersion...)
	buf = append(buf, s.SamplingHash.Bytes()...)
	buf = append(buf, s.PromptTemplateHash.Bytes()...)
	buf = append(buf, s.EmbeddingModelHash.Bytes()...)

	return common.BytesToHash(crypto.Keccak256(buf))
}

// PromptHash is the canonical hash of the exact prompt bytes sent to the engine.
// The chain stores it per job and binds it into the commit; both operator and
// requester must hash the identical UTF-8 prompt. This is keccak256 of the raw
// prompt bytes — no length prefix, because prompt_hash is a standalone 32-byte
// field, never concatenated with a variable-length sibling inside one preimage.
func PromptHash(prompt []byte) common.Hash {
	return common.BytesToHash(crypto.Keccak256(prompt))
}
