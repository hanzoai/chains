// Copyright (C) 2026, Hanzo AI Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// This test is the on/off-chain agreement GUARANTEE. It imports the REAL
// on-chain precompile (precompile/aiquorum, resolved via the go.mod replace =>
// ../) and asserts that canonical's wire functions produce byte-identical output
// to the precompile's ComputeModelSpecHash / ComputeCommit on randomized inputs.
//
// If this ever fails, an operator's commit would not match the precompile's
// recompute at RevealResponse and quorum could never form — so this test is the
// tripwire for any drift between the two definitions. It is pure Go (no cgo), so
// it runs without the engine: `GOWORK=off CGO_ENABLED=0 go test -run CrossCheck .`
package operator

import (
	"crypto/rand"
	"testing"

	"github.com/hanzoai/chains/hanzo-evm/operator/canonical"
	aiquorum "github.com/hanzoai/chains/hanzo-evm/precompile/aiquorum"
	"github.com/luxfi/geth/common"
)

func randHash(t *testing.T) common.Hash {
	t.Helper()
	var h common.Hash
	if _, err := rand.Read(h[:]); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return h
}

func randAddr(t *testing.T) common.Address {
	t.Helper()
	var a common.Address
	if _, err := rand.Read(a[:]); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return a
}

var randStrings = []string{"", "zen-nano", "a", "hanzo-engine/1.2.3", "zen-embed-0.6B",
	"a really rather long runtime version string with spaces and / slashes 2026"}

// ModelSpecHash MUST equal aiquorum.ComputeModelSpecHash for every input.
func TestCrossCheck_ModelSpecHash(t *testing.T) {
	for i := 0; i < 256; i++ {
		s := canonical.ModelSpec{
			ModelID:            randStrings[i%len(randStrings)],
			ModelHash:          randHash(t),
			TokenizerHash:      randHash(t),
			RuntimeVersion:     randStrings[(i+3)%len(randStrings)],
			SamplingHash:       randHash(t),
			PromptTemplateHash: randHash(t),
			EmbeddingModelHash: randHash(t),
		}
		off := s.ModelSpecHash()
		on := aiquorum.ComputeModelSpecHash(aiquorum.ModelSpec{
			ModelID:            s.ModelID,
			ModelHash:          s.ModelHash,
			TokenizerHash:      s.TokenizerHash,
			RuntimeVersion:     s.RuntimeVersion,
			SamplingHash:       s.SamplingHash,
			PromptTemplateHash: s.PromptTemplateHash,
			EmbeddingModelHash: s.EmbeddingModelHash,
		})
		if off != on {
			t.Fatalf("iter %d: ModelSpecHash mismatch\n off-chain %s\n  on-chain %s\n spec %+v", i, off.Hex(), on.Hex(), s)
		}
	}
}

// Commit MUST equal aiquorum.ComputeCommit for every input (operator-bound).
func TestCrossCheck_Commit(t *testing.T) {
	for i := 0; i < 256; i++ {
		job := randHash(t)
		spec := randHash(t)
		prompt := randHash(t)
		out := randHash(t)
		emb := randHash(t)
		op := randAddr(t)
		nonce := randHash(t)

		off := canonical.Commit(job, spec, prompt, out, emb, op, nonce)
		on := aiquorum.ComputeCommit(job, spec, prompt, out, emb, op, nonce)
		if off != on {
			t.Fatalf("iter %d: Commit mismatch\n off-chain %s\n  on-chain %s", i, off.Hex(), on.Hex())
		}
	}
}

// End-to-end: an operator builds a commit from canonical primitives; the
// precompile's recompute (the same function it runs at RevealResponse) accepts
// it. This is the exact agreement the lifecycle depends on.
func TestCrossCheck_RevealRecomputeAccepts(t *testing.T) {
	spec := canonical.ModelSpec{
		ModelID:        "zen-nano",
		ModelHash:      randHash(t),
		TokenizerHash:  randHash(t),
		RuntimeVersion: "hanzo-engine/1.2.3",
		SamplingHash:   randHash(t),
	}
	specHash := spec.ModelSpecHash()
	job := randHash(t)
	prompt := canonical.PromptHash([]byte("Who are you?"))
	out := canonical.OutputHashRaw([]byte("I am Zen."))
	emb, err := canonical.EmbeddingHash([]float32{0.1, -0.2, 0.3})
	if err != nil {
		t.Fatalf("EmbeddingHash: %v", err)
	}
	op := randAddr(t)
	nonce := randHash(t)

	// Operator-side commit.
	commit := canonical.Commit(job, specHash, prompt, out, emb, op, nonce)

	// Precompile-side recompute at reveal (identical inputs => must match).
	recomputed := aiquorum.ComputeCommit(job, specHash, prompt, out, emb, op, nonce)
	if commit != recomputed {
		t.Fatalf("reveal recompute would REJECT the operator's commit:\n commit     %s\n recomputed %s", commit.Hex(), recomputed.Hex())
	}
}
