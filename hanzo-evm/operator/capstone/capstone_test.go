// Copyright (C) 2026, Hanzo AI Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package capstone

import (
	"bytes"
	"testing"

	aiquorum "github.com/hanzoai/chains/hanzo-evm/precompile/aiquorum"
	"github.com/luxfi/geth/common"
)

// TestCapstoneEndToEnd is THE proof: it drives governance -> staked LLM quorum
// (REAL engine over cgo) -> on-chain commit/reveal/settle (REAL aiquorum
// precompile via its production Run path) and asserts the settled canonical hash
// is BYTE-IDENTICAL to the engine output the honest operators independently
// produced — i.e. not fabricated. Skipped (not failed) without the engine so the
// suite stays green on machines without the models; run with HANZO_FFI_MODELS +
// HANZO_FFI_TOK_DIR to get the real proof.
func TestCapstoneEndToEnd(t *testing.T) {
	if !EngineReady() {
		t.Skip("native engine not ready; set HANZO_FFI_MODELS + HANZO_FFI_TOK_DIR to run the capstone")
	}

	var trace bytes.Buffer
	res, err := Run(&trace)
	// Always surface the trace so a failure is debuggable.
	t.Log("\n" + trace.String())
	if err != nil {
		t.Fatalf("capstone run failed: %v", err)
	}

	// --- The central anti-fabrication assertion ---
	if res.CanonicalFromChain != res.EngineOutputHash {
		t.Fatalf("canonical hash %s is NOT the engine output %s — fabrication", res.CanonicalFromChain.Hex(), res.EngineOutputHash.Hex())
	}
	if res.CanonicalFromChain == (common.Hash{}) {
		t.Fatal("canonical hash is zero — no quorum settled")
	}
	if res.EngineEmbedHash == (common.Hash{}) {
		t.Fatal("embedding_hash is zero — embedding did not run")
	}

	// Quorum shape: exactly the honest operators won; divergent excluded.
	if res.WinnerCount != uint32(len(res.HonestOps)) {
		t.Fatalf("winner_count %d != honest %d", res.WinnerCount, len(res.HonestOps))
	}
	if len(res.HonestOps) < int(jobThreshold) {
		t.Fatalf("honest winners %d below threshold %d", len(res.HonestOps), jobThreshold)
	}
	if len(res.DivergentOps) == 0 {
		t.Fatal("no divergent operator exercised — exclusion not proven")
	}

	// Honest paid >= reward; divergent earned nothing (revealed minority, not slashed).
	for a, c := range res.HonestCredits {
		if c.IsZero() {
			t.Fatalf("honest op %s was not paid", a.Hex())
		}
	}
	for a, c := range res.DivergentCredits {
		if !c.IsZero() {
			t.Fatalf("divergent op %s earned %s, expected 0", a.Hex(), c)
		}
	}

	// No quorum-path slashing here (divergent revealed; SlashDissenters=false).
	if !aiquorum.SlashDissenters && res.Slashed.Sign() != 0 {
		t.Fatalf("dissenters must not be slashed by default; slashed=%s", res.Slashed)
	}

	// Value conserved end to end.
	if !res.Conserved {
		t.Fatal("value not conserved across the capstone")
	}

	// model_spec_hash agreement was checked inside Run; assert it is non-zero here.
	if res.ModelSpecHash == (common.Hash{}) {
		t.Fatal("model_spec_hash is zero")
	}

	t.Logf("CAPSTONE PASS: canonical=%s == engine=%s, winners=%d, %d divergent excluded",
		res.CanonicalFromChain.Hex(), res.EngineOutputHash.Hex(), res.WinnerCount, len(res.DivergentOps))
}
