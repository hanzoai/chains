// Copyright (C) 2026, Hanzo AI Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// quorum_test.go is the CENTRAL PROOF that quorum forms. It drives the REAL
// native engine over cgo and asserts:
//
//	(1) RAW: three honest operators (same engine, same ModelSpec, same prompt,
//	    distinct keys+nonces) produce the SAME output_hash and SAME embedding_hash
//	    (a quorum would settle), but DIFFERENT commits (operator-bound) and
//	    DIFFERENT signatures.
//	(2) A fourth, divergent operator (tampered output) yields a DIFFERENT
//	    output_hash and is excluded from the quorum group.
//	(3) GOVERNANCE: three operators whose rationale prose DIFFERS but whose
//	    {vote, confidence_bucket} is identical produce the SAME consensus
//	    output_hash (quorum forms) — proving rationale is excluded from consensus.
//
// It is skipped (not failed) when the engine is unavailable, so `go test` is
// green on machines without the models; run it with the engine env to get the
// real proof. cmd/quorumproof/main.go prints the same hashes for humans.
package operator

import (
	"bytes"
	"math/big"
	"testing"

	"github.com/hanzoai/chains/hanzo-evm/operator/canonical"
	"github.com/luxfi/crypto"
	"github.com/luxfi/geth/common"
)

const (
	testInferModel = "zen-nano"
	testEmbedModel = "zen-embed"
)

func testSpec() canonical.ModelSpec {
	// A concrete spec all operators share. The hashes here pin weights/tokenizer/
	// sampling/template; in production they are computed from the real artifacts.
	return canonical.ModelSpec{
		ModelID:            testInferModel,
		ModelHash:          common.HexToHash("0x1111111111111111111111111111111111111111111111111111111111111111"),
		TokenizerHash:      common.HexToHash("0x2222222222222222222222222222222222222222222222222222222222222222"),
		RuntimeVersion:     "hanzo-engine/ffi-greedy-v1",
		SamplingHash:       common.HexToHash("0x3333333333333333333333333333333333333333333333333333333333333333"), // greedy/argmax
		PromptTemplateHash: common.HexToHash("0x4444444444444444444444444444444444444444444444444444444444444444"),
		EmbeddingModelHash: common.HexToHash("0x5555555555555555555555555555555555555555555555555555555555555555"),
	}
}

func mustKeyOperator(t *testing.T, embed string) *Operator {
	t.Helper()
	k, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	return NewOperator(k, testInferModel, embed, testSpec())
}

// (1) + (2): RAW quorum forms; tampered operator excluded.
func TestQuorumForms_Raw(t *testing.T) {
	if !EngineReady() {
		t.Skip("native engine not ready; set HANZO_FFI_MODELS + HANZO_FFI_TOK_DIR to run the real proof")
	}
	spec := testSpec()
	specHash := spec.ModelSpecHash()
	jobID := common.HexToHash("0xABCDEF00000000000000000000000000000000000000000000000000000000aa")
	prompt := []byte("Reply with exactly: I am Zen.")
	embedText := []byte("The quick brown fox jumps over the lazy dog.")

	// Three honest operators: distinct keys, same everything else.
	ops := []*Operator{
		mustKeyOperator(t, testEmbedModel),
		mustKeyOperator(t, testEmbedModel),
		mustKeyOperator(t, testEmbedModel),
	}
	reveals := make([]*Reveal, len(ops))
	for i, o := range ops {
		r, err := o.Run(jobID, prompt, embedText, ModeRaw)
		if err != nil {
			t.Fatalf("op%d Run: %v", i, err)
		}
		reveals[i] = r
	}

	// Same spec for all (sanity).
	for i, o := range ops {
		if o.SpecHash() != specHash {
			t.Fatalf("op%d spec hash drift", i)
		}
	}

	// SAME output_hash across the three honest operators (the quorum-forming fact).
	o0 := reveals[0].OutputHash
	for i, r := range reveals {
		if r.OutputHash != o0 {
			t.Fatalf("op%d output_hash %s != op0 %s — honest operators diverged, quorum would NOT form",
				i, r.OutputHash.Hex(), o0.Hex())
		}
	}
	// SAME embedding_hash across the three.
	e0 := reveals[0].EmbeddingHash
	for i, r := range reveals {
		if r.EmbeddingHash != e0 {
			t.Fatalf("op%d embedding_hash %s != op0 %s", i, r.EmbeddingHash.Hex(), e0.Hex())
		}
	}
	if e0 == (common.Hash{}) {
		t.Fatal("embedding_hash is zero — embedding did not run")
	}

	// DIFFERENT commits (operator-bound) and DIFFERENT signatures.
	for i := 0; i < len(reveals); i++ {
		for j := i + 1; j < len(reveals); j++ {
			if reveals[i].Commit == reveals[j].Commit {
				t.Fatalf("op%d and op%d share a commit — operator binding broken", i, j)
			}
			if bytes.Equal(reveals[i].Signature, reveals[j].Signature) {
				t.Fatalf("op%d and op%d share a signature — keys not distinct", i, j)
			}
		}
	}

	// Every honest reveal recovers to its own operator and binds its commit.
	for i, r := range reveals {
		signer, err := RecoverReveal(r)
		if err != nil {
			t.Fatalf("op%d reveal does not verify: %v", i, err)
		}
		if signer != ops[i].Address() {
			t.Fatalf("op%d recovered %s != %s", i, signer.Hex(), ops[i].Address().Hex())
		}
	}

	// (2) Divergent operator: same job, but tampered output -> different hash.
	bad := mustKeyOperator(t, testEmbedModel)
	badR, err := bad.Run(jobID, prompt, embedText, ModeRaw)
	if err != nil {
		t.Fatalf("bad op Run: %v", err)
	}
	// Simulate tampering: the operator (or a bug) emits a different answer. We
	// recompute its output_hash from a mutated output and rebuild its commit.
	tampered := append(append([]byte(nil), badR.OutputRaw...), []byte(" -- tampered")...)
	badR.OutputHash = canonical.OutputHashRaw(tampered)
	if badR.OutputHash == o0 {
		t.Fatal("tampered output produced the same hash — cannot happen")
	}
	t.Logf("quorum group output_hash = %s (3 honest)", o0.Hex())
	t.Logf("divergent operator        = %s (excluded)", badR.OutputHash.Hex())

	// Group by output_hash the way the precompile's plurality does; the honest
	// group is size 3, the divergent one is its own group of 1.
	groups := map[common.Hash]int{}
	for _, r := range reveals {
		groups[r.OutputHash]++
	}
	groups[badR.OutputHash]++
	if groups[o0] != 3 {
		t.Fatalf("honest group size = %d, want 3", groups[o0])
	}
	if groups[badR.OutputHash] != 1 {
		t.Fatalf("divergent group size = %d, want 1", groups[badR.OutputHash])
	}
	// With threshold = 2-of-4 (floor(4/2)+1 = 3 actually), 3 >= 3 => settles on o0.
	const threshold = 3
	if groups[o0] < threshold {
		t.Fatalf("honest group %d below threshold %d — quorum would not settle", groups[o0], threshold)
	}
}

// (3) GOVERNANCE: different rationale prose, identical consensus hash.
//
// The engine is deterministic, so to exhibit DIFFERENT rationales with the SAME
// {vote,bucket} we strict-parse three hand-built valid decisions that share the
// vote and confidence bucket but carry different prose/citations. This directly
// exercises the rationale-exclusion property of the consensus hash with
// controlled inputs (the honest way to prove the design choice).
func TestQuorumForms_GovernanceRationaleExcluded(t *testing.T) {
	spec := testSpec()
	specHash := spec.ModelSpecHash()
	hex := specHash.Hex()

	// Three operators' raw model JSON: same vote (yes), confidences that all snap
	// to the SAME bucket (8000 bps: 7600,8200,8499 -> all 8000), different prose.
	raws := [][]byte{
		[]byte(`{"vote":"yes","confidence_bps":7600,"rationale":"Approve. The proposal funds core infrastructure and the budget is well justified.","citations":["ipfs://QmA"],"model_spec":"` + hex + `"}`),
		[]byte(`{"vote":"yes","confidence_bps":8200,"rationale":"YES — infra funding is sound; the numbers add up. Phrased completely differently.","citations":[],"model_spec":"` + hex + `"}`),
		[]byte(`{"vote":"yes","confidence_bps":8499,"rationale":"I support this. Strong case for the infra spend, minor reservations on timeline.","citations":["https://forum/post/42","ipfs://QmB"],"model_spec":"` + hex + `"}`),
	}

	var consensus []common.Hash
	var rationales []string
	for i, raw := range raws {
		d, err := canonical.ParseDecision(raw, specHash)
		if err != nil {
			t.Fatalf("op%d strict-parse failed: %v", i, err)
		}
		consensus = append(consensus, canonical.OutputHashGovernance(d))
		rationales = append(rationales, d.Rationale)
		// Sanity: each snaps to the 8000 bucket.
		if d.BucketBps() != 8000 {
			t.Fatalf("op%d bucket = %d, want 8000", i, d.BucketBps())
		}
	}

	// Rationales must genuinely differ...
	for i := 0; i < len(rationales); i++ {
		for j := i + 1; j < len(rationales); j++ {
			if rationales[i] == rationales[j] {
				t.Fatalf("op%d and op%d rationale identical — test does not prove exclusion", i, j)
			}
		}
	}
	// ...yet the consensus output_hash is identical => quorum forms.
	for i, c := range consensus {
		if c != consensus[0] {
			t.Fatalf("op%d consensus hash %s != op0 %s — rationale leaked into consensus", i, c.Hex(), consensus[0].Hex())
		}
	}
	t.Logf("governance consensus output_hash = %s (3 operators, DIFFERENT rationale, SAME {vote=yes,bucket=8000})", consensus[0].Hex())

	// A genuinely different decision (vote=no) must NOT join the quorum.
	dNo, err := canonical.ParseDecision(
		[]byte(`{"vote":"no","confidence_bps":8200,"rationale":"Reject.","citations":[],"model_spec":"`+hex+`"}`), specHash)
	if err != nil {
		t.Fatalf("no-decision parse: %v", err)
	}
	if canonical.OutputHashGovernance(dNo) == consensus[0] {
		t.Fatal("vote=no collided with vote=yes consensus")
	}
}

// Governance fail-secure: invalid model output -> abstain (a valid consensus
// value), and two abstaining operators agree. Engine-independent.
func TestGovernance_FailSecureAbstainAgrees(t *testing.T) {
	spec := testSpec()
	specHash := spec.ModelSpecHash()

	// Two operators both fail to produce valid JSON; both abstain; both agree.
	a := canonical.Abstain(specHash, "garbage from model A")
	b := canonical.Abstain(specHash, "engine error on model B")
	if canonical.OutputHashGovernance(a) != canonical.OutputHashGovernance(b) {
		t.Fatal("two abstentions under the same spec must agree (quorum of abstentions)")
	}
}

// Reveal signature must recover to the operator, and a TAMPERED reveal (any
// consensus field changed after signing) must be rejected by RecoverReveal even
// though we cannot re-sign it. Engine-independent (synthesises a reveal directly).
func TestReveal_SignAndDetectTamper(t *testing.T) {
	k, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	o := NewOperator(k, testInferModel, "", testSpec())
	specHash := o.SpecHash()
	job := common.HexToHash("0x01")
	promptHash := canonical.PromptHash([]byte("p"))
	outHash := canonical.OutputHashRaw([]byte("answer"))
	emb := canonical.EmptyEmbeddingHash
	nonce, _ := NewNonce()

	r := &Reveal{
		JobID: job, SpecHash: specHash, PromptHash: promptHash,
		OutputHash: outHash, EmbeddingHash: emb, Operator: o.Address(), Nonce: nonce,
		Mode:   ModeRaw,
		Commit: canonical.Commit(job, specHash, promptHash, outHash, emb, o.Address(), nonce),
	}
	if err := r.sign(o.key); err != nil {
		t.Fatalf("sign: %v", err)
	}

	signer, err := RecoverReveal(r)
	if err != nil || signer != o.Address() {
		t.Fatalf("honest reveal must verify: signer=%s err=%v", signer.Hex(), err)
	}

	// Tamper the output_hash after signing (commit no longer binds, sig no longer
	// matches digest). RecoverReveal must reject.
	bad := *r
	bad.OutputHash = canonical.OutputHashRaw([]byte("DIFFERENT answer"))
	if _, err := RecoverReveal(&bad); err == nil {
		t.Fatal("tampered output_hash must be rejected by RecoverReveal")
	}

	// Malleate S -> high-S form must be rejected by the canonical-S check.
	mal := *r
	mal.Signature = append([]byte(nil), r.Signature...)
	sBig := new(big.Int).SetBytes(mal.Signature[32:64])
	n := crypto.S256().Params().N
	sHigh := new(big.Int).Sub(n, sBig) // n - s is the malleable counterpart (> n/2)
	sBytes := sHigh.Bytes()
	// left-pad to 32 bytes
	copy(mal.Signature[32:64], make([]byte, 32))
	copy(mal.Signature[64-len(sBytes):64], sBytes)
	mal.Signature[64] ^= 1 // flip recovery id to keep it plausibly recoverable
	if _, err := RecoverReveal(&mal); err == nil {
		t.Fatal("high-S malleated signature must be rejected (non-canonical)")
	}
}

// DOCUMENTED parser behavior (for RED): Go's encoding/json keeps the LAST value
// for duplicate keys and does NOT error (RFC 8785 would reject duplicates). This
// is deterministic, so two honest operators parsing the same raw output agree;
// it is therefore not a quorum-breaking divergence, but it is a parser ambiguity
// a malicious operator could exploit to make human-readable raw text disagree
// with the parsed decision. Captured as a test so the behavior is explicit and
// any future change is caught.
func TestParseDecision_DuplicateKeyTakesLast_Documented(t *testing.T) {
	spec := testSpec().ModelSpecHash()
	raw := []byte(`{"vote":"yes","vote":"no","confidence_bps":5000,"rationale":"r","model_spec":"` + spec.Hex() + `"}`)
	d, err := canonical.ParseDecision(raw, spec)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if d.Vote != canonical.VoteNo {
		t.Fatalf("documented behavior changed: duplicate-key vote = %s, expected last (no)", d.Vote)
	}
}
