// Copyright (C) 2026, Hanzo AI Inc. All rights reserved.
// RED-2 adversarial tests. Pure Go (no cgo) so they run without the engine:
//   GOWORK=off CGO_ENABLED=0 go test -run RED2 .
package operator

import (
	"bytes"
	"crypto/ecdsa"
	"math/big"
	"testing"

	"github.com/hanzoai/chains/hanzo-evm/operator/canonical"
	"github.com/luxfi/crypto"
	"github.com/luxfi/geth/common"
)

func mustKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	return k
}

// ---- VECTOR 3: governance preimage injectivity (no false collision) --------
// Exhaustively hash every (vote, bucket) pair under a fixed spec and assert all
// 3*11 = 33 output_hashes are DISTINCT. A collision would be a false-agreement
// bug (two different verdicts counted as the same).
func TestRED2_GovernancePreimageInjective(t *testing.T) {
	spec := common.HexToHash("0xdeadbeef")
	seen := map[common.Hash]string{}
	votes := []canonical.Vote{canonical.VoteYes, canonical.VoteNo, canonical.VoteAbstain}
	for _, v := range votes {
		for bucket := 0; bucket <= canonical.MaxConfidenceBps; bucket += canonical.ConfidenceGridBps {
			d := canonical.Decision{ModelSpecHash: spec, Vote: v, ConfidenceBps: uint16(bucket)}
			h := canonical.OutputHashGovernance(d)
			key := d.ConsensusKey()
			if prev, ok := seen[h]; ok {
				t.Fatalf("FALSE COLLISION: %q and %q hash to the same output_hash %s", prev, key, h.Hex())
			}
			seen[h] = key
		}
	}
	if len(seen) != 33 {
		t.Fatalf("expected 33 distinct consensus hashes, got %d", len(seen))
	}
}

// ---- VECTOR 6a: signature malleability (high-S must be rejected) -----------
func TestRED2_SignatureMalleability_HighS_Rejected(t *testing.T) {
	k := mustKey(t)
	op := pubkeyAddress(&k.PublicKey)
	r := &Reveal{
		JobID: common.HexToHash("0x1"), SpecHash: common.HexToHash("0x2"),
		PromptHash: common.HexToHash("0x3"), OutputHash: common.HexToHash("0x4"),
		EmbeddingHash: common.HexToHash("0x5"), Operator: op, Nonce: common.HexToHash("0x6"),
	}
	r.Commit = canonical.Commit(r.JobID, r.SpecHash, r.PromptHash, r.OutputHash, r.EmbeddingHash, r.Operator, r.Nonce)
	if err := r.sign(k); err != nil {
		t.Fatalf("sign: %v", err)
	}
	// Honest reveal recovers fine.
	if _, err := RecoverReveal(r); err != nil {
		t.Fatalf("honest reveal rejected: %v", err)
	}
	// Malleate: s' = N - s, flip recovery id. This is the classic secp256k1
	// malleability; a non-canonical-aware verifier would still accept it.
	N := crypto.S256().Params().N
	s := new(big.Int).SetBytes(r.Signature[32:64])
	sPrime := new(big.Int).Sub(N, s)
	mal := make([]byte, 65)
	copy(mal[:32], r.Signature[:32])
	sp := sPrime.Bytes()
	copy(mal[64-len(sp):64], sp)
	mal[64] = r.Signature[64] ^ 1 // flip v
	bad := *r
	bad.Signature = mal
	if _, err := RecoverReveal(&bad); err == nil {
		t.Fatal("CRITICAL: high-S malleated signature ACCEPTED (malleability => double-reveal / equivocation)")
	}
}

// ---- VECTOR 6b: recovery-id confusion (v in {27,28} vs {0,1}) --------------
func TestRED2_RecoveryIDConfusion(t *testing.T) {
	k := mustKey(t)
	op := pubkeyAddress(&k.PublicKey)
	r := &Reveal{
		JobID: common.HexToHash("0xa"), SpecHash: common.HexToHash("0xb"),
		PromptHash: common.HexToHash("0xc"), OutputHash: common.HexToHash("0xd"),
		EmbeddingHash: common.HexToHash("0xe"), Operator: op, Nonce: common.HexToHash("0xf"),
	}
	r.Commit = canonical.Commit(r.JobID, r.SpecHash, r.PromptHash, r.OutputHash, r.EmbeddingHash, r.Operator, r.Nonce)
	if err := r.sign(k); err != nil {
		t.Fatalf("sign: %v", err)
	}
	// Add 27 to v (the "Ethereum" convention). crypto.SigToPub expects 0/1.
	bad := *r
	mal := make([]byte, 65)
	copy(mal, r.Signature)
	mal[64] = r.Signature[64] + 27
	bad.Signature = mal
	if _, err := RecoverReveal(&bad); err == nil {
		t.Fatal("recovery-id-confused signature (v+27) ACCEPTED — recovery id not validated")
	}
}

// ---- VECTOR 6c: signer != operator ----------------------------------------
func TestRED2_SignerNotOperator(t *testing.T) {
	kReal := mustKey(t)
	kAttacker := mustKey(t)
	victim := pubkeyAddress(&kReal.PublicKey)
	// Attacker signs a reveal but claims to be the victim operator.
	r := &Reveal{
		JobID: common.HexToHash("0x11"), SpecHash: common.HexToHash("0x22"),
		PromptHash: common.HexToHash("0x33"), OutputHash: common.HexToHash("0x44"),
		EmbeddingHash: common.HexToHash("0x55"), Operator: victim, Nonce: common.HexToHash("0x66"),
	}
	r.Commit = canonical.Commit(r.JobID, r.SpecHash, r.PromptHash, r.OutputHash, r.EmbeddingHash, r.Operator, r.Nonce)
	if err := r.sign(kAttacker); err != nil { // signed by the WRONG key
		t.Fatalf("sign: %v", err)
	}
	if _, err := RecoverReveal(r); err == nil {
		t.Fatal("CRITICAL: reveal signed by attacker but claiming victim operator was ACCEPTED")
	}
}

// ---- VECTOR 6d: tampered consensus field (commit no longer binds) ----------
func TestRED2_TamperedFieldBreaksCommitBinding(t *testing.T) {
	k := mustKey(t)
	op := pubkeyAddress(&k.PublicKey)
	r := &Reveal{
		JobID: common.HexToHash("0x1"), SpecHash: common.HexToHash("0x2"),
		PromptHash: common.HexToHash("0x3"), OutputHash: common.HexToHash("0x4"),
		EmbeddingHash: common.HexToHash("0x5"), Operator: op, Nonce: common.HexToHash("0x6"),
	}
	r.Commit = canonical.Commit(r.JobID, r.SpecHash, r.PromptHash, r.OutputHash, r.EmbeddingHash, r.Operator, r.Nonce)
	if err := r.sign(k); err != nil {
		t.Fatalf("sign: %v", err)
	}
	// Attacker flips output_hash AFTER commit/sign. revealDigest covers OutputHash,
	// so recovery fails on signer mismatch; even if it didn't, commit re-derivation
	// must reject. Verify it's rejected.
	bad := *r
	bad.OutputHash = common.HexToHash("0x99")
	if _, err := RecoverReveal(&bad); err == nil {
		t.Fatal("CRITICAL: tampered output_hash accepted (commit binding / signature not covering output)")
	}
}

// ---- VECTOR 6e: cross-job replay of a signed reveal ------------------------
// A reveal signed for job A must not validate when its JobID is swapped to job B.
func TestRED2_CrossJobReplay(t *testing.T) {
	k := mustKey(t)
	op := pubkeyAddress(&k.PublicKey)
	r := &Reveal{
		JobID: common.HexToHash("0xAAAA"), SpecHash: common.HexToHash("0x2"),
		PromptHash: common.HexToHash("0x3"), OutputHash: common.HexToHash("0x4"),
		EmbeddingHash: common.HexToHash("0x5"), Operator: op, Nonce: common.HexToHash("0x6"),
	}
	r.Commit = canonical.Commit(r.JobID, r.SpecHash, r.PromptHash, r.OutputHash, r.EmbeddingHash, r.Operator, r.Nonce)
	if err := r.sign(k); err != nil {
		t.Fatalf("sign: %v", err)
	}
	replay := *r
	replay.JobID = common.HexToHash("0xBBBB") // different job, same signature & commit
	if _, err := RecoverReveal(&replay); err == nil {
		t.Fatal("CRITICAL: signed reveal replayed across jobs was ACCEPTED")
	}
}

// ---- VECTOR 1: ModelSpec length-prefix cross-field ambiguity ---------------
// Try to make two DISTINCT specs collide by shifting bytes between the variable
// ModelID/RuntimeVersion and their neighbors. Fixed-width hashes bracket the
// length-prefixed strings, so this MUST be impossible.
func TestRED2_ModelSpecNoCrossFieldCollision(t *testing.T) {
	mk := func(id, rt string) canonical.ModelSpec {
		return canonical.ModelSpec{
			ModelID: id, ModelHash: common.HexToHash("0x01"), TokenizerHash: common.HexToHash("0x02"),
			RuntimeVersion: rt, SamplingHash: common.HexToHash("0x03"),
			PromptTemplateHash: common.HexToHash("0x04"), EmbeddingModelHash: common.HexToHash("0x05"),
		}
	}
	// Move one char from ModelID into RuntimeVersion: ("ab","c") vs ("a","bc").
	if mk("ab", "c").ModelSpecHash() == mk("a", "bc").ModelSpecHash() {
		t.Fatal("cross-field shift collision (ab|c == a|bc)")
	}
	// Empty vs single-char with compensating length.
	if mk("", "abc").ModelSpecHash() == mk("abc", "").ModelSpecHash() {
		t.Fatal("empty/nonempty shift collision")
	}
	// Length-prefix-as-content attack: a ModelID whose bytes spell a length prefix.
	a := mk(string([]byte{0, 0, 0, 1}), "")           // 4 bytes that look like u32be(1)
	b := mk(string([]byte{0, 0, 0, 0, 1}), "")        // 5 bytes
	if a.ModelSpecHash() == b.ModelSpecHash() {
		t.Fatal("length-prefix content confusion")
	}
}

// ---- VECTOR 4: JCS audit record cannot affect consensus, and is injection-safe
func TestRED2_AuditRecordCannotAffectConsensus(t *testing.T) {
	spec := common.HexToHash("0xab")
	base := canonical.Decision{ModelSpecHash: spec, Vote: canonical.VoteYes, ConfidenceBps: 5000}
	// Maximally hostile rationale: quotes, braces, JSON, control chars, U+2028/2029,
	// HTML metacharacters, a fake "vote" injection attempt.
	hostile := "\",\"vote\":\"no\",\"confidence_bps\":0,\"x\":\"" +
		"</script>&<>  \x00\x01\x1f{\"nested\":true}"
	d1 := base
	d1.Rationale = "clean"
	d2 := base
	d2.Rationale = hostile
	d2.Citations = []string{hostile, "ipfs://" + hostile}
	// Consensus hash MUST be identical (rationale/citations excluded).
	if canonical.OutputHashGovernance(d1) != canonical.OutputHashGovernance(d2) {
		t.Fatal("hostile rationale changed the consensus hash")
	}
	// And the audit JSON must remain well-formed (re-parseable) JSON.
	rec := canonical.AuditRecord{
		JobID: "0x1", ModelSpecHash: spec.Hex(), Mode: "governance", Operator: "0x2",
		Vote: "yes", ConfidenceBps: 5000, BucketBps: 5000, Rationale: hostile,
		Citations: []string{hostile}, OutputHash: "0x3", EmbeddingHash: "0x4", Nonce: "0x5", Commit: "0x6",
	}
	j := rec.CanonicalJSON()
	if !bytes.HasPrefix(j, []byte("{")) || !bytes.HasSuffix(j, []byte("}")) {
		t.Fatalf("audit JSON malformed: %s", j)
	}
	// Must be valid JSON (no break-out).
	if !jsonValid(j) {
		t.Fatalf("hostile rationale broke JCS well-formedness:\n%s", j)
	}
}

func jsonValid(b []byte) bool {
	return jsonValidImpl(b)
}
