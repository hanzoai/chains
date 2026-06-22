// Copyright (C) 2026, Hanzo AI Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package canonical

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"math"
	"strings"
	"testing"

	"github.com/luxfi/crypto"
	"github.com/luxfi/geth/common"
)

func h(b byte) common.Hash {
	var x common.Hash
	for i := range x {
		x[i] = b
	}
	return x
}

// --- ModelSpecHash: exact preimage reconstruction -------------------------

func TestModelSpecHash_ExactPreimage(t *testing.T) {
	s := ModelSpec{
		ModelID:            "zen-nano",
		ModelHash:          h(0x11),
		TokenizerHash:      h(0x22),
		RuntimeVersion:     "hanzo-engine/1.2.3",
		SamplingHash:       h(0x33),
		PromptTemplateHash: h(0x44),
		EmbeddingModelHash: h(0x55),
	}
	// Reconstruct the preimage independently and compare the hash.
	var lp [4]byte
	var buf []byte
	binary.BigEndian.PutUint32(lp[:], uint32(len("zen-nano")))
	buf = append(buf, lp[:]...)
	buf = append(buf, "zen-nano"...)
	buf = append(buf, h(0x11).Bytes()...)
	buf = append(buf, h(0x22).Bytes()...)
	binary.BigEndian.PutUint32(lp[:], uint32(len("hanzo-engine/1.2.3")))
	buf = append(buf, lp[:]...)
	buf = append(buf, "hanzo-engine/1.2.3"...)
	buf = append(buf, h(0x33).Bytes()...)
	buf = append(buf, h(0x44).Bytes()...)
	buf = append(buf, h(0x55).Bytes()...)
	want := common.BytesToHash(crypto.Keccak256(buf))

	if got := s.ModelSpecHash(); got != want {
		t.Fatalf("ModelSpecHash mismatch\n got %s\nwant %s", got.Hex(), want.Hex())
	}
}

// Field ordering must be load-bearing: swapping two values changes the hash.
func TestModelSpecHash_OrderingSensitive(t *testing.T) {
	a := ModelSpec{ModelID: "m", ModelHash: h(0x01), TokenizerHash: h(0x02), RuntimeVersion: "r", SamplingHash: h(0x03), PromptTemplateHash: h(0x04), EmbeddingModelHash: h(0x05)}
	b := a
	b.SamplingHash, b.PromptTemplateHash = a.PromptTemplateHash, a.SamplingHash // swap two 32B fields
	if a.ModelSpecHash() == b.ModelSpecHash() {
		t.Fatal("swapping sampling/prompt-template hashes did not change the digest — ordering not enforced")
	}
}

// model_id length-prefix must prevent "ab"|"c" colliding with "a"|"bc".
func TestModelSpecHash_LengthPrefixNoConcatCollision(t *testing.T) {
	base := ModelSpec{ModelHash: h(1), TokenizerHash: h(2), RuntimeVersion: "x", SamplingHash: h(3), PromptTemplateHash: h(4), EmbeddingModelHash: h(5)}
	a := base
	a.ModelID = "ab"
	b := base
	b.ModelID = "a" // shorter id, different bytes — must differ
	if a.ModelSpecHash() == b.ModelSpecHash() {
		t.Fatal("length-prefix failed: distinct model ids collided")
	}
}

// --- Commit: operator binding --------------------------------------------

func TestCommit_OperatorBound(t *testing.T) {
	job, spec, prompt, out, emb := h(1), h(2), h(3), h(4), h(5)
	nonce := h(9)
	opA := common.HexToAddress("0x00000000000000000000000000000000000000aa")
	opB := common.HexToAddress("0x00000000000000000000000000000000000000bb")

	cA := Commit(job, spec, prompt, out, emb, opA, nonce)
	cB := Commit(job, spec, prompt, out, emb, opB, nonce)
	if cA == cB {
		t.Fatal("commit is NOT operator-bound: two operators with identical reveal produced the same commit (replay/copy attack possible)")
	}
}

func TestCommit_NonceBound(t *testing.T) {
	job, spec, prompt, out, emb := h(1), h(2), h(3), h(4), h(5)
	op := common.HexToAddress("0x00000000000000000000000000000000000000aa")
	if Commit(job, spec, prompt, out, emb, op, h(7)) == Commit(job, spec, prompt, out, emb, op, h(8)) {
		t.Fatal("commit not bound to nonce")
	}
}

// --- output_hash modes ----------------------------------------------------

func TestOutputHashRaw(t *testing.T) {
	out := []byte("I am Zen, a language model.")
	want := common.BytesToHash(crypto.Keccak256(out))
	if OutputHashRaw(out) != want {
		t.Fatal("raw output hash mismatch")
	}
	if OutputHashRaw([]byte("x")) == OutputHashRaw([]byte("y")) {
		t.Fatal("distinct outputs collided")
	}
}

// --- governance: bucketing (integer round-half-to-even) -------------------

func TestBucketBps_RoundHalfToEven(t *testing.T) {
	cases := []struct {
		in   uint16
		want uint16
	}{
		{0, 0},
		{1, 0},
		{499, 0},
		{500, 0},    // .5 at index 0 -> even (0)
		{501, 1000}, // just over midpoint rounds up
		{999, 1000},
		{1000, 1000},
		{1499, 1000},
		{1500, 2000}, // .5 at index 1 (odd) -> round to even (2)
		{1501, 2000},
		{2000, 2000},
		{2499, 2000},
		{2500, 2000}, // .5 at index 2 (even) -> stay (2)
		{2501, 3000},
		{3500, 4000}, // .5 at index 3 (odd) -> 4
		{9499, 9000},
		{9500, 10000}, // .5 at index 9 (odd) -> 10
		{9999, 10000},
		{10000, 10000},
		{12345, 10000}, // clamp
	}
	for _, c := range cases {
		d := Decision{ConfidenceBps: c.in}
		if got := d.BucketBps(); got != c.want {
			t.Errorf("BucketBps(%d) = %d, want %d", c.in, got, c.want)
		}
	}
}

// The governance consensus hash must be INDEPENDENT of rationale/citations and
// DEPENDENT on {spec, vote, bucket}. This is the rationale-exclusion proof.
func TestOutputHashGovernance_RationaleExcluded(t *testing.T) {
	spec := h(0xAB)
	base := Decision{ModelSpecHash: spec, Vote: VoteYes, ConfidenceBps: 8200}

	d1 := base
	d1.Rationale = "Approve: the proposal funds core infra and the budget is sound."
	d1.Citations = []string{"ipfs://Qm111", "https://forum/post/1"}

	d2 := base
	d2.Rationale = "YES — infra funding justified; numbers check out. Different words entirely."
	d2.Citations = nil

	if OutputHashGovernance(d1) != OutputHashGovernance(d2) {
		t.Fatal("rationale/citations leaked into the consensus hash: identical {vote,bucket} must hash identically")
	}

	// Same raw confidence inside the SAME bucket must also match.
	d3 := base
	d3.ConfidenceBps = 8499 // snaps to 8000, same as 8200
	if OutputHashGovernance(base) != OutputHashGovernance(d3) {
		t.Fatalf("same-bucket confidences (8200 vs 8499 -> 8000) did not match")
	}

	// Different vote must NOT match.
	dNo := base
	dNo.Vote = VoteNo
	if OutputHashGovernance(base) == OutputHashGovernance(dNo) {
		t.Fatal("different votes collided into the same consensus hash")
	}

	// Different bucket must NOT match.
	dLow := base
	dLow.ConfidenceBps = 2000
	if OutputHashGovernance(base) == OutputHashGovernance(dLow) {
		t.Fatal("different buckets collided")
	}

	// Different spec must NOT match (spec is bound in).
	dSpec := base
	dSpec.ModelSpecHash = h(0xCD)
	if OutputHashGovernance(base) == OutputHashGovernance(dSpec) {
		t.Fatal("different spec collided — spec not bound into the decision")
	}
}

func TestConsensusPreimage_Layout(t *testing.T) {
	spec := h(0x7E)
	d := Decision{ModelSpecHash: spec, Vote: VoteNo, ConfidenceBps: 3000}
	p := d.consensusPreimage()
	if len(p) != 35 {
		t.Fatalf("preimage len = %d, want 35", len(p))
	}
	if !bytes.Equal(p[:32], spec.Bytes()) {
		t.Fatal("preimage[0:32] != spec")
	}
	if p[32] != byte(VoteNo) {
		t.Fatalf("vote byte = %d, want %d", p[32], VoteNo)
	}
	if binary.BigEndian.Uint16(p[33:35]) != 3000 {
		t.Fatalf("bucket = %d, want 3000", binary.BigEndian.Uint16(p[33:35]))
	}
}

// --- governance: strict parse + fail-secure -------------------------------

func TestParseDecision_Valid(t *testing.T) {
	spec := h(0x42)
	raw := []byte(`{"vote":"yes","confidence_bps":7500,"rationale":"sound","citations":["a","b"],"model_spec":"` + spec.Hex() + `"}`)
	d, err := ParseDecision(raw, spec)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if d.Vote != VoteYes || d.ConfidenceBps != 7500 || d.Rationale != "sound" || len(d.Citations) != 2 {
		t.Fatalf("parsed wrong: %+v", d)
	}
	if d.ModelSpecHash != spec {
		t.Fatal("spec not bound on parse")
	}
}

func TestParseDecision_Rejections(t *testing.T) {
	spec := h(0x42)
	ok := spec.Hex()
	cases := map[string]string{
		"unknown field":       `{"vote":"yes","confidence_bps":1,"rationale":"r","model_spec":"` + ok + `","evil":1}`,
		"bad vote":            `{"vote":"maybe","confidence_bps":1,"rationale":"r","model_spec":"` + ok + `"}`,
		"missing vote":        `{"confidence_bps":1,"rationale":"r","model_spec":"` + ok + `"}`,
		"confidence too high": `{"vote":"yes","confidence_bps":10001,"rationale":"r","model_spec":"` + ok + `"}`,
		"confidence negative": `{"vote":"yes","confidence_bps":-1,"rationale":"r","model_spec":"` + ok + `"}`,
		"missing confidence":  `{"vote":"yes","rationale":"r","model_spec":"` + ok + `"}`,
		"missing rationale":   `{"vote":"yes","confidence_bps":1,"model_spec":"` + ok + `"}`,
		"missing model_spec":  `{"vote":"yes","confidence_bps":1,"rationale":"r"}`,
		"wrong model_spec":    `{"vote":"yes","confidence_bps":1,"rationale":"r","model_spec":"` + h(0x99).Hex() + `"}`,
		"trailing data":       `{"vote":"yes","confidence_bps":1,"rationale":"r","model_spec":"` + ok + `"} garbage`,
		"trailing json":       `{"vote":"yes","confidence_bps":1,"rationale":"r","model_spec":"` + ok + `"}{}`,
		"not an object":       `"yes"`,
		"empty":               ``,
		"prose before":        `Sure! {"vote":"yes","confidence_bps":1,"rationale":"r","model_spec":"` + ok + `"}`,
	}
	for name, raw := range cases {
		if _, err := ParseDecision([]byte(raw), spec); err == nil {
			t.Errorf("%s: expected rejection, got nil error for %q", name, raw)
		}
	}
}

func TestAbstain(t *testing.T) {
	spec := h(7)
	d := Abstain(spec, "parse failed twice")
	if d.Vote != VoteAbstain || d.ConfidenceBps != 0 || d.ModelSpecHash != spec {
		t.Fatalf("abstain wrong: %+v", d)
	}
	// Two operators that both abstain (different reasons) still agree on the
	// consensus hash — a quorum of abstentions is a legitimate outcome.
	d2 := Abstain(spec, "engine error")
	if OutputHashGovernance(d) != OutputHashGovernance(d2) {
		t.Fatal("two abstentions under the same spec must produce the same consensus hash")
	}
}

// --- embedding quantization ----------------------------------------------

func TestQuantizeEmbedding_Layout(t *testing.T) {
	v := []float32{0, 0.5, -0.5, 1.0, -1.0}
	ser, scale, err := QuantizeEmbedding(v)
	if err != nil {
		t.Fatalf("QuantizeEmbedding: %v", err)
	}
	// scale = max|v| / 127 = 1/127
	if got := binary.BigEndian.Uint32(ser[:4]); got != uint32(len(v)) {
		t.Fatalf("dim header = %d, want %d", got, len(v))
	}
	// layout total = 4 + dim + 4
	if len(ser) != 4+len(v)+4 {
		t.Fatalf("serialized len = %d, want %d", len(ser), 4+len(v)+4)
	}
	// scale is f32be at the tail.
	if tail := binary.BigEndian.Uint32(ser[len(ser)-4:]); tail != math.Float32bits(scale) {
		t.Fatalf("scale tail mismatch: tail=%08x want=%08x", tail, math.Float32bits(scale))
	}
	// 1.0 / (1/127) = 127 -> int8 127; -1.0 -> -127; 0 -> 0.
	q := ser[4 : 4+len(v)]
	if int8(q[3]) != 127 || int8(q[4]) != -127 || int8(q[0]) != 0 {
		t.Fatalf("quantization wrong: q=%v", []int8{int8(q[0]), int8(q[1]), int8(q[2]), int8(q[3]), int8(q[4])})
	}
}

func TestQuantizeEmbedding_AllZeroScaleOne(t *testing.T) {
	ser, scale, err := QuantizeEmbedding([]float32{0, 0, 0})
	if err != nil {
		t.Fatalf("QuantizeEmbedding: %v", err)
	}
	if scale != 1 {
		t.Fatalf("all-zero scale = %v, want 1", scale)
	}
	for _, b := range ser[4 : 4+3] {
		if int8(b) != 0 {
			t.Fatal("all-zero vector must quantize to all-zero int8")
		}
	}
}

func TestQuantizeEmbedding_RoundHalfToEven(t *testing.T) {
	// Construct a vector where v_i/scale lands exactly on .5 boundaries.
	// scale = max|v|/127. Pick max = 127 so scale = 1, then values 0.5, 1.5, 2.5.
	v := []float32{127, 0.5, 1.5, 2.5, 3.5}
	ser, scale, err := QuantizeEmbedding(v)
	if err != nil {
		t.Fatalf("QuantizeEmbedding: %v", err)
	}
	if scale != 1 {
		t.Fatalf("scale = %v, want 1", scale)
	}
	q := ser[4 : 4+len(v)]
	// round-half-to-even: 0.5->0, 1.5->2, 2.5->2, 3.5->4
	want := []int8{127, 0, 2, 2, 4}
	for i := range want {
		if int8(q[i]) != want[i] {
			t.Errorf("q[%d] = %d, want %d (round-half-to-even)", i, int8(q[i]), want[i])
		}
	}
}

func TestEmbeddingHash_Deterministic(t *testing.T) {
	mustEmb := func(v []float32) common.Hash {
		t.Helper()
		h, err := EmbeddingHash(v)
		if err != nil {
			t.Fatalf("EmbeddingHash: %v", err)
		}
		return h
	}
	v := []float32{0.1, -0.2, 0.3, 0.9, -0.7}
	if mustEmb(v) != mustEmb(append([]float32(nil), v...)) {
		t.Fatal("embedding hash not deterministic for identical input")
	}
	w := append([]float32(nil), v...)
	w[0] = 0.1000001 // perturb beyond a quantization step at this scale
	// Not guaranteed to differ for tiny perturbations within a bucket; use a clear change.
	w[0] = 0.5
	if mustEmb(v) == mustEmb(w) {
		t.Fatal("clearly different embeddings collided")
	}
}

// --- RFC 8785 canonical JSON ---------------------------------------------

func TestCanonicalJSON_KeySortingAndStability(t *testing.T) {
	r := AuditRecord{
		JobID:         "0x01",
		ModelSpecHash: "0x02",
		Mode:          "governance",
		Operator:      "0x03",
		Vote:          "yes",
		ConfidenceBps: 8200,
		BucketBps:     8000,
		Rationale:     "ok",
		Citations:     []string{"a", "b"},
		OutputHash:    "0x04",
		EmbeddingHash: "0x05",
		Nonce:         "0x06",
		Commit:        "0x07",
	}
	out := string(r.CanonicalJSON())

	// Keys must appear in lexicographic order. Spot-check a few orderings.
	idx := func(k string) int { return strings.Index(out, `"`+k+`":`) }
	keysInOrder := []string{"bucket_bps", "citations", "commit", "confidence_bps", "embedding_hash", "job_id", "mode", "model_spec_hash", "nonce", "operator", "output_hash", "rationale", "vote"}
	prev := -1
	for _, k := range keysInOrder {
		at := idx(k)
		if at < 0 {
			t.Fatalf("key %q missing from canonical output", k)
		}
		if at < prev {
			t.Fatalf("key %q out of sorted order in: %s", k, out)
		}
		prev = at
	}

	// Deterministic: re-marshal is byte-identical.
	if string(r.CanonicalJSON()) != out {
		t.Fatal("CanonicalJSON not deterministic")
	}

	// Must be valid JSON.
	var sink map[string]any
	if err := json.Unmarshal([]byte(out), &sink); err != nil {
		t.Fatalf("canonical output is not valid JSON: %v\n%s", err, out)
	}
}

func TestCanonicalJSON_InjectionSafe(t *testing.T) {
	// A malicious rationale tries to break out of its string and inject members.
	evil := "\",\"vote\":\"no\",\"x\":\"" + "\x00\x07\b\t\n\f\r\"\\</>&" + "\u4e16\u754c"
	r := AuditRecord{Mode: "governance", Vote: "yes", Rationale: evil}
	out := r.CanonicalJSON()

	// Output must still be valid JSON and the top-level vote must remain "yes"
	// (the injected "vote":"no" must be trapped inside the rationale string).
	var m map[string]any
	if err := json.Unmarshal(out, &m); err != nil {
		t.Fatalf("injection broke JSON validity: %v\n%s", err, out)
	}
	if m["vote"] != "yes" {
		t.Fatalf("injection escaped the rationale string: vote=%v", m["vote"])
	}
	if m["rationale"] != evil {
		t.Fatalf("rationale round-trip mismatch:\n got %q\nwant %q", m["rationale"], evil)
	}

	// JCS specifics: <,>,& and non-ASCII are NOT escaped; control chars are.
	s := string(out)
	if !strings.Contains(s, "</>&") {
		t.Error("JCS must not HTML-escape <,>,&")
	}
	if !strings.Contains(s, "\u4e16\u754c") {
		t.Error("JCS must emit non-ASCII as literal UTF-8")
	}
	if !strings.Contains(s, "\\u0000") || !strings.Contains(s, "\\u0007") {
		t.Error("JCS must \\u-escape C0 control chars without short forms (NUL, BEL)")
	}
	if !strings.Contains(s, "\\b") || !strings.Contains(s, "\\t") || !strings.Contains(s, "\\n") || !strings.Contains(s, "\\f") || !strings.Contains(s, "\\r") {
		t.Error("JCS must use short escapes for \\b \\t \\n \\f \\r")
	}
}
