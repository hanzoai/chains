// Copyright (C) 2026, Hanzo AI Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package canonical

import (
	"sort"
	"strconv"
	"strings"
)

// ============================================================================
// RFC 8785 (JSON Canonicalization Scheme, JCS) — for the AUDIT record only
// ============================================================================
//
// This produces a single deterministic byte string for the FULL governance
// record (including the non-consensus rationale/citations) so it can be stored
// and audited reproducibly. It is NOT the consensus hash — the quorum is gated
// by OutputHashGovernance over the structured decision only (see governance.go).
//
// We implement the parts of JCS we need and constrain the inputs so the hard
// parts are trivially correct:
//
//   - Object member order: members are emitted sorted by member NAME. JCS sorts
//     names as sequences of UTF-16 code units; our record uses only ASCII names,
//     for which UTF-16-code-unit order equals byte order, so sort.Strings is
//     exactly correct. (Constraint: keys must be ASCII — they are, they're fixed
//     literals in this file.)
//   - String escaping: the JCS/ECMAScript rules, hand-rolled in escapeJCSString.
//     Notably this does NOT HTML-escape <,>,& and does NOT escape U+2028/U+2029,
//     so it differs from encoding/json's default and we cannot delegate to it.
//   - Numbers: we emit INTEGERS ONLY. JCS number canonicalization for arbitrary
//     floats requires the ECMAScript shortest-round-trip algorithm; we sidestep
//     that minefield entirely by restricting the audit record's numeric fields
//     to integers (confidence_bps is an int in [0,10000]). Integers serialize
//     unambiguously via strconv.FormatInt.
//
// JSON-INJECTION SAFETY (for RED): every string value is escaped, so a model's
// rationale or a citation containing quotes, braces, or control characters
// CANNOT break out of its JSON string or inject sibling members — the output is
// always well-formed JSON. And since this record never feeds the consensus hash,
// even a maximally adversarial rationale cannot influence whether a quorum forms.

// jcsValue is the minimal value model the JCS serializer walks. Keeping the model
// typed (string/int/array/object only) makes it impossible for a float to enter
// the audit record by accident.
type jcsValue interface{ writeJCS(b *strings.Builder) }

type jcsString string

func (s jcsString) writeJCS(b *strings.Builder) { escapeJCSString(b, string(s)) }

type jcsInt int64

func (n jcsInt) writeJCS(b *strings.Builder) { b.WriteString(strconv.FormatInt(int64(n), 10)) }

type jcsArray []jcsValue

func (a jcsArray) writeJCS(b *strings.Builder) {
	b.WriteByte('[')
	for i, v := range a {
		if i > 0 {
			b.WriteByte(',')
		}
		v.writeJCS(b)
	}
	b.WriteByte(']')
}

// jcsMember is one object entry; jcsObject sorts these by Name before emitting.
type jcsMember struct {
	Name  string
	Value jcsValue
}

type jcsObject []jcsMember

func (o jcsObject) writeJCS(b *strings.Builder) {
	// Stable sort by ASCII name == JCS UTF-16-code-unit order for ASCII keys.
	sorted := make([]jcsMember, len(o))
	copy(sorted, o)
	sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].Name < sorted[j].Name })
	b.WriteByte('{')
	for i, m := range sorted {
		if i > 0 {
			b.WriteByte(',')
		}
		escapeJCSString(b, m.Name) // names are strings too, escaped identically
		b.WriteByte(':')
		m.Value.writeJCS(b)
	}
	b.WriteByte('}')
}

// escapeJCSString writes s as a JCS/ECMAScript-escaped JSON string (including the
// surrounding quotes). Short escapes for the five named control chars and for
// quote/backslash; \u00xx (lowercase) for the remaining C0 controls; everything
// >= 0x20 (including non-ASCII and <,>,&) is emitted as literal UTF-8.
func escapeJCSString(b *strings.Builder, s string) {
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\b':
			b.WriteString(`\b`)
		case '\t':
			b.WriteString(`\t`)
		case '\n':
			b.WriteString(`\n`)
		case '\f':
			b.WriteString(`\f`)
		case '\r':
			b.WriteString(`\r`)
		default:
			if r < 0x20 {
				const hex = "0123456789abcdef"
				b.WriteString(`\u00`)
				b.WriteByte(hex[(r>>4)&0xf])
				b.WriteByte(hex[r&0xf])
			} else {
				b.WriteRune(r)
			}
		}
	}
	b.WriteByte('"')
}

// AuditRecord is the full, storable governance record. It carries BOTH the
// consensus-relevant fields and the non-consensus audit metadata (rationale,
// citations). Its CanonicalJSON is reproducible for storage/audit; it is NOT the
// consensus hash. The numeric field (ConfidenceBps) is an integer so JCS number
// canonicalization is trivial.
type AuditRecord struct {
	JobID         string   // 0x-hex job id
	ModelSpecHash string   // 0x-hex spec hash (also echoed by the model as model_spec)
	Mode          string   // "raw" | "governance"
	Operator      string   // 0x-hex operator address (the signer)
	Vote          string   // "yes"|"no"|"abstain" (governance); "" for raw
	ConfidenceBps int64    // raw confidence the model reported (governance); 0 for raw
	BucketBps     int64    // snapped consensus bucket (governance); 0 for raw
	Rationale     string   // non-consensus free-form reasoning
	Citations     []string // non-consensus references
	OutputHash    string   // 0x-hex consensus output_hash
	EmbeddingHash string   // 0x-hex embedding_hash
	Nonce         string   // 0x-hex commit nonce
	Commit        string   // 0x-hex commit
}

// CanonicalJSON returns the RFC 8785 canonical serialization of the audit record.
// Identical records yield byte-identical output regardless of field order at
// construction. Suitable for content-addressing or signing the audit blob.
func (r AuditRecord) CanonicalJSON() []byte {
	cites := make(jcsArray, len(r.Citations))
	for i, c := range r.Citations {
		cites[i] = jcsString(c)
	}
	obj := jcsObject{
		{"job_id", jcsString(r.JobID)},
		{"model_spec_hash", jcsString(r.ModelSpecHash)},
		{"mode", jcsString(r.Mode)},
		{"operator", jcsString(r.Operator)},
		{"vote", jcsString(r.Vote)},
		{"confidence_bps", jcsInt(r.ConfidenceBps)},
		{"bucket_bps", jcsInt(r.BucketBps)},
		{"rationale", jcsString(r.Rationale)},
		{"citations", cites},
		{"output_hash", jcsString(r.OutputHash)},
		{"embedding_hash", jcsString(r.EmbeddingHash)},
		{"nonce", jcsString(r.Nonce)},
		{"commit", jcsString(r.Commit)},
	}
	var b strings.Builder
	obj.writeJCS(&b)
	return []byte(b.String())
}
