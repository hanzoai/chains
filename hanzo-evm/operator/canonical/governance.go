// Copyright (C) 2026, Hanzo AI Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package canonical

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/luxfi/geth/common"
)

// ============================================================================
// GOVERNANCE consensus — the load-bearing determinism decision
// ============================================================================
//
// THE PROBLEM. A governance job asks N independent operators "should this pass?"
// Each runs an LLM that emits a JSON verdict. We need >= threshold of them to
// produce the SAME 32-byte output_hash so the chain sees agreement. But an LLM's
// free-form `rationale` prose will NOT be byte-identical across operators:
// greedy decoding is bit-identical only within one engine build on matching
// hardware, and even there a one-token difference (a synonym, a reordered
// clause) makes two rationales hash differently. If the consensus hash covered
// the rationale, quorum would essentially NEVER form — the system would be
// useless for governance.
//
// THE DECISION (and its justification). The consensus hash covers ONLY the
// STRUCTURED DECISION that operators can actually agree on:
//
//	{ vote, confidence_bucket }   bound to   model_spec_hash
//
//   - vote ∈ {yes, no, abstain} is a 3-way categorical — trivially agreeable.
//   - confidence_bps (0..10000) is snapped to a coarse grid (default: nearest
//     1000 bps, 11 buckets) so small numeric wobble between operators collapses
//     to the same bucket. The snap uses INTEGER round-half-to-even (banker's
//     rounding) so it is exactly reproducible with no floating point and no
//     directional bias.
//   - model_spec_hash is bound in so a decision can only equal another decision
//     made under the IDENTICAL spec.
//
// `rationale` and `citations` are deliberately EXCLUDED from the consensus hash.
// They are non-consensus AUDIT metadata: revealed in the reveal payload and
// stored (canonicalized by canonicaljson.go), inspectable by humans and
// auditors, but never gating the quorum. This is the one true place that
// decision is made and documented.
//
// THE PREIMAGE (one definition, fixed width, documented):
//
//	consensus_preimage = model_spec_hash(32) || vote_byte(1) || u16be(bucket_bps)(2)   // 35 bytes
//	output_hash        = keccak256(consensus_preimage)                                 // see OutputHashGovernance
//
//	vote_byte:  yes=1, no=2, abstain=3   (0 is reserved/invalid — a zero byte can
//	            never be a valid vote, so a malformed decision can never collide
//	            with a real one)
//	bucket_bps: the SNAPPED confidence in basis points ∈ {0,1000,...,10000}, big-
//	            endian u16. The snapped value (not the bucket index) is stored so
//	            the preimage is self-describing and u16 comfortably holds 10000.

// Vote is the categorical governance verdict.
type Vote uint8

const (
	// VoteInvalid is the zero value — never a valid vote. Its byte (0) cannot
	// appear in a well-formed consensus preimage, so a malformed/zero Decision is
	// structurally distinguishable from any real vote.
	VoteInvalid Vote = 0
	VoteYes     Vote = 1
	VoteNo      Vote = 2
	VoteAbstain Vote = 3
)

// String renders the wire token for a vote (also the JSON value).
func (v Vote) String() string {
	switch v {
	case VoteYes:
		return "yes"
	case VoteNo:
		return "no"
	case VoteAbstain:
		return "abstain"
	default:
		return "invalid"
	}
}

// parseVote maps a JSON token to a Vote, rejecting anything else. There is
// exactly one accepted spelling per vote (lowercase) — no aliasing, no case
// folding — so two operators cannot disagree on the encoding of the same intent.
func parseVote(s string) (Vote, error) {
	switch s {
	case "yes":
		return VoteYes, nil
	case "no":
		return VoteNo, nil
	case "abstain":
		return VoteAbstain, nil
	default:
		return VoteInvalid, fmt.Errorf("canonical: invalid vote %q (want yes|no|abstain)", s)
	}
}

// ConfidenceGridBps is the bucket width in basis points. confidence_bps is
// snapped to the nearest multiple of this. 1000 bps = 10 percentage points = 11
// buckets (0,10,20,...,100%). This is a protocol constant, not a per-call knob:
// every operator must snap to the identical grid or the buckets won't match.
const ConfidenceGridBps = 1000

// MaxConfidenceBps is the inclusive upper bound on confidence (100.00%).
const MaxConfidenceBps = 10000

// Decision is the consensus-relevant part of a governance verdict, plus the
// non-consensus audit fields. Only Vote and ConfidenceBps (via bucketing) feed
// the consensus hash; Rationale and Citations are audit-only and are NEVER
// hashed into output_hash.
type Decision struct {
	ModelSpecHash common.Hash // the spec this decision was made under (bound into the hash)
	Vote          Vote        // consensus field
	ConfidenceBps uint16      // consensus field (after bucketing); raw 0..10000

	// --- audit-only, NOT in the consensus hash ---
	Rationale string   // free-form reasoning; differs across operators by design
	Citations []string // supporting references; audit metadata only
}

// BucketBps snaps ConfidenceBps to the consensus grid using INTEGER round-half-
// to-even (banker's rounding) — fully deterministic, no floating point, no
// directional bias. Returns the snapped value in basis points (a multiple of
// ConfidenceGridBps), clamped to [0, MaxConfidenceBps].
//
// Worked half-cases (grid 1000): 500 -> 0 (index 0 is even), 1500 -> 2000 (round
// to even index 2), 2500 -> 2000 (index 2 even), 3500 -> 4000 (index 4 even).
//
// FRAGILITY (documented, surfaced for RED): bucketing has hard cliffs. Two
// operators whose models report confidence on opposite sides of a grid midpoint
// (e.g. 2499 vs 2501 bps with grid 1000) snap to different buckets (2000 vs
// 3000) and FAIL to agree. This is inherent to any quantization of a continuous
// quantity; it is a real divergence in the model's confidence, not a bug. A
// coarser grid reduces the cliff frequency at the cost of resolution. The vote
// (categorical) carries the primary signal; confidence is secondary.
func (d Decision) BucketBps() uint16 {
	bps := d.ConfidenceBps
	if bps > MaxConfidenceBps {
		bps = MaxConfidenceBps
	}
	const g = ConfidenceGridBps
	q := bps / g // floor bucket index
	r := bps % g // remainder within the bucket
	idx := uint32(q)
	switch {
	case r*2 < g:
		// below midpoint: round down (idx unchanged)
	case r*2 > g:
		idx = uint32(q) + 1 // above midpoint: round up
	default:
		// exactly the midpoint: round to even index
		if q%2 != 0 {
			idx = uint32(q) + 1
		}
	}
	snapped := idx * g
	if snapped > MaxConfidenceBps {
		snapped = MaxConfidenceBps
	}
	return uint16(snapped)
}

// consensusPreimage builds the 35-byte canonical structured-decision bytes that
// OutputHashGovernance hashes. This is the ONLY thing that gates a governance
// quorum.
func (d Decision) consensusPreimage() []byte {
	buf := make([]byte, 0, 32+1+2)
	buf = append(buf, d.ModelSpecHash.Bytes()...)
	buf = append(buf, byte(d.Vote))
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], d.BucketBps())
	buf = append(buf, b[:]...)
	return buf
}

// ConsensusKey is a compact human-readable description of the consensus-relevant
// content of a decision (spec || vote || bucket). Two decisions produce the same
// output_hash iff they produce the same ConsensusKey. Used in the proof output
// to make "different prose, identical consensus" legible.
func (d Decision) ConsensusKey() string {
	return fmt.Sprintf("spec=%s vote=%s bucket=%dbps", d.ModelSpecHash.Hex(), d.Vote, d.BucketBps())
}

// ----------------------------------------------------------------------------
// Strict parse: raw model JSON -> validated Decision
// ----------------------------------------------------------------------------

// ErrInvalidDecision is returned when raw model text cannot be validated into the
// strict governance schema. The operator's policy on this error is to retry
// inference once, then ABSTAIN (see operator.Operator.RunGovernance) — fail-
// secure: an operator that cannot produce a valid structured decision votes
// abstain rather than crashing the job or guessing yes/no.
var ErrInvalidDecision = errors.New("canonical: invalid governance decision")

// rawDecision is the exact strict schema the model is constrained to emit.
// json.Decoder with DisallowUnknownFields rejects extra keys, so a model that
// hallucinates additional fields fails validation (fail-closed) rather than
// silently dropping them. Pointers distinguish "absent" from "zero".
type rawDecision struct {
	Vote          *string  `json:"vote"`
	ConfidenceBps *int64   `json:"confidence_bps"`
	Rationale     *string  `json:"rationale"`
	Citations     []string `json:"citations"`
	ModelSpec     *string  `json:"model_spec"`
}

// ParseDecision strictly validates raw model output into a Decision bound to
// expectedSpec. It enforces, in order:
//
//   - exactly one well-formed JSON object (no trailing data, no unknown fields);
//   - vote present and ∈ {yes,no,abstain};
//   - confidence_bps present and ∈ [0, 10000];
//   - rationale present (may be empty string), citations may be null/empty;
//   - model_spec present and EQUAL to expectedSpec.Hex() — the model must echo
//     the spec it was told it is operating under. This binds the decision to the
//     spec at parse time and rejects a stale/forged decision pointed at another
//     spec.
//
// On any violation it returns ErrInvalidDecision wrapped with the cause. The
// returned Decision carries the RAW ConfidenceBps; bucketing happens in the
// consensus path so the audit record can show the precise value the model gave.
func ParseDecision(raw []byte, expectedSpec common.Hash) (Decision, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()

	var rd rawDecision
	if err := dec.Decode(&rd); err != nil {
		return Decision{}, fmt.Errorf("%w: decode: %v", ErrInvalidDecision, err)
	}
	// Reject trailing tokens after the object (e.g. a second JSON value, or
	// prose appended after the closing brace). Exactly one value is allowed.
	if dec.More() {
		return Decision{}, fmt.Errorf("%w: trailing data after JSON object", ErrInvalidDecision)
	}

	if rd.Vote == nil {
		return Decision{}, fmt.Errorf("%w: missing vote", ErrInvalidDecision)
	}
	vote, err := parseVote(*rd.Vote)
	if err != nil {
		return Decision{}, fmt.Errorf("%w: %v", ErrInvalidDecision, err)
	}
	if rd.ConfidenceBps == nil {
		return Decision{}, fmt.Errorf("%w: missing confidence_bps", ErrInvalidDecision)
	}
	if *rd.ConfidenceBps < 0 || *rd.ConfidenceBps > MaxConfidenceBps {
		return Decision{}, fmt.Errorf("%w: confidence_bps %d out of [0,%d]", ErrInvalidDecision, *rd.ConfidenceBps, MaxConfidenceBps)
	}
	if rd.Rationale == nil {
		return Decision{}, fmt.Errorf("%w: missing rationale", ErrInvalidDecision)
	}
	if rd.ModelSpec == nil {
		return Decision{}, fmt.Errorf("%w: missing model_spec", ErrInvalidDecision)
	}
	if *rd.ModelSpec != expectedSpec.Hex() {
		return Decision{}, fmt.Errorf("%w: model_spec %q != expected %q", ErrInvalidDecision, *rd.ModelSpec, expectedSpec.Hex())
	}

	return Decision{
		ModelSpecHash: expectedSpec,
		Vote:          vote,
		ConfidenceBps: uint16(*rd.ConfidenceBps),
		Rationale:     *rd.Rationale,
		Citations:     rd.Citations,
	}, nil
}

// Abstain is the fail-secure decision an operator emits when it cannot produce a
// valid structured verdict (e.g. ParseDecision failed after a retry). It is a
// genuine abstain vote at zero confidence, bound to the spec, with a fixed
// machine rationale. Because abstain is a real vote, abstaining operators that
// agree still form a quorum of abstentions (a legitimate "no decision" outcome)
// rather than silently dropping out.
func Abstain(spec common.Hash, reason string) Decision {
	return Decision{
		ModelSpecHash: spec,
		Vote:          VoteAbstain,
		ConfidenceBps: 0,
		Rationale:     "operator abstained: " + reason,
		Citations:     nil,
	}
}
