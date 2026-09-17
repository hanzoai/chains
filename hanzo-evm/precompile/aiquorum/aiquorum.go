// Copyright (C) 2026, Hanzo AI Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package aiquorum implements the on-chain quorum-settlement precompile for
// off-chain LLM inference on the Hanzo C-Chain EVM (luxfi/evm).
//
// # What validators agree on (and what they DON'T)
//
// Validators NEVER run the LLM. They agree ONLY on the SETTLEMENT RESULT of a
// commit-reveal quorum: did at least `threshold` staked operators independently
// submit the SAME answer under the SAME required ModelSpec? The actual
// inference runs off-chain (the Hanzo engine; EVM-side at evmllm 0x020001 /
// Rust exec_ai_inference). Operators report only a 32-byte output_hash; the
// chain treats it as opaque. Consensus is over the agreement, not the compute.
//
// # Address
//
//	0x0300000000000000000000000000000000000012 — AI range (0x0300-0x03FF),
//	adjacent to:
//	  0x020001                       evmllm AIInference  (the off-chain inference path)
//	  0x0300...0011                  aimarket            (priced per-token metering ledger)
//	  0x0300...0012  (this)          aiquorum            (quorum settlement: stake / commit-
//	                                                      reveal / pay / slash)
//
// The three are orthogonal: 0x020001 produces an answer, aimarket prices a
// single operator's usage, aiquorum decides whether N operators AGREE and
// settles stake/reward on that agreement. An operator can carry both an
// aimarket credit and an aiquorum credit; the two ledgers never alias (distinct
// escrow accounts, distinct keccak namespaces).
//
// # Lifecycle (windows by block height — the only nondeterminism source)
//
//	Requested ─RequestInference→ Committing ─(commit window)→ Revealing
//	          ─(reveal window)→  Settle ───→ Settled | Failed
//
//	commitDeadline = requestBlock + commitBlocks
//	revealDeadline = commitDeadline + revealBlocks
//
//	CommitResponse : block <= commitDeadline, caller SELECTED, no prior commit.
//	RevealResponse : commitDeadline < block <= revealDeadline, prior commit,
//	                 no prior reveal, recomputed commit == stored commit.
//	Settle         : block > revealDeadline; idempotent (settled marker).
//
// Only contract.BlockContext.Number() is consulted. No wall-clock, no RNG.
//
// # ModelSpec hash (SHARED WIRE SPEC — byte-identical to the off-chain prover)
//
// Fields in canonical order; the two strings carry a 4-byte big-endian length
// prefix, the six hashes are fixed 32-byte:
//
//	model_spec_hash = keccak256(
//	    u32be(len(model_id)) || model_id ||
//	    model_hash(32) || tokenizer_hash(32) ||
//	    u32be(len(runtime_version)) || runtime_version ||
//	    sampling_hash(32) || prompt_template_hash(32) || embedding_model_hash(32) )
//
// ComputeModelSpecHash implements exactly this so an external prover's hash can
// be verified on-chain. The chain stores only the 32-byte digest per job; the
// preimage is reproduced off-chain.
//
// # Commit preimage (SHARED WIRE SPEC — operator-bound, fixed width)
//
//	commit = keccak256(
//	    job_id(32) || model_spec_hash(32) || prompt_hash(32) ||
//	    output_hash(32) || embedding_hash(32) || operator(20) || nonce(32) )
//
// The operator address is bound INTO the commit. This is the anti-copy /
// anti-front-run control: a peer who observes operator A's commit hash cannot
// replay it as their own — recomputation with their own 20-byte address yields a
// different digest, so RevealResponse rejects it.
//
// # Deterministic operator selection (the beacon — reproducible by anyone)
//
// luxfi's contract.BlockContext exposes only Number()+Timestamp(): there is no
// blockhash / prevrandao accessor. The selection entropy is therefore anchored
// in the job_id itself:
//
//	job_id = keccak256("aiq/job", requester(20), requesterNonce(32),
//	                   modelSpecHash(32), promptHash(32), u64be(requestBlock),
//	                   u32be(N), u32be(threshold))
//
// job_id folds in the requester's monotonic nonce and the request block, so it
// is fully reproducible after the request lands and IDENTICAL across every
// validator. Because luxfi exposes no in-consensus entropy (no blockhash /
// prevrandao) to a precompile, the beacon is anchored ONLY in values knowable to
// the requester at submit time.
//
// Selection draws N distinct operators from the eligible set E (operators that
// advertise modelSpecHash with bonded stake >= minStake and are not unbonding),
// in registry-insertion order, by Fisher–Yates partial shuffle:
//
//	working = E (a copy, in insertion order)
//	for i in 0 .. N-1:
//	    j = i + ( u256(keccak256(job_id, u32be(i))) mod (len(working) - i) )
//	    swap working[i], working[j]      // selected = working[0:N]
//
// Anyone can rebuild E from the on-chain per-ModelSpec operator array, run the
// identical draw, and reproduce the exact selected set.
//
// # Selection threat model (what the beacon does and does NOT guarantee)
//
// The beacon is unbiased and unmanipulable against any party that does NOT
// control the requester: a third-party operator cannot influence job_id (set by
// the requester+chain) nor its own array index relative to others, so it cannot
// self-select.
//
// It is NOT a cryptographic defense against a malicious requester, nor against a
// requester that colludes with operators. The requester chooses promptHash (an
// opaque 32-byte field the chain never validates), N, and threshold, and
// influences requestBlock by choosing when to submit; the only chain-supplied
// component, the nonce, is monotonic and READABLE in advance. A requester can
// therefore enumerate candidate job_ids OFFLINE and pick a draw that (a) selects
// only its own operators — manufacturing an attacker-chosen canonical output_hash
// — or (b) excludes a specific operator (censorship). luxfi exposes no
// in-consensus randomness (no blockhash / prevrandao) to a precompile, so this
// grind CANNOT be closed with on-chain entropy. The mitigation is therefore
// ECONOMIC + SET-SIZE (RED-A), which is the honest fix on this platform:
//
//	(1) ELIGIBLE-SET MARGIN (RequestInference + requiredMargin): a job is rejected
//	    unless the eligible pool E for the ModelSpec satisfies
//	    E >= N + max(RequestMarginFloor, N*RequestMarginBps/1e4). This forbids
//	    degenerate pools where selection has no sampling headroom over an
//	    independent set, and guarantees the draw is always a strict subset of a
//	    larger universe (a single cheap operator is never the whole pool).
//	(2) NON-REFUNDABLE REQUEST FEE (RequestFeePerOperator, burned to BurnAddress):
//	    every distinct on-chain request costs N*RequestFeePerOperator, refunded to
//	    NO ONE — not even when the job later fails to reach quorum (only the reward
//	    escrow refunds). This prices REPEATED requests: a grinder who must submit
//	    many real jobs (varying N/threshold/timing, or censoring by resubmission)
//	    pays the fee on each, so the on-chain cost of the attack scales with N and
//	    with the number of submitted jobs.
//	(3) MinStake as the SYBIL COST: forging a canonical hash requires controlling
//	    >= threshold of the SELECTED set; since selection only ever picks eligible
//	    operators, the attacker must hold >= threshold operators each bonded >=
//	    MinStake. The floor on the cost to even be ABLE to force a hash is thus
//	    threshold * MinStake, independent of any grinding.
//
// RESIDUAL RISK (quantified, stated honestly — see RequestInference for the full
// derivation): the fee does NOT stop a SINGLE offline-grind-then-submit-once,
// because job_id grinding over the free promptHash field is an offline keccak
// search that pays the fee only on the one successful submission. The ABSOLUTE
// bound is information-theoretic and comes from (3): if the attacker controls
// c < threshold eligible operators, NO grind can ever land >= threshold of them
// in the selected set, so forgery is impossible at any compute budget. Forgery is
// possible ONLY when c >= threshold, i.e. only after bonding >= threshold*MinStake.
// Given that floor, the margin (1) keeps the pool non-degenerate and the fee (2)
// bounds multi-job grinding (k submitted jobs cost k*N*RequestFeePerOperator).
//
// CONSEQUENCE: getCanonicalResult is trustworthy to the extent that an attacker
// does not bond >= threshold*MinStake of eligible operators for the ModelSpec.
// Integrity rests on (i) a large, well-distributed eligible set enforced as a
// floor by the margin, (ii) MinStake making the threshold-sized cartel expensive,
// (iii) the fee making repeated grinding pay per attempt, and (iv) downstream
// consumers treating a single job's canonical hash as one staked attestation, NOT
// as unconditional ground truth. This precompile settles AGREEMENT among the
// selected set; it raises the cost of manipulating that set to a quantifiable
// stake+fee bound, but given the platform's lack of in-consensus randomness it
// cannot make the selection unconditionally unbiasable when the requester is the
// adversary.
//
// # Quorum, payment, and slashing (the settlement)
//
// At Settle (block > revealDeadline) the revealers are grouped by output_hash:
//   - If the largest group has size >= threshold: canonical_output_hash := that
//     group's hash; each operator in the winning group is paid rewardPerOperator
//     into its withdrawable credit; non-revealers (selected & committed but
//     never revealed) are slashed slashPerOperator from bonded stake and the
//     slashed wei is credited equally to the winning group (honest-majority
//     bonus). Dissenters (revealed a minority hash) are NOT slashed by default
//     (honest minority / nondeterministic model is plausible; slashing them
//     enables a majority-cartel griefing vector). Job → Settled.
//   - If no group reaches threshold: job → Failed; the requester's full escrow
//     (N*rewardPerOperator) is refunded; non-revealers are still slashed (they
//     withheld regardless of outcome) and that slashed wei is credited to the
//     requester (compensation for the failed job). Revealers keep their stake.
//
// Settle is idempotent: a settled marker makes a second call a no-op error, so
// it is replay-safe across re-execution.
//
// # Money custody (no reentrancy surface)
//
// Two value sinks live at ContractAddress (the escrow account, which holds no
// code): bonded stake and job reward escrow. All movement is balance mutation
// (SubBalance/AddBalance) — never a value-bearing CALL — so no recipient
// fallback runs and there is no reentrancy path through stake, escrow, pay, or
// slash. Every money path is uint256 with checked overflow on credit/stake
// addition and checked underflow on debit; a rejected op makes NO state change
// (fail-closed). The conservation invariant the tests assert:
//
//	balance(ContractAddress) ==
//	    sum(bonded stake) + sum(unsettled job escrow) + sum(unwithdrawn credit)
//
// at every step, and the sum over ALL accounts is constant.
package aiquorum

import (
	"encoding/binary"
	"errors"

	"github.com/holiman/uint256"
	"github.com/luxfi/crypto"
	"github.com/luxfi/geth/common"
)

// ContractAddress is the EVM address of the AI Quorum settlement precompile.
var ContractAddress = common.HexToAddress("0x0300000000000000000000000000000000000012")

// State-slot namespaces. Distinct prefixes guarantee the keccak256 keyspaces of
// different record kinds never collide.
var (
	nsOperator    = []byte("aiq/op")          // operator registry record
	nsModelIndex  = []byte("aiq/mspec.idx")   // per-ModelSpec operator-array length
	nsModelMember = []byte("aiq/mspec.mem")   // per-ModelSpec operator-array element
	nsModelSeen   = []byte("aiq/mspec.seen")  // per-(ModelSpec,operator) array-membership flag
	nsCredit      = []byte("aiq/cred")        // operator withdrawable credit ledger
	nsReqNonce    = []byte("aiq/req.nonce")   // requester monotonic nonce
	nsJob         = []byte("aiq/job")         // job record (status + params)  *** also job_id domain
	nsJobReward   = []byte("aiq/job.reward")  // job rewardPerOperator (uint256)
	nsJobEscrow   = []byte("aiq/job.escrow")  // job remaining escrow (uint256)
	nsSelected    = []byte("aiq/sel")         // per-(job,operator) selection flag
	nsSelList     = []byte("aiq/sel.list")    // per-job selected-operator-array element
	nsCommit      = []byte("aiq/commit")      // per-(job,operator) commit hash
	nsReveal      = []byte("aiq/reveal")      // per-(job,operator) revealed output_hash
	nsRevealFlag  = []byte("aiq/reveal.f")    // per-(job,operator) revealed flag
	nsRevealList  = []byte("aiq/reveal.list") // per-job revealer-array element
	nsRevealCount = []byte("aiq/reveal.cnt")  // per-job revealer count
	nsSettled     = []byte("aiq/settled")     // per-job settled marker (replay guard)
	nsCanonical   = []byte("aiq/canon")       // per-job canonical output_hash
)

// Job lifecycle states (stored in the job record's status byte).
const (
	JobNone       uint8 = 0 // zero value: no such job
	JobCommitting uint8 = 1 // open for commits
	JobSettled    uint8 = 2 // quorum reached, winners paid
	JobFailed     uint8 = 3 // no quorum, requester refunded
)

// Operator registry flags.
const (
	opExistsFlag    uint8 = 0x01 // record exists (distinguishes a real op from zero slot)
	opUnbondingFlag uint8 = 0x02 // deregistration requested; ineligible for new jobs
)

// Protocol bounds. minN forbids trivial self-quorums (a 1-of-1 "quorum" requires
// no agreement, and 2-of-2 is too small to be a meaningful independent quorum);
// 3 is the smallest set where a strict majority (2-of-3) is genuine agreement
// among independent operators. maxN caps the per-job operator set so selection
// and tally are gas-bounded. maxStringLen bounds the two ModelSpec strings so the
// hash preimage is bounded.
const (
	minN         = 3
	maxN         = 256
	maxStringLen = 4096
)

// BurnAddress is the unspendable sink the non-refundable request fee is sent to
// (see RequestFeePerOperator and the RED-A mitigation in RequestInference). It is
// the canonical Ethereum burn address; no precompile method ever pays OUT of it,
// so wei that lands here is permanently removed from circulation. Value is NOT
// destroyed (which would silently break the grand-total conservation invariant),
// it is parked forever in an account no one holds a key to — the honest, invariant-
// preserving form of a burn. The fee is moved requester -> ContractAddress ->
// BurnAddress (reusing the existing Ledger Pull+Pay), so ContractAddress nets zero
// for the fee and its escrow == stake + open-escrow + credit invariant is untouched.
var BurnAddress = common.HexToAddress("0x000000000000000000000000000000000000dEaD")

// Window + economic policy. These are protocol constants (one true configuration,
// not per-call knobs) so every validator computes identical deadlines and
// identical slash math.
var (
	// MinStake is the floor an operator must keep bonded to be eligible for
	// selection. Below this (e.g. after a slash) the operator is skipped. It is
	// also the per-operator SYBIL COST: forging a quorum requires controlling
	// >= threshold operators (see the RED-A residual model in RequestInference),
	// each of which must bond at least MinStake — so the floor on the cost to even
	// be ABLE to force a canonical hash is threshold * MinStake.
	MinStake = uint256.NewInt(1_000_000_000_000_000_000) // 1 token (1e18 wei)

	// SlashPerOperator is the bonded-stake penalty for a selected operator that
	// committed but never revealed (withholding).
	SlashPerOperator = uint256.NewInt(100_000_000_000_000_000) // 0.1 token

	// RequestFeePerOperator is the NON-REFUNDABLE fee charged per selected operator
	// at RequestInference, burned to BurnAddress. It is SEPARATE from the
	// refundable reward escrow: a job that fails to reach quorum refunds the
	// reward but NOT the fee. Its purpose (RED-A mitigation) is to price REPEATED
	// requests — every distinct on-chain request a grinder submits (to vary
	// N/threshold/timing or to censor by resubmission) costs feeTotal = N *
	// RequestFeePerOperator, so it scales with the work the request imposes.
	// 0.01 token (1% of MinStake) makes a burst of grind-resubmissions materially
	// expensive while staying negligible for an honest single request.
	RequestFeePerOperator = uint256.NewInt(10_000_000_000_000_000) // 0.01 token

	// RequestMarginFloor and RequestMarginBps define the ELIGIBLE-SET MARGIN
	// (RED-A): RequestInference is rejected unless the eligible operator count E
	// for the ModelSpec satisfies E >= N + requiredMargin(N). The margin forbids
	// degenerate pools where the selection has little or no sampling freedom over a
	// genuinely independent set, and guarantees there is always a strictly larger
	// pool than the draw so a tiny captured set is never the whole eligible
	// universe. requiredMargin(N) = max(RequestMarginFloor, N*RequestMarginBps/1e4).
	//   - RequestMarginFloor = 2: an absolute pool headroom (E >= N+2 always).
	//   - RequestMarginBps   = 5000 (50%): headroom grows with N, so a large draw
	//     still samples from a proportionally larger pool (E >= ceil(1.5*N) for the
	//     fractional term).
	// This is a NECESSARY set-size control, not a sufficient anti-forgery one: it
	// does not by itself bound a cartel that is a fixed fraction of a large pool
	// (see the residual model on RequestInference). MinStake bounds the cartel's
	// cost; this bounds the pool's degeneracy.
	RequestMarginFloor uint32 = 2
	RequestMarginBps   uint32 = 5000

	// CommitBlocks / RevealBlocks bound the commit and reveal windows. The reveal
	// window opens strictly AFTER the commit window closes so no operator can see
	// a peer's revealed output before committing.
	CommitBlocks uint64 = 30
	RevealBlocks uint64 = 30

	// UnbondCooldownBlocks is how long after DeregisterOperator a withdrawal of
	// stake must wait. It bounds the window in which an operator could be selected
	// for a job that has not yet settled.
	UnbondCooldownBlocks uint64 = 60

	// SlashDissenters controls whether operators who revealed a MINORITY hash are
	// slashed. Default false: honest disagreement (nondeterministic model output)
	// must not be punished, and slashing dissenters would let a majority cartel
	// grief an honest minority. Withholding (non-reveal) is always slashed.
	SlashDissenters = false
)

// Errors. All are returned to the EVM as call failures (revert).
var (
	ErrEmptyModelSpec      = errors.New("aiquorum: empty model spec hash")
	ErrEmptyPromptHash     = errors.New("aiquorum: empty prompt hash")
	ErrStringTooLong       = errors.New("aiquorum: model spec string too long")
	ErrStakeBelowMin       = errors.New("aiquorum: stake below MinStake")
	ErrOperatorExists      = errors.New("aiquorum: operator already registered")
	ErrOperatorUnknown     = errors.New("aiquorum: operator not registered")
	ErrOperatorUnbonding   = errors.New("aiquorum: operator is unbonding")
	ErrCooldownActive      = errors.New("aiquorum: unbond cooldown not elapsed")
	ErrInsufficientFunds   = errors.New("aiquorum: insufficient balance")
	ErrEscrowUnderflow     = errors.New("aiquorum: escrow underflow (invariant broken)")
	ErrStakeOverflow       = errors.New("aiquorum: stake overflow")
	ErrCreditOverflow      = errors.New("aiquorum: credit overflow")
	ErrRewardOverflow      = errors.New("aiquorum: reward escrow overflow")
	ErrNoCredit            = errors.New("aiquorum: no credit to withdraw")
	ErrBadN                = errors.New("aiquorum: N out of range [minN, maxN]")
	ErrBadThreshold        = errors.New("aiquorum: threshold must satisfy floor(N/2)+1 <= threshold <= N")
	ErrNotEnoughEligible   = errors.New("aiquorum: fewer eligible operators than N")
	ErrEligibleBelowMargin = errors.New("aiquorum: eligible operator set below N + required margin (RED-A anti-grind)")
	ErrFeeOverflow         = errors.New("aiquorum: request fee overflow")
	ErrJobUnknown          = errors.New("aiquorum: job not found")
	ErrJobNotCommitting    = errors.New("aiquorum: job not in committing state")
	ErrJobAlreadySettled   = errors.New("aiquorum: job already settled")
	ErrNotSelected         = errors.New("aiquorum: operator not selected for job")
	ErrCommitClosed        = errors.New("aiquorum: commit window closed")
	ErrAlreadyCommitted    = errors.New("aiquorum: operator already committed")
	ErrNotCommitted        = errors.New("aiquorum: operator did not commit")
	ErrRevealNotOpen       = errors.New("aiquorum: reveal window not open")
	ErrRevealClosed        = errors.New("aiquorum: reveal window closed")
	ErrAlreadyRevealed     = errors.New("aiquorum: operator already revealed")
	ErrCommitMismatch      = errors.New("aiquorum: reveal does not match commit")
	ErrEmptyCommit         = errors.New("aiquorum: empty commit hash")
	ErrEmptyOutputHash     = errors.New("aiquorum: empty output hash")
	ErrSettleTooEarly      = errors.New("aiquorum: reveal window not closed")
)

// StateDB is the minimal slot-level state interface. Satisfied by the
// contract.StateDB the precompile receives, adapted in contract.go. Custody
// (balances) is a separate Ledger interface so accounting stays testable in
// isolation — mirrors aimarket's split.
type StateDB interface {
	GetState(common.Address, common.Hash) common.Hash
	SetState(common.Address, common.Hash, common.Hash) common.Hash
}

// Ledger is the native-value custody interface. It owns a single escrow account
// (ContractAddress); Pull moves funds in, Pay moves funds out. Both are atomic
// and fail-closed. Identical shape to aimarket's Ledger but bound to THIS
// precompile's escrow address, so the two never alias.
type Ledger interface {
	GetBalance(common.Address) *uint256.Int
	Pull(from common.Address, amount *uint256.Int) error
	Pay(to common.Address, amount *uint256.Int) error
}

// ---------------------------------------------------------------------------
// Slot derivation (keccak of a namespace tuple — same scheme as aimarket)
// ---------------------------------------------------------------------------

func slotAddr(ns []byte, a common.Address) common.Hash {
	return common.BytesToHash(crypto.Keccak256(ns, a.Bytes()))
}

func slotHash(ns []byte, h common.Hash) common.Hash {
	return common.BytesToHash(crypto.Keccak256(ns, h.Bytes()))
}

func slotHashAddr(ns []byte, h common.Hash, a common.Address) common.Hash {
	return common.BytesToHash(crypto.Keccak256(ns, h.Bytes(), a.Bytes()))
}

func slotHashIdx(ns []byte, h common.Hash, idx uint32) common.Hash {
	var ib [4]byte
	binary.BigEndian.PutUint32(ib[:], idx)
	return common.BytesToHash(crypto.Keccak256(ns, h.Bytes(), ib[:]))
}

// ---------------------------------------------------------------------------
// Shared wire-spec hashes (byte-identical to the off-chain prover)
// ---------------------------------------------------------------------------

// ModelSpec is the off-chain inference specification. Only its keccak digest is
// ever stored on-chain; the preimage is reproduced by the prover.
type ModelSpec struct {
	ModelID            string
	ModelHash          common.Hash
	TokenizerHash      common.Hash
	RuntimeVersion     string
	SamplingHash       common.Hash
	PromptTemplateHash common.Hash
	EmbeddingModelHash common.Hash
}

// ComputeModelSpecHash implements the SHARED WIRE SPEC exactly:
//
//	keccak256( u32be(len(model_id))||model_id || model_hash || tokenizer_hash ||
//	           u32be(len(runtime_version))||runtime_version ||
//	           sampling_hash || prompt_template_hash || embedding_model_hash )
func ComputeModelSpecHash(s ModelSpec) common.Hash {
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

// ComputeCommit implements the SHARED WIRE SPEC exactly:
//
//	keccak256( job_id(32) || model_spec_hash(32) || prompt_hash(32) ||
//	           output_hash(32) || embedding_hash(32) || operator(20) || nonce(32) )
//
// Fixed-width fields in this precise order. The operator address is bound in,
// which is what makes a peer unable to copy a commit.
func ComputeCommit(jobID, modelSpecHash, promptHash, outputHash, embeddingHash common.Hash, operator common.Address, nonce common.Hash) common.Hash {
	buf := make([]byte, 0, 32*5+20+32)
	buf = append(buf, jobID.Bytes()...)
	buf = append(buf, modelSpecHash.Bytes()...)
	buf = append(buf, promptHash.Bytes()...)
	buf = append(buf, outputHash.Bytes()...)
	buf = append(buf, embeddingHash.Bytes()...)
	buf = append(buf, operator.Bytes()...)
	buf = append(buf, nonce.Bytes()...)
	return common.BytesToHash(crypto.Keccak256(buf))
}

// computeJobID derives the unique, reproducible job id (and selection beacon
// anchor) — see the package doc "deterministic operator selection".
func computeJobID(requester common.Address, nonce common.Hash, modelSpecHash, promptHash common.Hash, requestBlock uint64, n, threshold uint32) common.Hash {
	var bb [8]byte
	binary.BigEndian.PutUint64(bb[:], requestBlock)
	var nb, tb [4]byte
	binary.BigEndian.PutUint32(nb[:], n)
	binary.BigEndian.PutUint32(tb[:], threshold)
	return common.BytesToHash(crypto.Keccak256(
		nsJob,
		requester.Bytes(),
		nonce.Bytes(),
		modelSpecHash.Bytes(),
		promptHash.Bytes(),
		bb[:],
		nb[:],
		tb[:],
	))
}

// ---------------------------------------------------------------------------
// Operator registry record packing: [ flags:1 | _:31 ] — stake lives in its own
// uint256 slot so stake math is full-width and never shares a word with flags.
// ---------------------------------------------------------------------------

type operatorRecord struct {
	Exists        bool
	Unbonding     bool
	ModelSpecHash common.Hash // the single ModelSpec this operator advertises
	EndpointHash  common.Hash // off-chain endpoint / pubkey commitment
	UnbondBlock   uint64      // block at which deregistration was requested
}

// Operator registry layout:
//
//	slotAddr(nsOperator, op)            -> packed [flags:1 | _:23 | unbondBlock:8]
//	slotAddr(nsOperator, op) ^ "spec"   -> modelSpecHash       (kept in a sibling slot)
//	slotAddr(nsOperator, op) ^ "endp"   -> endpointHash
//	slotAddr(nsStake-ish)               -> bonded stake (uint256)
//
// To keep the keyspace simple we derive sibling slots by hashing the record key
// with a discriminator, so each scalar gets a clean 32-byte word.
func opMetaSlot(op common.Address) common.Hash { return slotAddr(nsOperator, op) }
func opSpecSlot(op common.Address) common.Hash {
	return common.BytesToHash(crypto.Keccak256(nsOperator, op.Bytes(), []byte("spec")))
}
func opEndpSlot(op common.Address) common.Hash {
	return common.BytesToHash(crypto.Keccak256(nsOperator, op.Bytes(), []byte("endp")))
}
func opStakeSlot(op common.Address) common.Hash {
	return common.BytesToHash(crypto.Keccak256(nsOperator, op.Bytes(), []byte("stake")))
}

func packOpMeta(r operatorRecord) common.Hash {
	var w [32]byte
	if r.Exists {
		w[0] |= opExistsFlag
	}
	if r.Unbonding {
		w[0] |= opUnbondingFlag
	}
	binary.BigEndian.PutUint64(w[24:32], r.UnbondBlock)
	return common.BytesToHash(w[:])
}

func unpackOpMeta(h common.Hash) operatorRecord {
	b := h.Bytes()
	return operatorRecord{
		Exists:      b[0]&opExistsFlag != 0,
		Unbonding:   b[0]&opUnbondingFlag != 0,
		UnbondBlock: binary.BigEndian.Uint64(b[24:32]),
	}
}

func readOperator(db StateDB, op common.Address) operatorRecord {
	r := unpackOpMeta(db.GetState(ContractAddress, opMetaSlot(op)))
	if !r.Exists {
		return r
	}
	r.ModelSpecHash = db.GetState(ContractAddress, opSpecSlot(op))
	r.EndpointHash = db.GetState(ContractAddress, opEndpSlot(op))
	return r
}

func writeOperatorMeta(db StateDB, op common.Address, r operatorRecord) {
	db.SetState(ContractAddress, opMetaSlot(op), packOpMeta(r))
}

func readStake(db StateDB, op common.Address) *uint256.Int {
	return new(uint256.Int).SetBytes(db.GetState(ContractAddress, opStakeSlot(op)).Bytes())
}

func writeStake(db StateDB, op common.Address, v *uint256.Int) {
	db.SetState(ContractAddress, opStakeSlot(op), h32(v))
}

// ---------------------------------------------------------------------------
// Per-ModelSpec eligible-operator array (enumerable so selection is reproducible)
// ---------------------------------------------------------------------------

func modelCount(db StateDB, spec common.Hash) uint32 {
	return uint32(new(uint256.Int).SetBytes(db.GetState(ContractAddress, slotHash(nsModelIndex, spec)).Bytes()).Uint64())
}

func modelMember(db StateDB, spec common.Hash, idx uint32) common.Address {
	return common.BytesToAddress(db.GetState(ContractAddress, slotHashIdx(nsModelMember, spec, idx)).Bytes())
}

// appendModelMember adds op to spec's operator array if not already present.
// Idempotent: the per-(spec,op) seen flag prevents duplicate enumeration entries
// across re-registration.
func appendModelMember(db StateDB, spec common.Hash, op common.Address) {
	seenSlot := slotHashAddr(nsModelSeen, spec, op)
	if isSet(db.GetState(ContractAddress, seenSlot)) {
		return
	}
	n := modelCount(db, spec)
	db.SetState(ContractAddress, slotHashIdx(nsModelMember, spec, n), common.BytesToHash(common.LeftPadBytes(op.Bytes(), 32)))
	db.SetState(ContractAddress, slotHash(nsModelIndex, spec), h32(uint256.NewInt(uint64(n)+1)))
	db.SetState(ContractAddress, seenSlot, oneHash())
}

// ---------------------------------------------------------------------------
// Job record packing: status + N + threshold + requester + deadlines.
// Split across two words so every field is unambiguous.
//   word A: [ status:1 | N:4 | threshold:4 | requester:20 | _:3 ]
//   word B: [ commitDeadline:8 | revealDeadline:8 | requestBlock:8 | _:8 ]
// modelSpecHash + promptHash live in sibling slots (full 32-byte each).
// ---------------------------------------------------------------------------

type jobRecord struct {
	Status         uint8
	N              uint32
	Threshold      uint32
	Requester      common.Address
	CommitDeadline uint64
	RevealDeadline uint64
	RequestBlock   uint64
	ModelSpecHash  common.Hash
	PromptHash     common.Hash
}

func jobMetaASlot(id common.Hash) common.Hash { return slotHash(nsJob, id) }
func jobMetaBSlot(id common.Hash) common.Hash {
	return common.BytesToHash(crypto.Keccak256(nsJob, id.Bytes(), []byte("B")))
}
func jobSpecSlot(id common.Hash) common.Hash {
	return common.BytesToHash(crypto.Keccak256(nsJob, id.Bytes(), []byte("spec")))
}
func jobPromptSlot(id common.Hash) common.Hash {
	return common.BytesToHash(crypto.Keccak256(nsJob, id.Bytes(), []byte("prompt")))
}

func packJobA(r jobRecord) common.Hash {
	var w [32]byte
	w[0] = r.Status
	binary.BigEndian.PutUint32(w[1:5], r.N)
	binary.BigEndian.PutUint32(w[5:9], r.Threshold)
	copy(w[9:29], r.Requester.Bytes())
	return common.BytesToHash(w[:])
}

func packJobB(r jobRecord) common.Hash {
	var w [32]byte
	binary.BigEndian.PutUint64(w[0:8], r.CommitDeadline)
	binary.BigEndian.PutUint64(w[8:16], r.RevealDeadline)
	binary.BigEndian.PutUint64(w[16:24], r.RequestBlock)
	return common.BytesToHash(w[:])
}

func writeJob(db StateDB, id common.Hash, r jobRecord) {
	db.SetState(ContractAddress, jobMetaASlot(id), packJobA(r))
	db.SetState(ContractAddress, jobMetaBSlot(id), packJobB(r))
	db.SetState(ContractAddress, jobSpecSlot(id), r.ModelSpecHash)
	db.SetState(ContractAddress, jobPromptSlot(id), r.PromptHash)
}

func readJob(db StateDB, id common.Hash) jobRecord {
	a := db.GetState(ContractAddress, jobMetaASlot(id)).Bytes()
	if a[0] == JobNone {
		// Distinguish "no job" by an all-zero A word (status byte zero AND no N).
		// A real job always has status>=1, so status==0 reliably means absent.
		return jobRecord{Status: JobNone}
	}
	b := db.GetState(ContractAddress, jobMetaBSlot(id)).Bytes()
	return jobRecord{
		Status:         a[0],
		N:              binary.BigEndian.Uint32(a[1:5]),
		Threshold:      binary.BigEndian.Uint32(a[5:9]),
		Requester:      common.BytesToAddress(a[9:29]),
		CommitDeadline: binary.BigEndian.Uint64(b[0:8]),
		RevealDeadline: binary.BigEndian.Uint64(b[8:16]),
		RequestBlock:   binary.BigEndian.Uint64(b[16:24]),
		ModelSpecHash:  db.GetState(ContractAddress, jobSpecSlot(id)),
		PromptHash:     db.GetState(ContractAddress, jobPromptSlot(id)),
	}
}

// ---------------------------------------------------------------------------
// Credit ledger (withdrawable rewards / slashed-stake bonuses)
// ---------------------------------------------------------------------------

func readCredit(db StateDB, a common.Address) *uint256.Int {
	return new(uint256.Int).SetBytes(db.GetState(ContractAddress, slotAddr(nsCredit, a)).Bytes())
}

func writeCredit(db StateDB, a common.Address, v *uint256.Int) {
	db.SetState(ContractAddress, slotAddr(nsCredit, a), h32(v))
}

// addCredit credits `amount` to `a`, checked for overflow. State is only written
// on success.
func addCredit(db StateDB, a common.Address, amount *uint256.Int) error {
	cur := readCredit(db, a)
	nv := new(uint256.Int)
	if _, overflow := nv.AddOverflow(cur, amount); overflow {
		return ErrCreditOverflow
	}
	writeCredit(db, a, nv)
	return nil
}

// ===========================================================================
// Core operations (pure, given StateDB / Ledger)
// ===========================================================================

// RegisterOperator bonds `stake` from `operator` and advertises a ModelSpec.
// The operator becomes eligible for selection iff stake >= MinStake. One active
// registration per operator (re-register requires deregister+cooldown+withdraw).
func RegisterOperator(db StateDB, lg Ledger, operator common.Address, stake *uint256.Int, modelSpecHash, endpointHash common.Hash) error {
	if modelSpecHash == (common.Hash{}) {
		return ErrEmptyModelSpec
	}
	if stake.Lt(MinStake) {
		return ErrStakeBelowMin
	}
	rec := readOperator(db, operator)
	if rec.Exists {
		return ErrOperatorExists
	}
	// Pull the stake into escrow FIRST (fails closed on insufficient balance —
	// no registry write happens if the operator cannot fund the bond).
	if err := lg.Pull(operator, stake); err != nil {
		return err
	}
	writeStake(db, operator, stake)
	db.SetState(ContractAddress, opSpecSlot(operator), modelSpecHash)
	db.SetState(ContractAddress, opEndpSlot(operator), endpointHash)
	writeOperatorMeta(db, operator, operatorRecord{Exists: true})
	appendModelMember(db, modelSpecHash, operator)
	return nil
}

// DeregisterOperator marks the operator unbonding at `block`. Stake is not
// returned here — WithdrawStake returns it after the cooldown. Marking
// unbonding immediately makes the operator ineligible for NEW jobs.
func DeregisterOperator(db StateDB, operator common.Address, block uint64) error {
	rec := readOperator(db, operator)
	if !rec.Exists {
		return ErrOperatorUnknown
	}
	if rec.Unbonding {
		return ErrOperatorUnbonding
	}
	rec.Unbonding = true
	rec.UnbondBlock = block
	writeOperatorMeta(db, operator, rec)
	return nil
}

// WithdrawStake returns bonded stake to a fully-unbonded operator after the
// cooldown. Clears the registry record. Idempotent-safe: a second call finds no
// record. Any reward credit is withdrawn separately via WithdrawRewards.
func WithdrawStake(db StateDB, lg Ledger, operator common.Address, block uint64) (*uint256.Int, error) {
	rec := readOperator(db, operator)
	if !rec.Exists {
		return nil, ErrOperatorUnknown
	}
	if !rec.Unbonding {
		return nil, ErrOperatorUnbonding // must DeregisterOperator first
	}
	if block < rec.UnbondBlock+UnbondCooldownBlocks {
		return nil, ErrCooldownActive
	}
	stake := readStake(db, operator)
	// Pay out first; only clear state if payment succeeds.
	if !stake.IsZero() {
		if err := lg.Pay(operator, stake); err != nil {
			return nil, err
		}
	}
	writeStake(db, operator, uint256.NewInt(0))
	writeOperatorMeta(db, operator, operatorRecord{Exists: false})
	// Note: the operator remains in the per-ModelSpec enumeration array (its
	// stake is now 0, so selection skips it as ineligible). This keeps the array
	// append-only and the beacon reproducible; pruning would shift indices.
	return stake, nil
}

// RequestInference opens a job: validates params, enforces the RED-A eligible-set
// margin, escrows N*rewardPerOperator (refundable) AND burns N*RequestFeePerOperator
// (non-refundable) from the requester, selects N eligible operators by the
// deterministic beacon, and records the job in Committing state. Returns the job id.
//
// # RED-A residual-risk derivation (requester-side selection grinding)
//
// Let E = eligible pool size (enforced >= N + requiredMargin(N)), c = operators
// the requester controls (each bonded >= MinStake), N = draw size, T = threshold.
// Forging the canonical hash needs >= T of the selected N to be cartel operators.
//
//   - NECESSARY CONDITION: c >= T. The selected set is drawn from the eligible
//     pool, which contains exactly c cartel operators; you cannot select more
//     cartel members than exist. If c < T no job_id — however ground out — can
//     reach a cartel quorum. This is an ABSOLUTE bound: forgery is impossible
//     below a bonded stake of T * MinStake, at any compute budget.
//   - WHEN c >= T: a single offline keccak grind over promptHash finds a job_id
//     whose draw lands >= T cartel members with per-attempt probability
//     P = P(Hypergeometric(E, c, N) >= T); the attacker then submits ONCE, paying
//     N*RequestFeePerOperator. The fee does not multiply by offline tries — it is
//     the price of the one on-chain submission. So against a c >= T cartel the
//     economic deterrent is the stake (T*MinStake at risk of slashing/illiquidity),
//     not the fee.
//   - The FEE bites MULTI-JOB strategies: if the attack needs k distinct on-chain
//     jobs (promptHash semantically constrained so it cannot be freely ground;
//     censorship by resubmission; varying N/T/timing), the on-chain cost is
//     k * N * RequestFeePerOperator — linear in both the per-request size and the
//     number of attempts.
//   - The MARGIN keeps E strictly > N so the pool is never degenerate; it does not
//     shrink c, but it guarantees the draw samples a strictly larger independent
//     set, which is the precondition for (i) a well-distributed pool to dilute a
//     fixed cartel and (ii) the hypergeometric P above to be < 1.
//
// Honest summary: the margin makes the pool non-degenerate, MinStake sets the
// absolute T*MinStake forgery floor, and the fee prices repeated on-chain
// grinding. None of these — and nothing available on a chain without
// in-consensus randomness — makes a c >= T cartel's single-shot grind impossible;
// they make it expensive and bounded.
func RequestInference(db StateDB, lg Ledger, requester common.Address, modelSpecHash, promptHash common.Hash, n, threshold uint32, rewardPerOperator *uint256.Int, block uint64) (common.Hash, error) {
	if modelSpecHash == (common.Hash{}) {
		return common.Hash{}, ErrEmptyModelSpec
	}
	if promptHash == (common.Hash{}) {
		return common.Hash{}, ErrEmptyPromptHash
	}
	if n < minN || n > maxN {
		return common.Hash{}, ErrBadN
	}
	// Threshold rule: strict majority floor(N/2)+1 <= threshold <= N. Rejects
	// weak quora (e.g. for N=5 the minimum is 3).
	minThreshold := n/2 + 1
	if threshold < minThreshold || threshold > n {
		return common.Hash{}, ErrBadThreshold
	}

	// Total escrow = N * rewardPerOperator (checked).
	totalEscrow := new(uint256.Int)
	if _, overflow := totalEscrow.MulOverflow(rewardPerOperator, uint256.NewInt(uint64(n))); overflow {
		return common.Hash{}, ErrRewardOverflow
	}
	// Non-refundable request fee = N * RequestFeePerOperator (checked). Burned to
	// BurnAddress; never refunded — see the RED-A mitigation note below.
	totalFee := new(uint256.Int)
	if _, overflow := totalFee.MulOverflow(RequestFeePerOperator, uint256.NewInt(uint64(n))); overflow {
		return common.Hash{}, ErrFeeOverflow
	}

	// RED-A ELIGIBLE-SET MARGIN: build the eligible universe and require it to be
	// strictly larger than the draw by requiredMargin(N). Enforced BEFORE any
	// money moves, so a too-small pool leaves balances untouched (fail-closed).
	// This is the set-size half of the RED-A mitigation: a requester cannot open a
	// job against a pool that gives the selection no sampling headroom over a
	// genuinely independent set.
	eligible := eligibleSet(db, modelSpecHash)
	if uint32(len(eligible)) < n {
		return common.Hash{}, ErrNotEnoughEligible
	}
	if uint32(len(eligible)) < n+requiredMargin(n) {
		return common.Hash{}, ErrEligibleBelowMargin
	}

	// Draw N from the SAME eligible set we just margin-checked (one scan, shared),
	// deterministically, BEFORE moving money so a selection failure leaves balances
	// untouched.
	nonceSlot := slotAddr(nsReqNonce, requester)
	nonce := db.GetState(ContractAddress, nonceSlot)
	jobID := computeJobID(requester, nonce, modelSpecHash, promptHash, block, n, threshold)

	selected, err := drawFromEligible(eligible, jobID, n)
	if err != nil {
		return common.Hash{}, err
	}

	// Combined affordability check (escrow + fee) BEFORE any move, so the two
	// money operations are all-or-nothing in the pure core (no partial state if
	// the requester can fund the escrow but not the fee). On-chain a revert would
	// also journal-roll-back a partial move, but checking up front keeps the core
	// honestly fail-closed in isolation.
	needed := new(uint256.Int)
	if _, overflow := needed.AddOverflow(totalEscrow, totalFee); overflow {
		return common.Hash{}, ErrRewardOverflow
	}
	if lg.GetBalance(requester).Lt(needed) {
		return common.Hash{}, ErrInsufficientFunds
	}

	// Escrow the reward (refundable). Fails closed.
	if err := lg.Pull(requester, totalEscrow); err != nil {
		return common.Hash{}, err
	}

	// Burn the non-refundable fee: requester -> ContractAddress -> BurnAddress,
	// reusing the existing Ledger primitives (no new custody surface). The fee
	// nets to zero on ContractAddress, so the escrow accounting invariant
	// (balance(CA) == stake + open-escrow + credit) is unaffected; the wei is
	// permanently parked at BurnAddress. The combined check above guarantees both
	// Pulls succeed, so the job is never created in a fee-unpaid state.
	if !totalFee.IsZero() {
		if err := lg.Pull(requester, totalFee); err != nil {
			return common.Hash{}, err
		}
		if err := lg.Pay(BurnAddress, totalFee); err != nil {
			return common.Hash{}, err
		}
	}

	// Persist the job + escrow + reward-per-operator.
	job := jobRecord{
		Status:         JobCommitting,
		N:              n,
		Threshold:      threshold,
		Requester:      requester,
		CommitDeadline: block + CommitBlocks,
		RevealDeadline: block + CommitBlocks + RevealBlocks,
		RequestBlock:   block,
		ModelSpecHash:  modelSpecHash,
		PromptHash:     promptHash,
	}
	writeJob(db, jobID, job)
	db.SetState(ContractAddress, slotHash(nsJobReward, jobID), h32(rewardPerOperator))
	db.SetState(ContractAddress, slotHash(nsJobEscrow, jobID), h32(totalEscrow))

	// Record the selected set: a membership flag (for O(1) "are you selected")
	// AND an indexed list (for reproducibility / enumeration). Index 0..N-1.
	for i, op := range selected {
		db.SetState(ContractAddress, slotHashAddr(nsSelected, jobID, op), oneHash())
		db.SetState(ContractAddress, slotHashIdx(nsSelList, jobID, uint32(i)), common.BytesToHash(common.LeftPadBytes(op.Bytes(), 32)))
	}

	// Bump the requester nonce so the next request is unique.
	bumpNonce(db, nonceSlot, nonce)
	return jobID, nil
}

// requiredMargin returns the eligible-set headroom required over N (RED-A). The
// pool must satisfy E >= N + requiredMargin(N). It is the larger of an absolute
// floor and a fraction (bps) of N, so both tiny and large draws keep meaningful
// sampling headroom. Pure function of N + the two policy constants — every
// validator computes the identical value.
func requiredMargin(n uint32) uint32 {
	frac := uint32((uint64(n) * uint64(RequestMarginBps)) / 10_000)
	if frac > RequestMarginFloor {
		return frac
	}
	return RequestMarginFloor
}

// eligibleSet builds the eligible working set for a ModelSpec in registry-
// insertion order: operators that exist, are not unbonding, and hold stake >=
// MinStake. It is the SINGLE source of "who is eligible" — both the margin check
// (RequestInference) and the beacon draw (selectOperators) consume it, so the two
// can never disagree about the eligible universe. Eligibility is recomputed from
// live state, so a slashed or deregistering operator is excluded even though it
// remains in the append-only enumeration array.
func eligibleSet(db StateDB, modelSpecHash common.Hash) []common.Address {
	total := modelCount(db, modelSpecHash)
	eligible := make([]common.Address, 0, total)
	for i := range total {
		op := modelMember(db, modelSpecHash, i)
		rec := readOperator(db, op)
		if !rec.Exists || rec.Unbonding {
			continue
		}
		if readStake(db, op).Lt(MinStake) {
			continue
		}
		eligible = append(eligible, op)
	}
	return eligible
}

// drawFromEligible is the PURE beacon draw: a Fisher–Yates partial shuffle of the
// given eligible set anchored in the job_id, returning the first N. It does no
// state access (the data is the input) so it is the one place the selection
// MECHANISM lives, independent of how the eligible set was gathered. It mutates
// the passed slice in place (callers pass a fresh slice). Reproducible by anyone
// who can rebuild the same eligible set in insertion order — see package doc.
func drawFromEligible(eligible []common.Address, jobID common.Hash, n uint32) ([]common.Address, error) {
	if uint32(len(eligible)) < n {
		return nil, ErrNotEnoughEligible
	}
	for i := range n {
		span := uint64(len(eligible)) - uint64(i) // remaining choices
		draw := new(uint256.Int).SetBytes(crypto.Keccak256(jobID.Bytes(), u32be(i)))
		j := uint32(i) + uint32(new(uint256.Int).Mod(draw, uint256.NewInt(span)).Uint64())
		eligible[i], eligible[j] = eligible[j], eligible[i]
	}
	return eligible[:n], nil
}

// selectOperators is the convenience composition of the one scan (eligibleSet)
// and the pure draw (drawFromEligible): it draws N distinct eligible operators
// from the per-ModelSpec array using the job_id beacon. It does NOT enforce the
// RED-A margin (that is a RequestInference policy gate). RequestInference does the
// scan ONCE itself (to share the eligible set with the margin check) and calls
// drawFromEligible directly; this wrapper exists for standalone callers and the
// reproducibility tests.
func selectOperators(db StateDB, jobID, modelSpecHash common.Hash, n uint32) ([]common.Address, error) {
	return drawFromEligible(eligibleSet(db, modelSpecHash), jobID, n)
}

// IsSelected reports whether op was selected for job (O(1) flag read).
func IsSelected(db StateDB, jobID common.Hash, op common.Address) bool {
	return isSet(db.GetState(ContractAddress, slotHashAddr(nsSelected, jobID, op)))
}

// SelectedAt returns the operator at selection index i (for reproducibility
// checks). idx must be < job.N.
func SelectedAt(db StateDB, jobID common.Hash, idx uint32) common.Address {
	return common.BytesToAddress(db.GetState(ContractAddress, slotHashIdx(nsSelList, jobID, idx)).Bytes())
}

// CommitResponse records a selected operator's commit hash within the commit
// window. One commit per operator per job.
func CommitResponse(db StateDB, jobID common.Hash, operator common.Address, commit common.Hash, block uint64) error {
	if commit == (common.Hash{}) {
		return ErrEmptyCommit
	}
	job := readJob(db, jobID)
	if job.Status == JobNone {
		return ErrJobUnknown
	}
	if job.Status != JobCommitting {
		return ErrJobNotCommitting
	}
	if block > job.CommitDeadline {
		return ErrCommitClosed
	}
	if !IsSelected(db, jobID, operator) {
		return ErrNotSelected
	}
	commitSlot := slotHashAddr(nsCommit, jobID, operator)
	if isSet(db.GetState(ContractAddress, commitSlot)) {
		return ErrAlreadyCommitted
	}
	db.SetState(ContractAddress, commitSlot, commit)
	return nil
}

// RevealResponse records a selected operator's revealed (output_hash,
// embedding_hash, nonce) within the reveal window. It recomputes the commit and
// requires it to equal the stored commit (binding). One reveal per operator.
//
// The reveal window opens strictly AFTER the commit window closes
// (commitDeadline < block <= revealDeadline) so no operator can observe a peer's
// revealed output before its own commit is sealed.
func RevealResponse(db StateDB, jobID common.Hash, operator common.Address, outputHash, embeddingHash, nonce common.Hash, block uint64) error {
	if outputHash == (common.Hash{}) {
		return ErrEmptyOutputHash
	}
	job := readJob(db, jobID)
	if job.Status == JobNone {
		return ErrJobUnknown
	}
	if job.Status != JobCommitting {
		return ErrJobNotCommitting
	}
	if block <= job.CommitDeadline {
		return ErrRevealNotOpen
	}
	if block > job.RevealDeadline {
		return ErrRevealClosed
	}
	commitSlot := slotHashAddr(nsCommit, jobID, operator)
	stored := db.GetState(ContractAddress, commitSlot)
	if !isSet(stored) {
		return ErrNotCommitted
	}
	revealFlagSlot := slotHashAddr(nsRevealFlag, jobID, operator)
	if isSet(db.GetState(ContractAddress, revealFlagSlot)) {
		return ErrAlreadyRevealed
	}
	// Recompute the commit from the revealed preimage; must match exactly.
	recomputed := ComputeCommit(jobID, job.ModelSpecHash, job.PromptHash, outputHash, embeddingHash, operator, nonce)
	if recomputed != stored {
		return ErrCommitMismatch
	}
	// Record the reveal: the output_hash, the revealed flag, and append the
	// operator to the per-job revealer array (for tally at Settle).
	db.SetState(ContractAddress, slotHashAddr(nsReveal, jobID, operator), outputHash)
	db.SetState(ContractAddress, revealFlagSlot, oneHash())
	cnt := revealCount(db, jobID)
	db.SetState(ContractAddress, slotHashIdx(nsRevealList, jobID, cnt), common.BytesToHash(common.LeftPadBytes(operator.Bytes(), 32)))
	db.SetState(ContractAddress, slotHash(nsRevealCount, jobID), h32(uint256.NewInt(uint64(cnt)+1)))
	return nil
}

func revealCount(db StateDB, jobID common.Hash) uint32 {
	return uint32(new(uint256.Int).SetBytes(db.GetState(ContractAddress, slotHash(nsRevealCount, jobID)).Bytes()).Uint64())
}

// SettleResult is the outcome of Settle, returned for the ABI layer + tests.
type SettleResult struct {
	Status        uint8        // JobSettled or JobFailed
	CanonicalHash common.Hash  // winning output_hash (zero if Failed)
	WinnerCount   uint32       // size of the winning group (0 if Failed)
	Paid          *uint256.Int // total wei paid out as rewards (0 if Failed)
	Slashed       *uint256.Int // total wei slashed from non-revealers
}

// Settle finalizes a job after its reveal window closes. It tallies revealers by
// output_hash, applies the quorum rule, pays winners, slashes non-revealers, and
// flips the job to Settled or Failed. Idempotent: a settled marker rejects
// replay.
func Settle(db StateDB, lg Ledger, jobID common.Hash, block uint64) (SettleResult, error) {
	settledSlot := slotHash(nsSettled, jobID)
	if isSet(db.GetState(ContractAddress, settledSlot)) {
		return SettleResult{}, ErrJobAlreadySettled
	}
	job := readJob(db, jobID)
	if job.Status == JobNone {
		return SettleResult{}, ErrJobUnknown
	}
	if job.Status != JobCommitting {
		return SettleResult{}, ErrJobAlreadySettled
	}
	if block <= job.RevealDeadline {
		return SettleResult{}, ErrSettleTooEarly
	}

	reward := new(uint256.Int).SetBytes(db.GetState(ContractAddress, slotHash(nsJobReward, jobID)).Bytes())
	escrow := new(uint256.Int).SetBytes(db.GetState(ContractAddress, slotHash(nsJobEscrow, jobID)).Bytes())

	// Tally revealers by output_hash. revealers + their hashes are read from the
	// per-job revealer array (bounded by N).
	rc := revealCount(db, jobID)
	revealers := make([]common.Address, rc)
	hashes := make([]common.Hash, rc)
	for i := range rc {
		op := common.BytesToAddress(db.GetState(ContractAddress, slotHashIdx(nsRevealList, jobID, i)).Bytes())
		revealers[i] = op
		hashes[i] = db.GetState(ContractAddress, slotHashAddr(nsReveal, jobID, op))
	}

	// Find the largest group (plurality) and its size.
	canonical, winnerSize := plurality(hashes)

	res := SettleResult{Paid: uint256.NewInt(0), Slashed: uint256.NewInt(0)}

	if winnerSize >= job.Threshold {
		// QUORUM REACHED.
		res.Status = JobSettled
		res.CanonicalHash = canonical
		res.WinnerCount = winnerSize

		// Slash withholders (and dissenters if the knob is on); collect the
		// slashed pool to share among winners.
		slashedPool, err := slashStake(db, jobID, job, canonical, true)
		if err != nil {
			return SettleResult{}, err
		}
		res.Slashed = slashedPool

		// Winners = revealers whose hash == canonical.
		winners := make([]common.Address, 0, winnerSize)
		for i := range rc {
			if hashes[i] == canonical {
				winners = append(winners, revealers[i])
			}
		}
		nWin := uint64(len(winners))

		// Each winner is paid rewardPerOperator from job escrow plus an equal
		// share of the slashed pool; the slashed-pool remainder (from integer
		// division) is refunded to the requester.
		share := new(uint256.Int)
		remainder := new(uint256.Int).Set(slashedPool)
		if !slashedPool.IsZero() && nWin > 0 {
			share.Div(slashedPool, uint256.NewInt(nWin))
			distributed := new(uint256.Int).Mul(share, uint256.NewInt(nWin))
			remainder.Sub(slashedPool, distributed)
		}
		for _, w := range winners {
			if escrow.Lt(reward) {
				return SettleResult{}, ErrEscrowUnderflow
			}
			escrow.Sub(escrow, reward)
			payout := new(uint256.Int).Add(reward, share)
			if err := addCredit(db, w, payout); err != nil {
				return SettleResult{}, err
			}
			res.Paid.Add(res.Paid, payout)
		}

		// Refund unspent reward escrow — (N-winnerSize)*reward, since winnerSize
		// of the N escrowed rewards were paid — plus the slashed-pool remainder.
		refund := new(uint256.Int).Add(escrow, remainder)
		if !refund.IsZero() {
			if err := addCredit(db, job.Requester, refund); err != nil {
				return SettleResult{}, err
			}
		}
	} else {
		// NO QUORUM → job Failed. Refund the requester's full remaining escrow,
		// slash non-revealers, and credit the slashed pool to the requester as
		// compensation for the failed job.
		res.Status = JobFailed
		// No quorum → no canonical hash → only withholders are slashed.
		slashedPool, err := slashStake(db, jobID, job, common.Hash{}, false)
		if err != nil {
			return SettleResult{}, err
		}
		res.Slashed = slashedPool
		refund := new(uint256.Int).Add(escrow, slashedPool)
		if !refund.IsZero() {
			if err := addCredit(db, job.Requester, refund); err != nil {
				return SettleResult{}, err
			}
		}
	}

	// Flip job state, record the canonical result, and burn the replay marker —
	// all in the same frame (the EVM journals them together).
	job.Status = res.Status
	db.SetState(ContractAddress, jobMetaASlot(jobID), packJobA(job))
	db.SetState(ContractAddress, slotHash(nsJobEscrow, jobID), h32(uint256.NewInt(0)))
	if res.Status == JobSettled {
		db.SetState(ContractAddress, slotHash(nsCanonical, jobID), canonical)
	}
	db.SetState(ContractAddress, settledSlot, oneHash())
	return res, nil
}

// slashStake slashes the culpable selected operators of a job. The slashed wei
// stays in the escrow account (it was bonded there at register time, so no
// balance move is needed) and is accumulated into the returned pool for
// redistribution. Bonded stake is reduced by the slash amount floored at the
// operator's remaining stake (never negative).
//
//	canonical is the winning output_hash (zero when no quorum). A selected
//	operator is slashed when:
//	  - it committed but never revealed (unambiguous withholding) — always; or
//	  - SlashDissenters is set AND it revealed a hash != canonical (dissent) —
//	    only on the quorum path where a canonical hash exists.
func slashStake(db StateDB, jobID common.Hash, job jobRecord, canonical common.Hash, haveCanonical bool) (*uint256.Int, error) {
	pool := uint256.NewInt(0)
	for i := uint32(0); i < job.N; i++ {
		op := SelectedAt(db, jobID, i)
		if op == (common.Address{}) {
			continue
		}
		committed := isSet(db.GetState(ContractAddress, slotHashAddr(nsCommit, jobID, op)))
		revealed := isSet(db.GetState(ContractAddress, slotHashAddr(nsRevealFlag, jobID, op)))

		slashThis := committed && !revealed // withholding: always slashed
		if !slashThis && SlashDissenters && revealed && haveCanonical {
			revealedHash := db.GetState(ContractAddress, slotHashAddr(nsReveal, jobID, op))
			slashThis = revealedHash != canonical // dissent: slashed only under the knob
		}
		if !slashThis {
			continue
		}

		stake := readStake(db, op)
		slash := new(uint256.Int).Set(SlashPerOperator)
		if stake.Lt(slash) {
			slash.Set(stake) // floor at the operator's remaining stake
		}
		if slash.IsZero() {
			continue
		}
		stake.Sub(stake, slash)
		writeStake(db, op, stake)
		pool.Add(pool, slash)
	}
	return pool, nil
}

// plurality returns the most-common hash and its count. Deterministic tie-break:
// among hashes tied for the max count, the lexicographically smallest hash wins,
// so every validator computes the identical canonical hash. (A tie cannot reach
// a strict-majority threshold anyway, but the tie-break keeps the function
// total and deterministic.)
func plurality(hashes []common.Hash) (common.Hash, uint32) {
	counts := make(map[common.Hash]uint32, len(hashes))
	for _, h := range hashes {
		counts[h]++
	}
	var best common.Hash
	var bestN uint32
	for h, c := range counts {
		if c > bestN || (c == bestN && bytesLess(h, best)) {
			best, bestN = h, c
		}
	}
	return best, bestN
}

func bytesLess(a, b common.Hash) bool {
	ab, bb := a.Bytes(), b.Bytes()
	for i := range ab {
		if ab[i] != bb[i] {
			return ab[i] < bb[i]
		}
	}
	return false
}

// WithdrawRewards pays the operator's entire accrued credit out of escrow and
// zeroes the ledger. Fails closed if nothing is owed; an escrow shortfall is a
// hard invariant breach.
func WithdrawRewards(db StateDB, lg Ledger, operator common.Address) (*uint256.Int, error) {
	credit := readCredit(db, operator)
	if credit.IsZero() {
		return nil, ErrNoCredit
	}
	if err := lg.Pay(operator, credit); err != nil {
		return nil, err
	}
	writeCredit(db, operator, uint256.NewInt(0))
	return credit, nil
}

// ---------------------------------------------------------------------------
// Read-only views
// ---------------------------------------------------------------------------

// GetOperator reads an operator's registry record.
func GetOperator(db StateDB, op common.Address) (exists, unbonding bool, stake *uint256.Int, modelSpecHash, endpointHash common.Hash) {
	rec := readOperator(db, op)
	return rec.Exists, rec.Unbonding, readStake(db, op), rec.ModelSpecHash, rec.EndpointHash
}

// GetCredit reads an operator's withdrawable credit.
func GetCredit(db StateDB, op common.Address) *uint256.Int { return readCredit(db, op) }

// GetJob reads a job's state.
func GetJob(db StateDB, jobID common.Hash) jobRecord { return readJob(db, jobID) }

// GetCanonicalResult reads a settled job's canonical output_hash (zero if not
// settled or no quorum).
func GetCanonicalResult(db StateDB, jobID common.Hash) common.Hash {
	return db.GetState(ContractAddress, slotHash(nsCanonical, jobID))
}

// ---------------------------------------------------------------------------
// small helpers
// ---------------------------------------------------------------------------

func u32be(v uint32) []byte {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], v)
	return b[:]
}

func bumpNonce(db StateDB, nonceSlot, nonce common.Hash) {
	n := new(uint256.Int).SetBytes(nonce.Bytes())
	n.AddUint64(n, 1)
	db.SetState(ContractAddress, nonceSlot, h32(n))
}

func isSet(h common.Hash) bool { return h != (common.Hash{}) }

func oneHash() common.Hash {
	var w [32]byte
	w[31] = 1
	return common.BytesToHash(w[:])
}

func h32(v *uint256.Int) common.Hash {
	b := v.Bytes32()
	return common.BytesToHash(b[:])
}
