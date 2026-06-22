// Copyright (C) 2026, Hanzo AI Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package aimarket implements the Hanzo decentralized inference marketplace
// precompile for the Hanzo C-Chain EVM (luxfi/evm).
//
// Node operators advertise priced model offerings on-chain; smart-contract
// callers request inference / embedding by model name; usage is metered per
// thousand tokens and the serving operator is credited. The actual inference
// is served off-chain via the Hanzo engine FFI (Rust precompiles 0x0201 /
// 0x0202); THIS precompile owns the on-chain accounting and settlement.
//
// # Address
//
// 0x0300000000000000000000000000000000000011 — AI range (0x0300-0x03FF),
// adjacent to the Lux compute job-board at 0x0300..10. The two are
// orthogonal: 0x0300..10 is a hash-attested job board (submit/claim/verify);
// this is a priced model registry with per-token metering + escrow + replay-
// safe settlement.
//
// # On-chain state layout
//
// All slots live under ContractAddress. Keys are keccak256 of a namespaced
// tuple so distinct records can never collide.
//
//	offering price/maxSize : keccak256("aimkt/off", operator(20), modelName)
//	                         -> packed [ price:uint128 | maxSizeTokens:uint32 | flags:uint8 ]
//	                            (a non-zero EXISTS flag distinguishes "price 0,
//	                             offered" from "never registered")
//	operator credit ledger : keccak256("aimkt/cred", operator(20))
//	                         -> accrued credit (uint256 wei)
//	request record         : keccak256("aimkt/req", recordId(32))
//	                         -> packed [ status:uint8 | operator(20) | tokens:uint32 ]
//	request cost           : keccak256("aimkt/req.cost", recordId(32))
//	                         -> cost charged at meter time (uint256 wei, escrowed)
//	caller request nonce   : keccak256("aimkt/nonce", caller(20))
//	                         -> monotonic nonce for unique recordIds
//	settled marker         : keccak256("aimkt/settled", recordId(32))
//	                         -> 1 once SettleInference consumes the record (replay guard)
//
// # Money custody
//
// Meter pulls cost from the caller's native balance into the precompile's
// escrow (SubBalance(caller) + AddBalance(precompile)) and records an equal
// credit in the operator ledger. Withdraw pays the ledger out of escrow
// (SubBalance(precompile) + AddBalance(operator)) and zeroes the ledger.
// Invariant: escrow_balance == sum(unwithdrawn operator credits). All money
// math is uint256, checked for overflow on credit and underflow on debit.
//
// Custody never uses a value-bearing CALL: funds move only via balance
// mutation on the precompile escrow account (which holds no code), so no
// recipient fallback executes — there is no reentrancy surface through Pull or
// Pay. (A future refactor to CALL-with-value would reintroduce one and must
// re-establish checks-effects-interactions ordering.)
//
// # Settlement model (IMPORTANT design decision)
//
// This implementation credits the operator at METER time (prepaid model):
// Meter / RequestInference move the caller's funds into escrow AND credit the
// operator's withdrawable ledger atomically. SettleInference is the
// attestation GATE — the operator proves delivery by signing
// keccak256(recordId, resultHash) — and flips the request to Settled exactly
// once (replay-guarded). Settlement does NOT credit a second time; crediting
// twice would be a critical double-spend.
//
// Tradeoff: prepaid favors the operator (it can Withdraw before attesting).
// The caller-protective alternative is escrow-until-settle: hold the cost in a
// PENDING bucket at Meter, move it to the operator's withdrawable ledger ONLY
// on a valid SettleInference, and refund the caller after a timeout if no
// attestation arrives. That variant is a strict superset of this one (add a
// pending ledger + a block-height timeout + a Refund op) and is the
// recommended production posture for untrusted operators. See the package
// report for the full in-consensus vs off-chain-verify analysis.
package aimarket

import (
	"encoding/binary"
	"errors"

	"github.com/holiman/uint256"
	"github.com/luxfi/crypto"
	"github.com/luxfi/geth/common"
)

// ContractAddress is the EVM address of the AI Market precompile.
var ContractAddress = common.HexToAddress("0x0300000000000000000000000000000000000011")

// Namespaces for state-slot derivation. Distinct prefixes guarantee that the
// keccak256 keyspaces of different record kinds never overlap.
var (
	nsOffering = []byte("aimkt/off")
	nsCredit   = []byte("aimkt/cred")
	nsRequest  = []byte("aimkt/req")
	nsReqCost  = []byte("aimkt/req.cost")
	nsNonce    = []byte("aimkt/nonce")
	nsSettled  = []byte("aimkt/settled")
)

// BaseCostWei is the flat per-request floor added to the metered token cost.
// It prices the on-chain accounting work (the request record + ledger write)
// independently of model usage, so a zero-priced model still has a real cost.
var BaseCostWei = uint256.NewInt(1_000_000_000) // 1 gwei

// Request lifecycle states (stored in the request record's status byte).
const (
	StatusNone     uint8 = 0 // zero value: no such record
	StatusMetered  uint8 = 1 // metered, cost escrowed, awaiting attestation
	StatusSettled  uint8 = 2 // result attested, operator credited
	StatusReverted uint8 = 3 // reserved for future dispute/refund flows
)

// Offering flags. EXISTS lets us represent a legitimately price-0 offering
// distinct from an unregistered (all-zero slot) one.
const offeringExistsFlag uint8 = 0x01

// modelNameMaxLen bounds a model name so its hashed key and gas are bounded.
const modelNameMaxLen = 64

// uint128Max is the inclusive ceiling for a stored offering price. Prices are
// packed into 16 bytes; metering still computes in full uint256, so a single
// huge request can exceed 2^128 in aggregate cost and is overflow-checked.
var uint128Max = new(uint256.Int).SubUint64(new(uint256.Int).Lsh(uint256.NewInt(1), 128), 1)

// thousand is the per-K-token divisor for metering.
var thousand = uint256.NewInt(1000)

// Errors. These are returned to the EVM as call failures (revert).
var (
	ErrEmptyModelName    = errors.New("aimarket: empty model name")
	ErrModelNameTooLong  = errors.New("aimarket: model name too long")
	ErrPriceTooLarge     = errors.New("aimarket: price exceeds uint128")
	ErrOfferingNotFound  = errors.New("aimarket: no offering for (operator, model)")
	ErrTokensOverMax     = errors.New("aimarket: tokensUsed exceeds offering maxSizeTokens")
	ErrZeroTokens        = errors.New("aimarket: tokensUsed must be > 0")
	ErrCostOverflow      = errors.New("aimarket: cost computation overflow")
	ErrCreditOverflow    = errors.New("aimarket: operator credit overflow")
	ErrInsufficientFunds = errors.New("aimarket: caller has insufficient balance for cost")
	ErrNoCredit          = errors.New("aimarket: operator has no credit to withdraw")
	ErrEscrowUnderflow   = errors.New("aimarket: escrow underflow (accounting invariant broken)")
	ErrRecordNotFound    = errors.New("aimarket: request record not found")
	ErrAlreadySettled    = errors.New("aimarket: request already settled")
	ErrNotMetered        = errors.New("aimarket: request not in metered state")
	ErrEmptyResultHash   = errors.New("aimarket: empty result hash")
	ErrAttestationFailed = errors.New("aimarket: operator attestation failed")
)

// StateDB is the minimal slot-level state interface this package needs. It is
// satisfied by the contract.StateDB the precompile receives, adapted in
// contract.go. Money custody (balances) is handled separately via the Ledger
// interface so the pure accounting logic stays testable in isolation.
type StateDB interface {
	GetState(common.Address, common.Hash) common.Hash
	SetState(common.Address, common.Hash, common.Hash) common.Hash
}

// Ledger is the native-value custody interface: pull funds from a caller into
// precompile escrow on metering, and pay an operator out of escrow on
// withdraw. It is satisfied by the contract.StateDB balance methods, adapted
// in contract.go. Kept separate from StateDB so accounting (slots) and custody
// (balances) are orthogonal concerns.
type Ledger interface {
	GetBalance(common.Address) *uint256.Int
	// Pull moves `amount` from `from` into the precompile escrow. Returns
	// ErrInsufficientFunds if `from` cannot cover it. Atomic.
	Pull(from common.Address, amount *uint256.Int) error
	// Pay moves `amount` from the precompile escrow to `to`. Returns
	// ErrEscrowUnderflow if escrow cannot cover it (an invariant breach).
	Pay(to common.Address, amount *uint256.Int) error
}

// ---------------------------------------------------------------------------
// Slot derivation
// ---------------------------------------------------------------------------

// slot1 derives a state slot from a namespace and one address.
func slot1(ns []byte, a common.Address) common.Hash {
	return common.BytesToHash(crypto.Keccak256(ns, a.Bytes()))
}

// slot2 derives a state slot from a namespace, an address, and a byte key.
func slot2(ns []byte, a common.Address, key []byte) common.Hash {
	return common.BytesToHash(crypto.Keccak256(ns, a.Bytes(), key))
}

// slotID derives a state slot from a namespace and a 32-byte record id.
func slotID(ns []byte, id common.Hash) common.Hash {
	return common.BytesToHash(crypto.Keccak256(ns, id.Bytes()))
}

// ---------------------------------------------------------------------------
// Offering packing: [ price:16 | maxSize:4 | _:11 | flags:1 ] = 32 bytes
// ---------------------------------------------------------------------------

// Offering is the decoded form of a stored model offering.
type Offering struct {
	Price         *uint256.Int // wei per 1000 tokens
	MaxSizeTokens uint32
	Exists        bool
}

// packOffering encodes an offering into a 32-byte word.
//
//	bytes [0:16]   price (big-endian uint128)
//	bytes [16:20]  maxSizeTokens (big-endian uint32)
//	bytes [20:31]  zero (reserved)
//	byte  [31]     flags
func packOffering(price *uint256.Int, maxSize uint32) (common.Hash, error) {
	if price.Gt(uint128Max) {
		return common.Hash{}, ErrPriceTooLarge
	}
	var w [32]byte
	// price occupies the low 16 bytes of the uint256; copy them big-endian
	// into w[0:16].
	pb := price.Bytes32() // 32-byte big-endian
	copy(w[0:16], pb[16:32])
	binary.BigEndian.PutUint32(w[16:20], maxSize)
	w[31] = offeringExistsFlag
	return common.BytesToHash(w[:]), nil
}

// unpackOffering decodes a stored offering word. A zero word means "never
// registered" (Exists=false).
func unpackOffering(h common.Hash) Offering {
	b := h.Bytes() // 32 bytes, big-endian
	if b[31]&offeringExistsFlag == 0 {
		return Offering{Price: uint256.NewInt(0), Exists: false}
	}
	price := new(uint256.Int).SetBytes(b[0:16])
	maxSize := binary.BigEndian.Uint32(b[16:20])
	return Offering{Price: price, MaxSizeTokens: maxSize, Exists: true}
}

// ---------------------------------------------------------------------------
// Request record packing: [ status:1 | operator:20 | tokens:4 | _:7 ]
// ---------------------------------------------------------------------------

type requestRecord struct {
	Status   uint8
	Operator common.Address
	Tokens   uint32
}

func packRequest(r requestRecord) common.Hash {
	var w [32]byte
	w[0] = r.Status
	copy(w[1:21], r.Operator.Bytes())
	binary.BigEndian.PutUint32(w[21:25], r.Tokens)
	return common.BytesToHash(w[:])
}

func unpackRequest(h common.Hash) requestRecord {
	b := h.Bytes()
	return requestRecord{
		Status:   b[0],
		Operator: common.BytesToAddress(b[1:21]),
		Tokens:   binary.BigEndian.Uint32(b[21:25]),
	}
}

// ---------------------------------------------------------------------------
// Core accounting operations (pure, given a StateDB / Ledger)
// ---------------------------------------------------------------------------

// RegisterOffering stores (or overwrites) the operator's offering for a model.
// Idempotent overwrite is intentional: an operator re-prices by calling again.
func RegisterOffering(db StateDB, operator common.Address, modelName []byte, price *uint256.Int, maxSizeTokens uint32) error {
	if err := validateModelName(modelName); err != nil {
		return err
	}
	if price.Gt(uint128Max) {
		return ErrPriceTooLarge
	}
	w, err := packOffering(price, maxSizeTokens)
	if err != nil {
		return err
	}
	db.SetState(ContractAddress, slot2(nsOffering, operator, modelName), w)
	return nil
}

// GetOffering reads an offering. Exists=false if never registered.
func GetOffering(db StateDB, operator common.Address, modelName []byte) Offering {
	h := db.GetState(ContractAddress, slot2(nsOffering, operator, modelName))
	return unpackOffering(h)
}

// ComputeCost returns base + tokensUsed * price / 1000, in wei, fully checked
// for overflow in uint256. It does NOT touch state — callers use it to quote.
func ComputeCost(price *uint256.Int, tokensUsed uint32) (*uint256.Int, error) {
	// product = price * tokensUsed  (checked)
	product := new(uint256.Int)
	if _, overflow := product.MulOverflow(price, uint256.NewInt(uint64(tokensUsed))); overflow {
		return nil, ErrCostOverflow
	}
	// metered = product / 1000  (floor division; no overflow possible)
	metered := new(uint256.Int).Div(product, thousand)
	// cost = base + metered  (checked)
	cost := new(uint256.Int)
	if _, overflow := cost.AddOverflow(BaseCostWei, metered); overflow {
		return nil, ErrCostOverflow
	}
	return cost, nil
}

// Meter validates the offering, computes cost, pulls it from the caller into
// escrow, and credits the operator's ledger. Returns the cost charged.
//
// Guards: model must be offered; tokensUsed in (0, maxSize]; caller must have
// the funds; credit addition must not overflow uint256.
func Meter(db StateDB, lg Ledger, caller, operator common.Address, modelName []byte, tokensUsed uint32) (*uint256.Int, error) {
	if err := validateModelName(modelName); err != nil {
		return nil, err
	}
	if tokensUsed == 0 {
		return nil, ErrZeroTokens
	}
	off := GetOffering(db, operator, modelName)
	if !off.Exists {
		return nil, ErrOfferingNotFound
	}
	if tokensUsed > off.MaxSizeTokens {
		return nil, ErrTokensOverMax
	}

	cost, err := ComputeCost(off.Price, tokensUsed)
	if err != nil {
		return nil, err
	}

	// Read current operator credit and pre-check the addition for overflow
	// BEFORE moving any money, so a would-be-overflow leaves state untouched.
	credit := readCredit(db, operator)
	newCredit := new(uint256.Int)
	if _, overflow := newCredit.AddOverflow(credit, cost); overflow {
		return nil, ErrCreditOverflow
	}

	// Pull funds into escrow (fails closed on insufficient balance — no
	// credit is recorded if the caller can't pay).
	if err := lg.Pull(caller, cost); err != nil {
		return nil, err
	}

	// Record the credit. After Pull succeeded, escrow grew by `cost`, so this
	// preserves the escrow == sum(credits) invariant.
	writeCredit(db, operator, newCredit)
	return cost, nil
}

// Withdraw pays the operator's entire accrued credit out of escrow and zeroes
// the ledger. Returns the amount paid. Fails closed if there is nothing to
// withdraw, and treats an escrow shortfall as a hard invariant breach.
func Withdraw(db StateDB, lg Ledger, operator common.Address) (*uint256.Int, error) {
	credit := readCredit(db, operator)
	if credit.IsZero() {
		return nil, ErrNoCredit
	}
	// Pay first; only zero the ledger if payment succeeds. If Pay fails the
	// ledger is left intact so the operator can retry — no credit is lost.
	if err := lg.Pay(operator, credit); err != nil {
		return nil, err
	}
	writeCredit(db, operator, uint256.NewInt(0))
	return credit, nil
}

// GetCredit reads an operator's accrued (unwithdrawn) credit.
func GetCredit(db StateDB, operator common.Address) *uint256.Int {
	return readCredit(db, operator)
}

// RequestInference looks up an offering, meters it, and records a request,
// returning a unique recordId. The recordId binds the operator and token
// count so SettleInference can credit-on-attest without trusting calldata.
//
// recordId = keccak256("aimkt/req", caller, nonce, operator, modelName,
// tokensUsed) — deterministic, unique per (caller, nonce), and unforgeable
// for a different operator/model/token tuple.
func RequestInference(db StateDB, lg Ledger, caller, operator common.Address, modelName []byte, tokensUsed uint32) (common.Hash, *uint256.Int, error) {
	if err := validateModelName(modelName); err != nil {
		return common.Hash{}, nil, err
	}
	// Meter first (validates offering, tokens, funds, and escrows cost).
	cost, err := Meter(db, lg, caller, operator, modelName, tokensUsed)
	if err != nil {
		return common.Hash{}, nil, err
	}

	// Derive a unique recordId from the caller's monotonic nonce.
	nonceSlot := slot1(nsNonce, caller)
	nonce := db.GetState(ContractAddress, nonceSlot)
	recordId := computeRecordID(caller, nonce, operator, modelName, tokensUsed)

	// Persist the request record + its escrowed cost.
	db.SetState(ContractAddress, slotID(nsRequest, recordId), packRequest(requestRecord{
		Status:   StatusMetered,
		Operator: operator,
		Tokens:   tokensUsed,
	}))
	db.SetState(ContractAddress, slotID(nsReqCost, recordId), h32(cost))

	// Bump the nonce so the next request from this caller is unique.
	bumpNonce(db, nonceSlot, nonce)

	return recordId, cost, nil
}

// SettleInference finalizes a metered request once a result is attested. The
// operator proves it served the request by signing a message over
// (recordId, resultHash); on success the record flips to Settled. The funds
// were already escrowed + credited at Meter time, so settlement is the
// attestation gate, not a second credit. The settled marker makes replay a
// no-op error.
//
// `attest` is a pluggable attestation verifier (so the precompile can wire in
// ML-DSA / secp256k1 / threshold sig verification). It must return true iff
// `operatorSig` is a valid attestation by `operator` over the digest
// keccak256(recordId, resultHash). Returns the (now-settled) operator.
func SettleInference(db StateDB, recordId common.Hash, resultHash common.Hash, operatorSig []byte, attest AttestFunc) (common.Address, error) {
	if resultHash == (common.Hash{}) {
		return common.Address{}, ErrEmptyResultHash
	}

	// Replay guard: a consumed record can never be settled twice.
	settledSlot := slotID(nsSettled, recordId)
	if isSet(db.GetState(ContractAddress, settledSlot)) {
		return common.Address{}, ErrAlreadySettled
	}

	recH := db.GetState(ContractAddress, slotID(nsRequest, recordId))
	if recH == (common.Hash{}) {
		return common.Address{}, ErrRecordNotFound
	}
	rec := unpackRequest(recH)
	if rec.Status != StatusMetered {
		return common.Address{}, ErrNotMetered
	}

	// Verify the operator's attestation over (recordId, resultHash).
	digest := common.BytesToHash(crypto.Keccak256(recordId.Bytes(), resultHash.Bytes()))
	if !attest(rec.Operator, digest, operatorSig) {
		return common.Address{}, ErrAttestationFailed
	}

	// Flip to settled and burn the replay marker in the SAME call. Both
	// writes must land; the EVM journals them together and reverts both on
	// any later failure in this frame.
	rec.Status = StatusSettled
	db.SetState(ContractAddress, slotID(nsRequest, recordId), packRequest(rec))
	db.SetState(ContractAddress, settledSlot, oneHash())

	return rec.Operator, nil
}

// AttestFunc verifies that `sig` is a valid attestation by `operator` over
// `digest`. Pluggable so settlement can use any signature scheme.
type AttestFunc func(operator common.Address, digest common.Hash, sig []byte) bool

// GetRequest reads a request record (Status=StatusNone if absent).
func GetRequest(db StateDB, recordId common.Hash) (operator common.Address, tokens uint32, status uint8) {
	h := db.GetState(ContractAddress, slotID(nsRequest, recordId))
	if h == (common.Hash{}) {
		return common.Address{}, 0, StatusNone
	}
	r := unpackRequest(h)
	return r.Operator, r.Tokens, r.Status
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func validateModelName(name []byte) error {
	if len(name) == 0 {
		return ErrEmptyModelName
	}
	if len(name) > modelNameMaxLen {
		return ErrModelNameTooLong
	}
	return nil
}

func readCredit(db StateDB, operator common.Address) *uint256.Int {
	h := db.GetState(ContractAddress, slot1(nsCredit, operator))
	return new(uint256.Int).SetBytes(h.Bytes())
}

func writeCredit(db StateDB, operator common.Address, v *uint256.Int) {
	db.SetState(ContractAddress, slot1(nsCredit, operator), h32(v))
}

func computeRecordID(caller common.Address, nonce common.Hash, operator common.Address, modelName []byte, tokensUsed uint32) common.Hash {
	var tb [4]byte
	binary.BigEndian.PutUint32(tb[:], tokensUsed)
	return common.BytesToHash(crypto.Keccak256(
		nsRequest,
		caller.Bytes(),
		nonce.Bytes(),
		operator.Bytes(),
		modelName,
		tb[:],
	))
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

// h32 converts a uint256 to a left-padded 32-byte state word.
func h32(v *uint256.Int) common.Hash {
	b := v.Bytes32()
	return common.BytesToHash(b[:])
}
