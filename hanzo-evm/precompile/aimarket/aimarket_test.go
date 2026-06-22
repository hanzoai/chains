// Copyright (C) 2026, Hanzo AI Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package aimarket

import (
	"context"
	"crypto/ecdsa"
	"encoding/binary"
	"math/big"
	"testing"

	"github.com/holiman/uint256"
	"github.com/luxfi/crypto"
	"github.com/luxfi/geth/common"
	"github.com/luxfi/geth/core/tracing"
	ethtypes "github.com/luxfi/geth/core/types"
	"github.com/luxfi/precompile/contract"
	"github.com/luxfi/precompile/precompileconfig"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Balance-tracking mock harness.
//
// The lux ai/module_test.go mock returns zero balances and no-ops AddBalance /
// SubBalance because the lux AI precompile never touches value. THIS
// marketplace moves money, so the harness must actually track balances to
// prove "caller charged" + "operator credited" + value conservation.
// ---------------------------------------------------------------------------

type mockStateDB struct {
	state   map[common.Address]map[common.Hash]common.Hash
	balance map[common.Address]*uint256.Int
}

func newMockStateDB() *mockStateDB {
	return &mockStateDB{
		state:   make(map[common.Address]map[common.Hash]common.Hash),
		balance: make(map[common.Address]*uint256.Int),
	}
}

func (m *mockStateDB) GetState(addr common.Address, key common.Hash) common.Hash {
	if m.state[addr] == nil {
		return common.Hash{}
	}
	return m.state[addr][key]
}

func (m *mockStateDB) SetState(addr common.Address, key, val common.Hash) common.Hash {
	if m.state[addr] == nil {
		m.state[addr] = make(map[common.Hash]common.Hash)
	}
	old := m.state[addr][key]
	m.state[addr][key] = val
	return old
}

func (m *mockStateDB) bal(a common.Address) *uint256.Int {
	if m.balance[a] == nil {
		m.balance[a] = new(uint256.Int)
	}
	return m.balance[a]
}

func (m *mockStateDB) GetBalance(a common.Address) *uint256.Int {
	return new(uint256.Int).Set(m.bal(a))
}

func (m *mockStateDB) AddBalance(a common.Address, v *uint256.Int, _ tracing.BalanceChangeReason) uint256.Int {
	prev := new(uint256.Int).Set(m.bal(a))
	m.balance[a] = new(uint256.Int).Add(prev, v)
	return *prev
}

func (m *mockStateDB) SubBalance(a common.Address, v *uint256.Int, _ tracing.BalanceChangeReason) uint256.Int {
	prev := new(uint256.Int).Set(m.bal(a))
	m.balance[a] = new(uint256.Int).Sub(prev, v)
	return *prev
}

// unused StateDB surface
func (m *mockStateDB) SetNonce(common.Address, uint64, tracing.NonceChangeReason) {}
func (m *mockStateDB) GetNonce(common.Address) uint64                             { return 0 }
func (m *mockStateDB) GetBalanceMultiCoin(common.Address, common.Hash) *big.Int   { return big.NewInt(0) }
func (m *mockStateDB) AddBalanceMultiCoin(common.Address, common.Hash, *big.Int)  {}
func (m *mockStateDB) SubBalanceMultiCoin(common.Address, common.Hash, *big.Int)  {}
func (m *mockStateDB) CreateAccount(common.Address)                               {}
func (m *mockStateDB) Exist(common.Address) bool                                  { return false }
func (m *mockStateDB) AddLog(*ethtypes.Log)                                       {}
func (m *mockStateDB) Logs() []*ethtypes.Log                                      { return nil }
func (m *mockStateDB) GetPredicateStorageSlots(common.Address, int) ([]byte, bool) {
	return nil, false
}
func (m *mockStateDB) TxHash() common.Hash  { return common.Hash{} }
func (m *mockStateDB) Snapshot() int        { return 0 }
func (m *mockStateDB) RevertToSnapshot(int) {}

var _ contract.StateDB = (*mockStateDB)(nil)

type mockBlockCtx struct{}

func (mockBlockCtx) Number() *big.Int                                       { return big.NewInt(1) }
func (mockBlockCtx) Timestamp() uint64                                      { return 1000 }
func (mockBlockCtx) GetPredicateResults(common.Hash, common.Address) []byte { return nil }

type mockChainCfg struct{}

func (mockChainCfg) IsDurango(uint64) bool { return true }

type mockEnv struct{}

func (mockEnv) ReadOnly() bool { return false }

type mockAccessibleState struct{ db *mockStateDB }

func (a *mockAccessibleState) GetStateDB() contract.StateDB                 { return a.db }
func (a *mockAccessibleState) GetBlockContext() contract.BlockContext       { return mockBlockCtx{} }
func (a *mockAccessibleState) GetConsensusContext() context.Context         { return context.Background() }
func (a *mockAccessibleState) GetChainConfig() precompileconfig.ChainConfig { return mockChainCfg{} }
func (a *mockAccessibleState) GetPrecompileEnv() contract.PrecompileEnvironment {
	return mockEnv{}
}

var _ contract.AccessibleState = (*mockAccessibleState)(nil)

func newAS() *mockAccessibleState { return &mockAccessibleState{db: newMockStateDB()} }

// fund credits a test account's native balance.
func fund(db *mockStateDB, a common.Address, wei uint64) {
	db.balance[a] = uint256.NewInt(wei)
}

// keypair returns a secp256k1 key and its EVM address (an operator identity).
func keypair(t *testing.T) (*ecdsa.PrivateKey, common.Address) {
	t.Helper()
	k, err := crypto.GenerateKey()
	require.NoError(t, err)
	// Bridge luxfi/crypto/common.Address -> luxfi/geth/common.Address ([20]byte).
	a := crypto.PubkeyToAddress(k.PublicKey)
	return k, common.BytesToAddress(a[:])
}

// attestSig signs the settlement digest keccak256(recordId, resultHash).
func attestSig(t *testing.T, k *ecdsa.PrivateKey, recordId, resultHash common.Hash) []byte {
	t.Helper()
	digest := crypto.Keccak256(recordId.Bytes(), resultHash.Bytes())
	sig, err := crypto.Sign(digest, k)
	require.NoError(t, err)
	return sig
}

var (
	caller   = common.HexToAddress("0xCa11e700000000000000000000000000000000A1")
	operator = common.HexToAddress("0x0pe7a70000000000000000000000000000000B2")
	model    = []byte("zen-nano")
)

// ===========================================================================
// Core accounting unit tests (direct StateDB/Ledger — no calldata layer)
// ===========================================================================

func TestRegisterAndGetOffering(t *testing.T) {
	db := newMockStateDB()

	// Unregistered → Exists=false.
	o := GetOffering(db, operator, model)
	require.False(t, o.Exists)

	price := uint256.NewInt(2_000_000_000_000) // 2e12 wei / 1k tokens
	require.NoError(t, RegisterOffering(db, operator, model, price, 4096))

	got := GetOffering(db, operator, model)
	require.True(t, got.Exists)
	require.Equal(t, price, got.Price)
	require.Equal(t, uint32(4096), got.MaxSizeTokens)

	// Re-price (overwrite) is allowed.
	require.NoError(t, RegisterOffering(db, operator, model, uint256.NewInt(5), 10))
	got = GetOffering(db, operator, model)
	require.Equal(t, uint256.NewInt(5), got.Price)
	require.Equal(t, uint32(10), got.MaxSizeTokens)
}

func TestRegisterOfferingRejectsBadInput(t *testing.T) {
	db := newMockStateDB()
	require.ErrorIs(t, RegisterOffering(db, operator, nil, uint256.NewInt(1), 1), ErrEmptyModelName)
	long := make([]byte, modelNameMaxLen+1)
	require.ErrorIs(t, RegisterOffering(db, operator, long, uint256.NewInt(1), 1), ErrModelNameTooLong)
	tooBig := new(uint256.Int).Add(uint128Max, uint256.NewInt(1))
	require.ErrorIs(t, RegisterOffering(db, operator, model, tooBig, 1), ErrPriceTooLarge)
}

func TestZeroPriceOfferingIsDistinctFromUnregistered(t *testing.T) {
	db := newMockStateDB()
	// A genuinely free model: price 0 but Exists must be true.
	require.NoError(t, RegisterOffering(db, operator, model, uint256.NewInt(0), 100))
	o := GetOffering(db, operator, model)
	require.True(t, o.Exists, "price-0 offering must still exist")
	require.True(t, o.Price.IsZero())

	// A different, never-registered model must read as not-existing.
	require.False(t, GetOffering(db, operator, []byte("other")).Exists)
}

func TestComputeCostMath(t *testing.T) {
	// cost = base + tokens*price/1000
	// price = 1e9/1k tokens, tokens = 2000 → metered = 2e9, + base 1e9 = 3e9.
	price := uint256.NewInt(1_000_000_000)
	cost, err := ComputeCost(price, 2000)
	require.NoError(t, err)
	require.Equal(t, uint256.NewInt(3_000_000_000), cost)

	// Sub-thousand tokens floor-divide: 999 * 1e9 / 1000 = 999e6, + base.
	cost, err = ComputeCost(price, 999)
	require.NoError(t, err)
	require.Equal(t, uint256.NewInt(1_000_000_000+999_000_000), cost)

	// Overflow: price near 2^256 * any tokens>1 overflows the multiply.
	huge := new(uint256.Int).Sub(new(uint256.Int).Lsh(uint256.NewInt(1), 255), uint256.NewInt(1))
	_, err = ComputeCost(huge, 1000)
	require.ErrorIs(t, err, ErrCostOverflow)
}

func TestMeterChargesCallerCreditsOperator(t *testing.T) {
	db := newMockStateDB()
	lg := newLedger(db)
	fund(db, caller, 10_000_000_000)

	require.NoError(t, RegisterOffering(db, operator, model, uint256.NewInt(1_000_000_000), 4096))

	startCaller := db.GetBalance(caller).Uint64()
	cost, err := Meter(db, lg, caller, operator, model, 2000)
	require.NoError(t, err)
	// 1e9 base + 2000*1e9/1000 = 1e9 + 2e9 = 3e9.
	require.Equal(t, uint64(3_000_000_000), cost.Uint64())

	// Caller debited exactly cost.
	require.Equal(t, startCaller-cost.Uint64(), db.GetBalance(caller).Uint64())
	// Escrow (precompile) holds exactly cost.
	require.Equal(t, cost.Uint64(), db.GetBalance(ContractAddress).Uint64())
	// Operator ledger credited exactly cost.
	require.Equal(t, cost.Uint64(), GetCredit(db, operator).Uint64())

	// Conservation: escrow == sum(credits).
	require.Equal(t, GetCredit(db, operator).Uint64(), db.GetBalance(ContractAddress).Uint64())
}

func TestMeterAccumulatesCredit(t *testing.T) {
	db := newMockStateDB()
	lg := newLedger(db)
	fund(db, caller, 100_000_000_000)
	require.NoError(t, RegisterOffering(db, operator, model, uint256.NewInt(1_000_000_000), 4096))

	c1, err := Meter(db, lg, caller, operator, model, 1000)
	require.NoError(t, err)
	c2, err := Meter(db, lg, caller, operator, model, 3000)
	require.NoError(t, err)

	want := c1.Uint64() + c2.Uint64()
	require.Equal(t, want, GetCredit(db, operator).Uint64())
	require.Equal(t, want, db.GetBalance(ContractAddress).Uint64(), "escrow == sum credits")
}

func TestMeterRejectsUnregisteredModel(t *testing.T) {
	db := newMockStateDB()
	lg := newLedger(db)
	fund(db, caller, 10_000_000_000)
	_, err := Meter(db, lg, caller, operator, []byte("ghost"), 100)
	require.ErrorIs(t, err, ErrOfferingNotFound)
	// No money moved.
	require.Equal(t, uint64(10_000_000_000), db.GetBalance(caller).Uint64())
	require.Zero(t, db.GetBalance(ContractAddress).Uint64())
}

func TestMeterRejectsOverMaxSize(t *testing.T) {
	db := newMockStateDB()
	lg := newLedger(db)
	fund(db, caller, 10_000_000_000)
	require.NoError(t, RegisterOffering(db, operator, model, uint256.NewInt(1_000_000_000), 1000))

	_, err := Meter(db, lg, caller, operator, model, 1001)
	require.ErrorIs(t, err, ErrTokensOverMax)
	// Exactly maxSize is allowed.
	_, err = Meter(db, lg, caller, operator, model, 1000)
	require.NoError(t, err)
}

func TestMeterRejectsZeroTokens(t *testing.T) {
	db := newMockStateDB()
	lg := newLedger(db)
	fund(db, caller, 10_000_000_000)
	require.NoError(t, RegisterOffering(db, operator, model, uint256.NewInt(1), 1000))
	_, err := Meter(db, lg, caller, operator, model, 0)
	require.ErrorIs(t, err, ErrZeroTokens)
}

func TestMeterFailsClosedOnInsufficientFunds(t *testing.T) {
	db := newMockStateDB()
	lg := newLedger(db)
	fund(db, caller, 100) // far less than cost
	require.NoError(t, RegisterOffering(db, operator, model, uint256.NewInt(1_000_000_000), 4096))

	_, err := Meter(db, lg, caller, operator, model, 2000)
	require.ErrorIs(t, err, ErrInsufficientFunds)
	// Fail-closed: caller untouched, no escrow, no credit.
	require.Equal(t, uint64(100), db.GetBalance(caller).Uint64())
	require.Zero(t, db.GetBalance(ContractAddress).Uint64())
	require.Zero(t, GetCredit(db, operator).Uint64())
}

func TestWithdraw(t *testing.T) {
	db := newMockStateDB()
	lg := newLedger(db)
	fund(db, caller, 100_000_000_000)
	require.NoError(t, RegisterOffering(db, operator, model, uint256.NewInt(1_000_000_000), 4096))

	cost, err := Meter(db, lg, caller, operator, model, 2000)
	require.NoError(t, err)

	opStart := db.GetBalance(operator).Uint64()
	paid, err := Withdraw(db, lg, operator)
	require.NoError(t, err)
	require.Equal(t, cost.Uint64(), paid.Uint64())

	// Operator received funds; ledger and escrow zeroed.
	require.Equal(t, opStart+cost.Uint64(), db.GetBalance(operator).Uint64())
	require.Zero(t, GetCredit(db, operator).Uint64())
	require.Zero(t, db.GetBalance(ContractAddress).Uint64(), "escrow drained")

	// Second withdraw with no credit fails closed.
	_, err = Withdraw(db, lg, operator)
	require.ErrorIs(t, err, ErrNoCredit)
}

func TestWithdrawNothing(t *testing.T) {
	db := newMockStateDB()
	lg := newLedger(db)
	_, err := Withdraw(db, lg, operator)
	require.ErrorIs(t, err, ErrNoCredit)
}

// TestValueConservationInvariant is the core economic-safety property: no wei
// is created or destroyed by the marketplace. Across a full multi-operator,
// multi-caller, meter+withdraw lifecycle, the sum of all balances is constant,
// and at every step escrow == sum of unwithdrawn operator credits.
func TestValueConservationInvariant(t *testing.T) {
	db := newMockStateDB()
	lg := newLedger(db)

	op2 := common.HexToAddress("0x00000000000000000000000000000000000000C3")
	caller2 := common.HexToAddress("0x00000000000000000000000000000000000000D4")

	fund(db, caller, 50_000_000_000)
	fund(db, caller2, 50_000_000_000)

	total := func() uint64 {
		return db.GetBalance(caller).Uint64() + db.GetBalance(caller2).Uint64() +
			db.GetBalance(operator).Uint64() + db.GetBalance(op2).Uint64() +
			db.GetBalance(ContractAddress).Uint64()
	}
	want := total()

	escrowEqualsCredits := func() {
		credits := GetCredit(db, operator).Uint64() + GetCredit(db, op2).Uint64()
		require.Equal(t, credits, db.GetBalance(ContractAddress).Uint64(), "escrow == sum credits")
	}

	require.NoError(t, RegisterOffering(db, operator, model, uint256.NewInt(1_000_000_000), 4096))
	require.NoError(t, RegisterOffering(db, op2, []byte("zen-coder"), uint256.NewInt(2_000_000_000), 8192))

	// Interleave metering from both callers to both operators.
	_, err := Meter(db, lg, caller, operator, model, 1500)
	require.NoError(t, err)
	require.Equal(t, want, total())
	escrowEqualsCredits()

	_, err = Meter(db, lg, caller2, op2, []byte("zen-coder"), 4000)
	require.NoError(t, err)
	require.Equal(t, want, total())
	escrowEqualsCredits()

	_, err = Meter(db, lg, caller2, operator, model, 500)
	require.NoError(t, err)
	require.Equal(t, want, total())
	escrowEqualsCredits()

	// Each operator withdraws; conservation still holds and escrow drains.
	_, err = Withdraw(db, lg, operator)
	require.NoError(t, err)
	require.Equal(t, want, total())
	escrowEqualsCredits()

	_, err = Withdraw(db, lg, op2)
	require.NoError(t, err)
	require.Equal(t, want, total())
	require.Zero(t, db.GetBalance(ContractAddress).Uint64())
}

// TestDirectMeterCreditIsWithdrawable proves that a raw Meter call (no
// RequestInference, no settlement) produces a real, immediately withdrawable
// credit — Meter is the standalone accounting primitive.
func TestDirectMeterCreditIsWithdrawable(t *testing.T) {
	db := newMockStateDB()
	lg := newLedger(db)
	fund(db, caller, 10_000_000_000)
	require.NoError(t, RegisterOffering(db, operator, model, uint256.NewInt(1_000_000_000), 4096))

	cost, err := Meter(db, lg, caller, operator, model, 1000)
	require.NoError(t, err)
	paid, err := Withdraw(db, lg, operator)
	require.NoError(t, err)
	require.Equal(t, cost.Uint64(), paid.Uint64())
}

// ===========================================================================
// RequestInference + SettleInference (settlement + replay guard)
// ===========================================================================

func TestRequestInferenceMetersAndRecords(t *testing.T) {
	db := newMockStateDB()
	lg := newLedger(db)
	opKey, op := keypair(t)
	_ = opKey
	fund(db, caller, 100_000_000_000)
	require.NoError(t, RegisterOffering(db, op, model, uint256.NewInt(1_000_000_000), 4096))

	recordId, cost, err := RequestInference(db, lg, caller, op, model, 2000)
	require.NoError(t, err)
	require.NotEqual(t, common.Hash{}, recordId)
	require.Equal(t, uint64(3_000_000_000), cost.Uint64())

	// Operator credited at request time (metering happened).
	require.Equal(t, cost.Uint64(), GetCredit(db, op).Uint64())

	// Request record persisted as Metered.
	gotOp, tokens, status := GetRequest(db, recordId)
	require.Equal(t, op, gotOp)
	require.Equal(t, uint32(2000), tokens)
	require.Equal(t, StatusMetered, status)
}

func TestRequestInferenceUniqueRecordIds(t *testing.T) {
	db := newMockStateDB()
	lg := newLedger(db)
	fund(db, caller, 100_000_000_000)
	require.NoError(t, RegisterOffering(db, operator, model, uint256.NewInt(1), 4096))

	r1, _, err := RequestInference(db, lg, caller, operator, model, 100)
	require.NoError(t, err)
	r2, _, err := RequestInference(db, lg, caller, operator, model, 100)
	require.NoError(t, err)
	require.NotEqual(t, r1, r2, "nonce must make identical requests distinct")
}

func TestSettleInferenceHappyPath(t *testing.T) {
	db := newMockStateDB()
	lg := newLedger(db)
	opKey, op := keypair(t)
	fund(db, caller, 100_000_000_000)
	require.NoError(t, RegisterOffering(db, op, model, uint256.NewInt(1_000_000_000), 4096))

	recordId, _, err := RequestInference(db, lg, caller, op, model, 2000)
	require.NoError(t, err)

	resultHash := common.HexToHash("0xdeadbeef")
	sig := attestSig(t, opKey, recordId, resultHash)

	settledOp, err := SettleInference(db, recordId, resultHash, sig, DefaultAttest)
	require.NoError(t, err)
	require.Equal(t, op, settledOp)

	_, _, status := GetRequest(db, recordId)
	require.Equal(t, StatusSettled, status)
}

func TestSettleInferenceReplayRejected(t *testing.T) {
	db := newMockStateDB()
	lg := newLedger(db)
	opKey, op := keypair(t)
	fund(db, caller, 100_000_000_000)
	require.NoError(t, RegisterOffering(db, op, model, uint256.NewInt(1_000_000_000), 4096))

	recordId, _, err := RequestInference(db, lg, caller, op, model, 2000)
	require.NoError(t, err)
	resultHash := common.HexToHash("0xabc123")
	sig := attestSig(t, opKey, recordId, resultHash)

	// First settle succeeds.
	_, err = SettleInference(db, recordId, resultHash, sig, DefaultAttest)
	require.NoError(t, err)

	// Replay with the SAME valid signature is rejected (consumed once).
	_, err = SettleInference(db, recordId, resultHash, sig, DefaultAttest)
	require.ErrorIs(t, err, ErrAlreadySettled)

	// Even a fresh valid signature over the same record is rejected.
	sig2 := attestSig(t, opKey, recordId, resultHash)
	_, err = SettleInference(db, recordId, resultHash, sig2, DefaultAttest)
	require.ErrorIs(t, err, ErrAlreadySettled)
}

func TestSettleInferenceRejectsForgedSignature(t *testing.T) {
	db := newMockStateDB()
	lg := newLedger(db)
	opKey, op := keypair(t)
	attackerKey, _ := keypair(t)
	fund(db, caller, 100_000_000_000)
	require.NoError(t, RegisterOffering(db, op, model, uint256.NewInt(1_000_000_000), 4096))

	recordId, _, err := RequestInference(db, lg, caller, op, model, 2000)
	require.NoError(t, err)
	resultHash := common.HexToHash("0xfeed")

	// Signature by someone other than the recorded operator → rejected.
	forged := attestSig(t, attackerKey, recordId, resultHash)
	_, err = SettleInference(db, recordId, resultHash, forged, DefaultAttest)
	require.ErrorIs(t, err, ErrAttestationFailed)

	// A signature over a DIFFERENT resultHash than supplied → recovers to a
	// different address than operator → rejected.
	wrongDigestSig := attestSig(t, opKey, recordId, common.HexToHash("0x9999"))
	_, err = SettleInference(db, recordId, resultHash, wrongDigestSig, DefaultAttest)
	require.ErrorIs(t, err, ErrAttestationFailed)

	// Record stays Metered after failed settlements.
	_, _, status := GetRequest(db, recordId)
	require.Equal(t, StatusMetered, status)
	_ = opKey
}

func TestSettleInferenceUnknownRecord(t *testing.T) {
	db := newMockStateDB()
	_, err := SettleInference(db, common.HexToHash("0x01"), common.HexToHash("0x02"), make([]byte, 65), DefaultAttest)
	require.ErrorIs(t, err, ErrRecordNotFound)
}

func TestSettleInferenceEmptyResultHash(t *testing.T) {
	db := newMockStateDB()
	_, err := SettleInference(db, common.HexToHash("0x01"), common.Hash{}, make([]byte, 65), DefaultAttest)
	require.ErrorIs(t, err, ErrEmptyResultHash)
}

// ===========================================================================
// Run dispatcher tests (calldata encode/decode, gas, readOnly)
//
// Core unit tests above drive the REAL production evmLedger via newLedger(db),
// so the accounting + custody path under test is exactly the one the EVM runs.
// ===========================================================================

func selBytes(sel uint32) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, sel)
	return b
}

// encReg builds calldata for registerOffering(string,uint256,uint32).
func encReg(name []byte, price, maxSize uint64) []byte {
	out := selBytes(SelectorRegisterOffering)
	out = append(out, padLeft32(uint256.NewInt(price).Bytes())...) // price
	out = append(out, padLeft32Uint32(uint32(maxSize))...)         // maxSize
	out = append(out, padLeft32(uint256.NewInt(uint64(len(name))).Bytes())...)
	out = append(out, padRight32(name)...)
	return out
}

func encAddrStr(sel uint32, a common.Address, name []byte) []byte {
	out := selBytes(sel)
	out = append(out, addrWord(a)...)
	out = append(out, padLeft32(uint256.NewInt(uint64(len(name))).Bytes())...)
	out = append(out, padRight32(name)...)
	return out
}

func encMeterLike(sel uint32, a common.Address, name []byte, tokens uint32) []byte {
	out := selBytes(sel)
	out = append(out, addrWord(a)...)
	out = append(out, padLeft32Uint32(tokens)...)
	out = append(out, padLeft32(uint256.NewInt(uint64(len(name))).Bytes())...)
	out = append(out, padRight32(name)...)
	return out
}

func addrWord(a common.Address) []byte {
	w := make([]byte, 32)
	copy(w[12:], a.Bytes())
	return w
}
func padLeft32(b []byte) []byte {
	w := make([]byte, 32)
	copy(w[32-len(b):], b)
	return w
}
func padLeft32Uint32(v uint32) []byte {
	w := make([]byte, 32)
	binary.BigEndian.PutUint32(w[28:], v)
	return w
}
func padRight32(b []byte) []byte {
	n := (len(b) + 31) / 32 * 32
	if n == 0 {
		n = 32
	}
	w := make([]byte, n)
	copy(w, b)
	return w
}

func TestRunRegisterAndGetOffering(t *testing.T) {
	as := newAS()

	// Register via Run.
	ret, gas, err := Precompile.Run(as, operator, ContractAddress, encReg(model, 1_000_000_000, 4096), 1_000_000, false)
	require.NoError(t, err)
	require.Equal(t, byte(1), ret[31])
	require.Less(t, gas, uint64(1_000_000))

	// Read back via Run (getOffering(address,string)).
	ret, _, err = Precompile.Run(as, caller, ContractAddress, encAddrStr(SelectorGetOffering, operator, model), 1_000_000, false)
	require.NoError(t, err)
	require.Len(t, ret, 96)
	price := new(uint256.Int).SetBytes(ret[0:32])
	require.Equal(t, uint64(1_000_000_000), price.Uint64())
	require.Equal(t, uint32(4096), binary.BigEndian.Uint32(ret[60:64]))
	require.Equal(t, byte(1), ret[95], "exists flag")
}

func TestRunRegisterReadOnlyRejected(t *testing.T) {
	as := newAS()
	_, _, err := Precompile.Run(as, operator, ContractAddress, encReg(model, 1, 1), 1_000_000, true)
	require.ErrorIs(t, err, ErrReadOnly)
}

func TestRunMeterAndWithdraw(t *testing.T) {
	as := newAS()
	fund(as.db, caller, 100_000_000_000)

	// Register.
	_, _, err := Precompile.Run(as, operator, ContractAddress, encReg(model, 1_000_000_000, 4096), 1_000_000, false)
	require.NoError(t, err)

	// Meter(operator, model, 2000) called by caller.
	ret, _, err := Precompile.Run(as, caller, ContractAddress, encMeterLike(SelectorMeter, operator, model, 2000), 1_000_000, false)
	require.NoError(t, err)
	cost := new(uint256.Int).SetBytes(ret).Uint64()
	require.Equal(t, uint64(3_000_000_000), cost)
	require.Equal(t, cost, as.db.GetBalance(ContractAddress).Uint64())

	// Withdraw() called by operator.
	ret, _, err = Precompile.Run(as, operator, ContractAddress, selBytes(SelectorWithdraw), 1_000_000, false)
	require.NoError(t, err)
	require.Equal(t, cost, new(uint256.Int).SetBytes(ret).Uint64())
	require.Equal(t, cost, as.db.GetBalance(operator).Uint64())
	require.Zero(t, as.db.GetBalance(ContractAddress).Uint64())
}

func TestRunMeterRejectsUnregistered(t *testing.T) {
	as := newAS()
	fund(as.db, caller, 100_000_000_000)
	_, _, err := Precompile.Run(as, caller, ContractAddress, encMeterLike(SelectorMeter, operator, []byte("ghost"), 100), 1_000_000, false)
	require.ErrorIs(t, err, ErrOfferingNotFound)
}

func TestRunRequestAndSettleViaDispatch(t *testing.T) {
	as := newAS()
	opKey, op := keypair(t)
	fund(as.db, caller, 100_000_000_000)

	// Register offering for the keypair operator.
	_, _, err := Precompile.Run(as, op, ContractAddress, encReg(model, 1_000_000_000, 4096), 1_000_000, false)
	require.NoError(t, err)

	// requestInference(op, model, 2000).
	ret, _, err := Precompile.Run(as, caller, ContractAddress, encMeterLike(SelectorRequestInference, op, model, 2000), 1_000_000, false)
	require.NoError(t, err)
	require.Len(t, ret, 64)
	var recordId common.Hash
	copy(recordId[:], ret[0:32])

	// settleInference(recordId, resultHash, sig).
	resultHash := common.HexToHash("0xc0ffee")
	sig := attestSig(t, opKey, recordId, resultHash)
	settleInput := selBytes(SelectorSettleInference)
	settleInput = append(settleInput, recordId.Bytes()...)
	settleInput = append(settleInput, resultHash.Bytes()...)
	settleInput = append(settleInput, padLeft32(uint256.NewInt(uint64(len(sig))).Bytes())...)
	settleInput = append(settleInput, padRight32(sig)...)

	ret, _, err = Precompile.Run(as, caller, ContractAddress, settleInput, 1_000_000, false)
	require.NoError(t, err)
	require.Equal(t, op, common.BytesToAddress(ret[12:32]))

	// Replay via dispatch rejected.
	_, _, err = Precompile.Run(as, caller, ContractAddress, settleInput, 1_000_000, false)
	require.ErrorIs(t, err, ErrAlreadySettled)
}

func TestRunUnknownSelector(t *testing.T) {
	as := newAS()
	_, _, err := Precompile.Run(as, caller, ContractAddress, selBytes(0xDEADBEEF), 1_000_000, false)
	require.ErrorIs(t, err, ErrUnknownOp)
}

func TestRunInputTooShort(t *testing.T) {
	as := newAS()
	_, _, err := Precompile.Run(as, caller, ContractAddress, []byte{1, 2, 3}, 1_000_000, false)
	require.ErrorIs(t, err, ErrInputTooShort)
}

func TestRunOutOfGas(t *testing.T) {
	as := newAS()
	// Register needs GasRegisterOffering (20k); supply less.
	_, _, err := Precompile.Run(as, operator, ContractAddress, encReg(model, 1, 1), 10, false)
	require.ErrorIs(t, err, contract.ErrOutOfGas)
}

func TestRunGetCredit(t *testing.T) {
	as := newAS()
	fund(as.db, caller, 100_000_000_000)
	_, _, err := Precompile.Run(as, operator, ContractAddress, encReg(model, 1_000_000_000, 4096), 1_000_000, false)
	require.NoError(t, err)
	_, _, err = Precompile.Run(as, caller, ContractAddress, encMeterLike(SelectorMeter, operator, model, 2000), 1_000_000, false)
	require.NoError(t, err)

	credInput := append(selBytes(SelectorGetCredit), addrWord(operator)...)
	ret, _, err := Precompile.Run(as, caller, ContractAddress, credInput, 1_000_000, false)
	require.NoError(t, err)
	require.Equal(t, uint64(3_000_000_000), new(uint256.Int).SetBytes(ret).Uint64())
}

func TestRunMalformedAddressWord(t *testing.T) {
	as := newAS()
	// getOffering with a non-zero high byte in the address word.
	bad := selBytes(SelectorGetOffering)
	w := make([]byte, 32)
	w[0] = 0xFF // dirty high byte
	bad = append(bad, w...)
	bad = append(bad, padLeft32(uint256.NewInt(uint64(len(model))).Bytes())...)
	bad = append(bad, padRight32(model)...)
	_, _, err := Precompile.Run(as, caller, ContractAddress, bad, 1_000_000, false)
	require.Error(t, err)
}

func TestRunDynamicLengthOverrun(t *testing.T) {
	as := newAS()
	// getOffering where the string length claims more bytes than provided.
	bad := selBytes(SelectorGetOffering)
	bad = append(bad, addrWord(operator)...)
	bad = append(bad, padLeft32(uint256.NewInt(9999).Bytes())...) // huge len
	bad = append(bad, []byte("short")...)
	_, _, err := Precompile.Run(as, caller, ContractAddress, bad, 1_000_000, false)
	require.ErrorIs(t, err, ErrInputTooShort)
}

// ===========================================================================
// RequiredGas + module wiring
// ===========================================================================

func TestRequiredGas(t *testing.T) {
	for _, tc := range []struct {
		sel uint32
		gas uint64
	}{
		{SelectorRegisterOffering, GasRegisterOffering},
		{SelectorGetOffering, GasGetOffering},
		{SelectorMeter, GasMeter},
		{SelectorWithdraw, GasWithdraw},
		{SelectorRequestInference, GasRequestInference},
		{SelectorSettleInference, GasSettleInference},
		{SelectorGetCredit, GasGetCredit},
		{SelectorGetRequest, GasGetRequest},
		{0xDEADBEEF, GasGetOffering},
	} {
		require.Equal(t, tc.gas, Precompile.RequiredGas(selBytes(tc.sel)))
	}
	require.Equal(t, GasGetOffering, Precompile.RequiredGas([]byte{1}))
}

func TestModuleWiring(t *testing.T) {
	require.Equal(t, ConfigKey, Module.ConfigKey)
	require.Equal(t, ContractAddress, Module.Address)

	c := &configurator{}
	cfg := c.MakeConfig()
	require.Equal(t, ConfigKey, cfg.Key())
	require.NoError(t, c.Configure(mockChainCfg{}, cfg, newMockStateDB(), mockBlockCtx{}))
}

func TestConfigLifecycle(t *testing.T) {
	cfg := &Config{}
	require.Equal(t, ConfigKey, cfg.Key())
	require.Nil(t, cfg.Timestamp())
	require.False(t, cfg.IsDisabled())
	require.NoError(t, cfg.Verify(mockChainCfg{}))
	require.True(t, cfg.Equal(&Config{}))

	ts := uint64(42)
	cfg2 := &Config{Upgrade: precompileconfig.Upgrade{BlockTimestamp: &ts}}
	require.Equal(t, &ts, cfg2.Timestamp())
	require.False(t, cfg.Equal(cfg2))

	dis := &Config{Upgrade: precompileconfig.Upgrade{Disable: true}}
	require.True(t, dis.IsDisabled())
}

func TestDefaultAttestRejectsBadSigLen(t *testing.T) {
	require.False(t, DefaultAttest(operator, common.HexToHash("0x1"), make([]byte, 10)))
	require.False(t, DefaultAttest(operator, common.HexToHash("0x1"), nil))
}
