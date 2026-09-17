// Copyright (C) 2026, Hanzo AI Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package aiquorum

import (
	"context"
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
// Balance-tracking mock harness (mirrors aimarket's) with a settable block
// height so commit/reveal/settle WINDOWS can be driven deterministically.
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

// mockBlockCtx carries a mutable height so tests can advance the chain.
type mockBlockCtx struct{ n uint64 }

func (b *mockBlockCtx) Number() *big.Int                                       { return new(big.Int).SetUint64(b.n) }
func (b *mockBlockCtx) Timestamp() uint64                                      { return 1000 + b.n }
func (b *mockBlockCtx) GetPredicateResults(common.Hash, common.Address) []byte { return nil }

type mockChainCfg struct{}

func (mockChainCfg) IsDurango(uint64) bool { return true }

type mockEnv struct{}

func (mockEnv) ReadOnly() bool { return false }

type mockAccessibleState struct {
	db  *mockStateDB
	blk *mockBlockCtx
}

func (a *mockAccessibleState) GetStateDB() contract.StateDB                 { return a.db }
func (a *mockAccessibleState) GetBlockContext() contract.BlockContext       { return a.blk }
func (a *mockAccessibleState) GetConsensusContext() context.Context         { return context.Background() }
func (a *mockAccessibleState) GetChainConfig() precompileconfig.ChainConfig { return mockChainCfg{} }
func (a *mockAccessibleState) GetPrecompileEnv() contract.PrecompileEnvironment {
	return mockEnv{}
}

var _ contract.AccessibleState = (*mockAccessibleState)(nil)

func newAS() *mockAccessibleState {
	return &mockAccessibleState{db: newMockStateDB(), blk: &mockBlockCtx{n: 1}}
}

func fund(db *mockStateDB, a common.Address, wei *uint256.Int) {
	db.balance[a] = new(uint256.Int).Set(wei)
}

// wei builds a small uint256 balance from a plain integer (sub-1e18 amounts).
func wei(n uint64) *uint256.Int { return uint256.NewInt(n) }

// opAddr builds a deterministic operator address from an index (readable in
// failures and stable across runs — selection determinism depends on stable
// addresses, not random keys).
func opAddr(i int) common.Address {
	var a common.Address
	a[0] = 0x0e
	binary.BigEndian.PutUint32(a[16:20], uint32(i))
	return a
}

var (
	requester = common.HexToAddress("0x4e90e57000000000000000000000000000000A11")
	spec1     = common.HexToHash("0x1111111111111111111111111111111111111111111111111111111111111111")
	prompt1   = common.HexToHash("0x2222222222222222222222222222222222222222222222222222222222222222")
)

// 1e18-scale helpers keep the numbers readable.
func tokens(n uint64) *uint256.Int {
	return new(uint256.Int).Mul(uint256.NewInt(n), uint256.NewInt(1_000_000_000_000_000_000))
}

// registerN registers `count` operators each advertising `spec` with `stake`,
// funding them first. Returns their addresses in registration order.
func registerN(t *testing.T, db *mockStateDB, lg Ledger, spec common.Hash, count int, stake *uint256.Int) []common.Address {
	t.Helper()
	ops := make([]common.Address, count)
	for i := range count {
		op := opAddr(i)
		ops[i] = op
		db.balance[op] = new(uint256.Int).Add(stake, tokens(1)) // stake + spare
		require.NoError(t, RegisterOperator(db, lg, op, stake, spec, common.HexToHash("0xabc")))
	}
	return ops
}

// ===========================================================================
// ModelSpec + commit wire-spec hashes (byte-exact — Blue-2 verifies against these)
// ===========================================================================

func TestComputeModelSpecHashByteLayout(t *testing.T) {
	s := ModelSpec{
		ModelID:            "zen-coder-flash",
		ModelHash:          common.HexToHash("0xaa"),
		TokenizerHash:      common.HexToHash("0xbb"),
		RuntimeVersion:     "vllm-0.6.3",
		SamplingHash:       common.HexToHash("0xcc"),
		PromptTemplateHash: common.HexToHash("0xdd"),
		EmbeddingModelHash: common.HexToHash("0xee"),
	}
	got := ComputeModelSpecHash(s)

	// Reconstruct the preimage independently from the wire spec and hash it; the
	// two MUST agree, pinning the exact byte layout (4-byte BE length prefix for
	// the two strings, fixed 32-byte hashes, this exact order).
	var lp [4]byte
	var pre []byte
	binary.BigEndian.PutUint32(lp[:], uint32(len(s.ModelID)))
	pre = append(pre, lp[:]...)
	pre = append(pre, s.ModelID...)
	pre = append(pre, s.ModelHash.Bytes()...)
	pre = append(pre, s.TokenizerHash.Bytes()...)
	binary.BigEndian.PutUint32(lp[:], uint32(len(s.RuntimeVersion)))
	pre = append(pre, lp[:]...)
	pre = append(pre, s.RuntimeVersion...)
	pre = append(pre, s.SamplingHash.Bytes()...)
	pre = append(pre, s.PromptTemplateHash.Bytes()...)
	pre = append(pre, s.EmbeddingModelHash.Bytes()...)
	require.Equal(t, 4+len(s.ModelID)+32+32+4+len(s.RuntimeVersion)+32+32+32, len(pre))
	want := common.BytesToHash(keccak(pre))
	require.Equal(t, want, got)

	// Field-order sensitivity: swapping two distinct hash fields changes the hash.
	s2 := s
	s2.SamplingHash, s2.PromptTemplateHash = s.PromptTemplateHash, s.SamplingHash
	require.NotEqual(t, got, ComputeModelSpecHash(s2))

	// String-length-prefix sensitivity: "ab"+"c" vs "a"+"bc" must differ even
	// though concatenated bytes are identical (the length prefix disambiguates).
	a := ModelSpec{ModelID: "ab", RuntimeVersion: "c"}
	b := ModelSpec{ModelID: "a", RuntimeVersion: "bc"}
	require.NotEqual(t, ComputeModelSpecHash(a), ComputeModelSpecHash(b))
}

func TestComputeCommitByteLayout(t *testing.T) {
	jobID := common.HexToHash("0x10")
	output := common.HexToHash("0xbeef")
	embed := common.HexToHash("0xf00d")
	nonce := common.HexToHash("0x99")
	op := opAddr(7)

	got := ComputeCommit(jobID, spec1, prompt1, output, embed, op, nonce)

	var pre []byte
	pre = append(pre, jobID.Bytes()...)
	pre = append(pre, spec1.Bytes()...)
	pre = append(pre, prompt1.Bytes()...)
	pre = append(pre, output.Bytes()...)
	pre = append(pre, embed.Bytes()...)
	pre = append(pre, op.Bytes()...)
	pre = append(pre, nonce.Bytes()...)
	require.Equal(t, 32*5+20+32, len(pre))
	require.Equal(t, common.BytesToHash(keccak(pre)), got)

	// Operator-binding: same (output,embed,nonce) but a DIFFERENT operator yields
	// a different commit. This is the anti-copy property.
	other := ComputeCommit(jobID, spec1, prompt1, output, embed, opAddr(8), nonce)
	require.NotEqual(t, got, other)
}

// ===========================================================================
// Operator registry: register / stake / eligibility / deregister / withdraw
// ===========================================================================

func TestRegisterOperatorBondsStake(t *testing.T) {
	db := newMockStateDB()
	lg := newLedger(db)
	op := opAddr(1)
	fund(db, op, tokens(5)) // 5 tokens

	require.NoError(t, RegisterOperator(db, lg, op, tokens(2), spec1, common.HexToHash("0xe")))

	exists, unbonding, stake, gotSpec, _ := GetOperator(db, op)
	require.True(t, exists)
	require.False(t, unbonding)
	require.Equal(t, tokens(2), stake)
	require.Equal(t, spec1, gotSpec)

	// Stake moved into escrow.
	require.Equal(t, tokens(2).Uint64(), db.GetBalance(ContractAddress).Uint64())
	require.Equal(t, tokens(3).Uint64(), db.GetBalance(op).Uint64())
}

func TestRegisterOperatorRejectsBelowMinStake(t *testing.T) {
	db := newMockStateDB()
	lg := newLedger(db)
	op := opAddr(1)
	fund(db, op, tokens(5))
	below := new(uint256.Int).Sub(MinStake, uint256.NewInt(1))
	require.ErrorIs(t, RegisterOperator(db, lg, op, below, spec1, common.Hash{}), ErrStakeBelowMin)
	// Fail-closed: no escrow, no record.
	require.Zero(t, db.GetBalance(ContractAddress).Uint64())
	exists, _, _, _, _ := GetOperator(db, op)
	require.False(t, exists)
}

func TestRegisterOperatorRejectsEmptySpecAndDouble(t *testing.T) {
	db := newMockStateDB()
	lg := newLedger(db)
	op := opAddr(1)
	fund(db, op, tokens(10))
	require.ErrorIs(t, RegisterOperator(db, lg, op, tokens(2), common.Hash{}, common.Hash{}), ErrEmptyModelSpec)
	require.NoError(t, RegisterOperator(db, lg, op, tokens(2), spec1, common.Hash{}))
	// Double-register rejected (fail-closed; no second pull).
	require.ErrorIs(t, RegisterOperator(db, lg, op, tokens(2), spec1, common.Hash{}), ErrOperatorExists)
	require.Equal(t, tokens(2).Uint64(), db.GetBalance(ContractAddress).Uint64())
}

func TestRegisterOperatorInsufficientFundsFailsClosed(t *testing.T) {
	db := newMockStateDB()
	lg := newLedger(db)
	op := opAddr(1)
	fund(db, op, wei(1)) // way below stake
	require.ErrorIs(t, RegisterOperator(db, lg, op, tokens(2), spec1, common.Hash{}), ErrInsufficientFunds)
	require.Equal(t, uint64(1), db.GetBalance(op).Uint64())
	require.Zero(t, db.GetBalance(ContractAddress).Uint64())
}

func TestDeregisterAndWithdrawStakeCooldown(t *testing.T) {
	db := newMockStateDB()
	lg := newLedger(db)
	op := opAddr(1)
	fund(db, op, tokens(10))
	require.NoError(t, RegisterOperator(db, lg, op, tokens(2), spec1, common.Hash{}))

	// Withdraw before deregister → rejected.
	_, err := WithdrawStake(db, lg, op, 5)
	require.ErrorIs(t, err, ErrOperatorUnbonding)

	require.NoError(t, DeregisterOperator(db, op, 100))
	// Double-deregister rejected.
	require.ErrorIs(t, DeregisterOperator(db, op, 100), ErrOperatorUnbonding)

	// Within cooldown → rejected.
	_, err = WithdrawStake(db, lg, op, 100+UnbondCooldownBlocks-1)
	require.ErrorIs(t, err, ErrCooldownActive)

	// After cooldown → stake returned, record cleared.
	opStart := db.GetBalance(op).Uint64()
	paid, err := WithdrawStake(db, lg, op, 100+UnbondCooldownBlocks)
	require.NoError(t, err)
	require.Equal(t, tokens(2).Uint64(), paid.Uint64())
	require.Equal(t, opStart+tokens(2).Uint64(), db.GetBalance(op).Uint64())
	require.Zero(t, db.GetBalance(ContractAddress).Uint64())
	exists, _, _, _, _ := GetOperator(db, op)
	require.False(t, exists)
}

// ===========================================================================
// Deterministic selection (beacon) — reproducible + eligibility-filtered
// ===========================================================================

func TestSelectionIsDeterministicAndReproducible(t *testing.T) {
	db := newMockStateDB()
	lg := newLedger(db)
	registerN(t, db, lg, spec1, 10, tokens(2))

	jobID := common.HexToHash("0xdecafbad")

	// Same inputs → same selection, every time.
	s1, err := selectOperators(db, jobID, spec1, 5)
	require.NoError(t, err)
	s2, err := selectOperators(db, jobID, spec1, 5)
	require.NoError(t, err)
	require.Equal(t, s1, s2, "selection must be deterministic")

	// Distinct (no duplicate operators selected).
	seen := map[common.Address]bool{}
	for _, op := range s1 {
		require.False(t, seen[op], "operator selected twice")
		seen[op] = true
	}
	require.Len(t, s1, 5)

	// A different job_id → (generally) a different draw.
	s3, err := selectOperators(db, common.HexToHash("0xfeedface"), spec1, 5)
	require.NoError(t, err)
	require.NotEqual(t, s1, s3, "different beacon should reshuffle")

	// Anyone can REPRODUCE the exact set by re-running the public algorithm over
	// the same eligible set in insertion order. Reimplement it here independently.
	reproduced := reproduceSelection(t, db, jobID, spec1, 5)
	require.Equal(t, s1, reproduced, "selection must be reproducible by a third party")
}

// reproduceSelection re-derives the selected set using ONLY public data (the
// per-ModelSpec operator array + the documented Fisher–Yates beacon), proving an
// external verifier reaches the identical set.
func reproduceSelection(t *testing.T, db StateDB, jobID, spec common.Hash, n uint32) []common.Address {
	t.Helper()
	total := modelCount(db, spec)
	eligible := make([]common.Address, 0, total)
	for i := range total {
		op := modelMember(db, spec, i)
		exists, unbonding, stake, _, _ := GetOperator(db, op)
		if !exists || unbonding || stake.Lt(MinStake) {
			continue
		}
		eligible = append(eligible, op)
	}
	for i := range n {
		span := uint64(len(eligible)) - uint64(i)
		var ib [4]byte
		binary.BigEndian.PutUint32(ib[:], i)
		draw := new(uint256.Int).SetBytes(keccak(jobID.Bytes(), ib[:]))
		j := i + uint32(new(uint256.Int).Mod(draw, uint256.NewInt(span)).Uint64())
		eligible[i], eligible[j] = eligible[j], eligible[i]
	}
	return eligible[:n]
}

func TestSelectionSkipsIneligibleOperators(t *testing.T) {
	db := newMockStateDB()
	lg := newLedger(db)
	ops := registerN(t, db, lg, spec1, 5, tokens(2))

	// Deregister two: they remain in the array but must be excluded from selection.
	require.NoError(t, DeregisterOperator(db, ops[0], 1))
	require.NoError(t, DeregisterOperator(db, ops[1], 1))

	// Now only 3 eligible; selecting 4 must fail.
	_, err := selectOperators(db, common.HexToHash("0x1"), spec1, 4)
	require.ErrorIs(t, err, ErrNotEnoughEligible)

	// Selecting 3 succeeds and never returns a deregistered operator.
	sel, err := selectOperators(db, common.HexToHash("0x1"), spec1, 3)
	require.NoError(t, err)
	for _, s := range sel {
		require.NotEqual(t, ops[0], s)
		require.NotEqual(t, ops[1], s)
	}
}

func TestRequestRejectsNotEnoughEligibleNoMoneyMoved(t *testing.T) {
	db := newMockStateDB()
	lg := newLedger(db)
	registerN(t, db, lg, spec1, 2, tokens(2)) // only 2 eligible
	fund(db, requester, tokens(100))

	start := db.GetBalance(requester).Uint64()
	_, err := RequestInference(db, lg, requester, spec1, prompt1, 5, 3, tokens(1), 10)
	require.ErrorIs(t, err, ErrNotEnoughEligible)
	// Selection runs before escrow → requester untouched.
	require.Equal(t, start, db.GetBalance(requester).Uint64())
}

// ===========================================================================
// Threshold rule (reject weak quora)
// ===========================================================================

func TestThresholdRule(t *testing.T) {
	db := newMockStateDB()
	lg := newLedger(db)
	registerN(t, db, lg, spec1, 16, tokens(2))
	fund(db, requester, tokens(1000))

	// N=5: minThreshold = 3. threshold 2 rejected, 3 accepted, 6 (>N) rejected.
	_, err := RequestInference(db, lg, requester, spec1, prompt1, 5, 2, tokens(1), 10)
	require.ErrorIs(t, err, ErrBadThreshold)
	_, err = RequestInference(db, lg, requester, spec1, prompt1, 5, 6, tokens(1), 10)
	require.ErrorIs(t, err, ErrBadThreshold)
	_, err = RequestInference(db, lg, requester, spec1, prompt1, 5, 3, tokens(1), 10)
	require.NoError(t, err)

	// N=4: minThreshold = 3 (floor(4/2)+1). threshold 2 rejected, 3 accepted.
	_, err = RequestInference(db, lg, requester, spec1, prompt1, 4, 2, tokens(1), 10)
	require.ErrorIs(t, err, ErrBadThreshold)
	_, err = RequestInference(db, lg, requester, spec1, prompt1, 4, 3, tokens(1), 10)
	require.NoError(t, err)

	// N=0 and N>maxN rejected.
	_, err = RequestInference(db, lg, requester, spec1, prompt1, 0, 0, tokens(1), 10)
	require.ErrorIs(t, err, ErrBadN)
	_, err = RequestInference(db, lg, requester, spec1, prompt1, maxN+1, maxN, tokens(1), 10)
	require.ErrorIs(t, err, ErrBadN)

	// Trivial self-quorums forbidden: N=1 (1-of-1 needs no agreement) and N=2
	// (too small) are rejected even with a "valid" threshold. minN = 3.
	_, err = RequestInference(db, lg, requester, spec1, prompt1, 1, 1, tokens(1), 10)
	require.ErrorIs(t, err, ErrBadN, "1-of-1 self-quorum must be rejected")
	_, err = RequestInference(db, lg, requester, spec1, prompt1, 2, 2, tokens(1), 10)
	require.ErrorIs(t, err, ErrBadN, "2-of-2 quorum is too small")
	// N=3, threshold=2 (smallest legitimate quorum) is accepted.
	_, err = RequestInference(db, lg, requester, spec1, prompt1, 3, 2, tokens(1), 10)
	require.NoError(t, err)
}

// TestSettleZeroRevealsFailsAndSlashesAll covers the edge where the commit
// window had commits but NOBODY revealed: job Failed, all committers slashed, and
// the requester is refunded escrow + the full slash pool.
func TestSettleZeroRevealsFailsAndSlashesAll(t *testing.T) {
	db := newMockStateDB()
	lg := newLedger(db)
	jobID, sel := setupJob(t, db, lg, 5, 5, 3, tokens(1), 10)

	// All 5 commit, none reveal.
	for i := range 5 {
		nonce := common.BigToHash(big.NewInt(int64(700 + i)))
		require.NoError(t, commitFor(t, db, jobID, sel[i], common.HexToHash("0x0a55"), common.HexToHash("0x0e3b"), nonce, 12))
	}

	res, err := Settle(db, lg, jobID, 10+CommitBlocks+RevealBlocks+1)
	require.NoError(t, err)
	require.Equal(t, JobFailed, res.Status)
	require.Equal(t, common.Hash{}, res.CanonicalHash)
	// All 5 slashed.
	require.Equal(t, new(uint256.Int).Mul(SlashPerOperator, uint256.NewInt(5)).Uint64(), res.Slashed.Uint64())
	// Requester refunded escrow (5 tokens) + full slash pool (5 * SlashPerOperator).
	want := new(uint256.Int).Add(tokens(5), new(uint256.Int).Mul(SlashPerOperator, uint256.NewInt(5)))
	require.Equal(t, want.Uint64(), GetCredit(db, requester).Uint64())
}

func TestRequestEscrowsReward(t *testing.T) {
	db := newMockStateDB()
	lg := newLedger(db)
	nOps := 7 // N + requiredMargin(5) = 5 + 2
	registerN(t, db, lg, spec1, nOps, tokens(2))
	fund(db, requester, tokens(1000))

	stakeEscrow := db.GetBalance(ContractAddress).Uint64() // nOps * 2 tokens
	start := db.GetBalance(requester).Uint64()
	burnStart := db.GetBalance(BurnAddress).Uint64()

	_, err := RequestInference(db, lg, requester, spec1, prompt1, 5, 3, tokens(1), 10)
	require.NoError(t, err)

	// Requester debited N*reward (5 tokens, escrowed) PLUS the non-refundable
	// N*RequestFeePerOperator fee (burned). Escrow account grows ONLY by the
	// refundable reward (the fee nets to zero on it); the fee lands at BurnAddress.
	fee := new(uint256.Int).Mul(RequestFeePerOperator, uint256.NewInt(5))
	require.Equal(t, start-tokens(5).Uint64()-fee.Uint64(), db.GetBalance(requester).Uint64(),
		"requester debited reward escrow + burned fee")
	require.Equal(t, stakeEscrow+tokens(5).Uint64(), db.GetBalance(ContractAddress).Uint64(),
		"escrow account grows only by the refundable reward; fee nets to zero on it")
	require.Equal(t, burnStart+fee.Uint64(), db.GetBalance(BurnAddress).Uint64(),
		"fee burned to BurnAddress")
}

// ===========================================================================
// Commit window
// ===========================================================================

// setupJob registers operators and opens a job at block `reqBlock`, returning the
// job id and the selected operators. It registers max(nOps, N + requiredMargin(N))
// operators so the RED-A eligible-set margin is always satisfied — extra operators
// beyond N are never selected (the beacon picks exactly N) and never commit, so
// they are inert for the quorum/slash/pay mechanics these helper-driven tests
// exercise; they exist only to give the request a legal pool. Tests that probe the
// margin or selection economics directly do NOT use this helper.
func setupJob(t *testing.T, db *mockStateDB, lg Ledger, nOps int, n, threshold uint32, reward *uint256.Int, reqBlock uint64) (common.Hash, []common.Address) {
	t.Helper()
	if min := int(n + requiredMargin(n)); nOps < min {
		nOps = min
	}
	registerN(t, db, lg, spec1, nOps, tokens(2))
	fund(db, requester, tokens(1000))
	jobID, err := RequestInference(db, lg, requester, spec1, prompt1, n, threshold, reward, reqBlock)
	require.NoError(t, err)
	// Enumerate the selected set from the on-chain sel-list.
	sel := make([]common.Address, n)
	for i := range n {
		sel[i] = SelectedAt(db, jobID, i)
		require.True(t, IsSelected(db, jobID, sel[i]))
	}
	return jobID, sel
}

// commitFor builds a valid commit for op and submits it at the given block.
func commitFor(t *testing.T, db StateDB, jobID common.Hash, op common.Address, output, embed, nonce common.Hash, block uint64) error {
	t.Helper()
	commit := ComputeCommit(jobID, spec1, prompt1, output, embed, op, nonce)
	return CommitResponse(db, jobID, op, commit, block)
}

func TestCommitWithinWindow(t *testing.T) {
	db := newMockStateDB()
	lg := newLedger(db)
	jobID, sel := setupJob(t, db, lg, 5, 5, 3, tokens(1), 10)
	// commitDeadline = 10 + CommitBlocks.
	deadline := 10 + CommitBlocks

	out := common.HexToHash("0xabc")
	// At deadline → ok.
	require.NoError(t, commitFor(t, db, jobID, sel[0], out, common.HexToHash("0x1"), common.HexToHash("0x2"), deadline))
	// After deadline → rejected.
	require.ErrorIs(t, commitFor(t, db, jobID, sel[1], out, common.HexToHash("0x1"), common.HexToHash("0x2"), deadline+1), ErrCommitClosed)
}

func TestCommitOnlySelected(t *testing.T) {
	db := newMockStateDB()
	lg := newLedger(db)
	jobID, _ := setupJob(t, db, lg, 6, 5, 3, tokens(1), 10)

	// Find an operator NOT selected.
	var outsider common.Address
	for i := range 6 {
		op := opAddr(i)
		if !IsSelected(db, jobID, op) {
			outsider = op
			break
		}
	}
	require.NotEqual(t, common.Address{}, outsider, "expected one non-selected operator with N=5 of 6")
	require.ErrorIs(t, commitFor(t, db, jobID, outsider, common.HexToHash("0x1"), common.HexToHash("0x2"), common.HexToHash("0x3"), 12), ErrNotSelected)
}

func TestDoubleCommitRejected(t *testing.T) {
	db := newMockStateDB()
	lg := newLedger(db)
	jobID, sel := setupJob(t, db, lg, 5, 5, 3, tokens(1), 10)
	out := common.HexToHash("0xabc")
	require.NoError(t, commitFor(t, db, jobID, sel[0], out, common.HexToHash("0x1"), common.HexToHash("0x2"), 12))
	require.ErrorIs(t, commitFor(t, db, jobID, sel[0], out, common.HexToHash("0x9"), common.HexToHash("0x8"), 12), ErrAlreadyCommitted)
}

func TestCommitEmptyRejected(t *testing.T) {
	db := newMockStateDB()
	lg := newLedger(db)
	jobID, sel := setupJob(t, db, lg, 5, 5, 3, tokens(1), 10)
	require.ErrorIs(t, CommitResponse(db, jobID, sel[0], common.Hash{}, 12), ErrEmptyCommit)
}

func TestCommitUnknownJob(t *testing.T) {
	db := newMockStateDB()
	require.ErrorIs(t, CommitResponse(db, common.HexToHash("0xdead"), opAddr(1), common.HexToHash("0x1"), 12), ErrJobUnknown)
}

// ===========================================================================
// Reveal window + commit binding (the core anti-cheat)
// ===========================================================================

func TestRevealMustMatchCommit(t *testing.T) {
	db := newMockStateDB()
	lg := newLedger(db)
	jobID, sel := setupJob(t, db, lg, 5, 5, 3, tokens(1), 10)
	op := sel[0]
	out := common.HexToHash("0xCAFE")
	embed := common.HexToHash("0xE1")
	nonce := common.HexToHash("0x0a01")

	require.NoError(t, commitFor(t, db, jobID, op, out, embed, nonce, 12))

	revealBlock := 10 + CommitBlocks + 1 // first block of reveal window

	// Tampered output_hash → recomputed commit differs → rejected.
	require.ErrorIs(t, RevealResponse(db, jobID, op, common.HexToHash("0xBEEF"), embed, nonce, revealBlock), ErrCommitMismatch)
	// Tampered embedding → rejected.
	require.ErrorIs(t, RevealResponse(db, jobID, op, out, common.HexToHash("0xE2"), nonce, revealBlock), ErrCommitMismatch)
	// Tampered nonce → rejected.
	require.ErrorIs(t, RevealResponse(db, jobID, op, out, embed, common.HexToHash("0x0a02"), revealBlock), ErrCommitMismatch)
	// Correct preimage → accepted.
	require.NoError(t, RevealResponse(db, jobID, op, out, embed, nonce, revealBlock))
}

func TestRevealWindowBoundaries(t *testing.T) {
	db := newMockStateDB()
	lg := newLedger(db)
	jobID, sel := setupJob(t, db, lg, 5, 5, 3, tokens(1), 10)
	op := sel[0]
	out, embed, nonce := common.HexToHash("0x1"), common.HexToHash("0x2"), common.HexToHash("0x3")
	require.NoError(t, commitFor(t, db, jobID, op, out, embed, nonce, 12))

	commitDeadline := 10 + CommitBlocks
	revealDeadline := commitDeadline + RevealBlocks

	// At commitDeadline reveal is NOT yet open (window opens strictly after).
	require.ErrorIs(t, RevealResponse(db, jobID, op, out, embed, nonce, commitDeadline), ErrRevealNotOpen)
	// After revealDeadline → closed.
	require.ErrorIs(t, RevealResponse(db, jobID, op, out, embed, nonce, revealDeadline+1), ErrRevealClosed)
	// At revealDeadline (inclusive) → accepted.
	require.NoError(t, RevealResponse(db, jobID, op, out, embed, nonce, revealDeadline))
}

func TestRevealRequiresCommit(t *testing.T) {
	db := newMockStateDB()
	lg := newLedger(db)
	jobID, sel := setupJob(t, db, lg, 5, 5, 3, tokens(1), 10)
	op := sel[0]
	revealBlock := 10 + CommitBlocks + 1
	// Never committed → reveal rejected.
	require.ErrorIs(t, RevealResponse(db, jobID, op, common.HexToHash("0x1"), common.HexToHash("0x2"), common.HexToHash("0x3"), revealBlock), ErrNotCommitted)
}

func TestDoubleRevealRejected(t *testing.T) {
	db := newMockStateDB()
	lg := newLedger(db)
	jobID, sel := setupJob(t, db, lg, 5, 5, 3, tokens(1), 10)
	op := sel[0]
	out, embed, nonce := common.HexToHash("0x1"), common.HexToHash("0x2"), common.HexToHash("0x3")
	require.NoError(t, commitFor(t, db, jobID, op, out, embed, nonce, 12))
	revealBlock := 10 + CommitBlocks + 1
	require.NoError(t, RevealResponse(db, jobID, op, out, embed, nonce, revealBlock))
	require.ErrorIs(t, RevealResponse(db, jobID, op, out, embed, nonce, revealBlock), ErrAlreadyRevealed)
}

// ===========================================================================
// Full happy path: N=5, threshold=3, 3 agree, 2 withhold → settle
// ===========================================================================

func TestHappyPathQuorumSettles(t *testing.T) {
	db := newMockStateDB()
	lg := newLedger(db)
	jobID, sel := setupJob(t, db, lg, 5, 5, 3, tokens(1), 10)

	canonicalOut := common.HexToHash("0x0a60") // the agreed answer hash
	embed := common.HexToHash("0x0e3b")

	// Operators 0,1,2 commit+reveal the SAME output_hash (the agreeing majority).
	// Each uses a distinct nonce (commit is operator+nonce bound).
	commitBlock := uint64(12)
	revealBlock := 10 + CommitBlocks + 1
	for i := range 3 {
		nonce := common.BigToHash(big.NewInt(int64(100 + i)))
		require.NoError(t, commitFor(t, db, jobID, sel[i], canonicalOut, embed, nonce, commitBlock))
	}
	// Operators 3,4 commit (a different answer) but DO NOT reveal (withholders).
	for i := 3; i < 5; i++ {
		nonce := common.BigToHash(big.NewInt(int64(100 + i)))
		require.NoError(t, commitFor(t, db, jobID, sel[i], common.HexToHash("0x0d15"), embed, nonce, commitBlock))
	}
	for i := range 3 {
		nonce := common.BigToHash(big.NewInt(int64(100 + i)))
		require.NoError(t, RevealResponse(db, jobID, sel[i], canonicalOut, embed, nonce, revealBlock))
	}

	// Settle after the reveal window.
	settleBlock := 10 + CommitBlocks + RevealBlocks + 1
	res, err := Settle(db, lg, jobID, settleBlock)
	require.NoError(t, err)
	require.Equal(t, JobSettled, res.Status)
	require.Equal(t, canonicalOut, res.CanonicalHash)
	require.Equal(t, uint32(3), res.WinnerCount)

	// Canonical result recorded on-chain.
	require.Equal(t, canonicalOut, GetCanonicalResult(db, jobID))
	require.Equal(t, JobSettled, GetJob(db, jobID).Status)

	// 3 winners each got >= rewardPerOperator credit (reward + slashed-pool share).
	for i := range 3 {
		require.GreaterOrEqual(t, GetCredit(db, sel[i]).Uint64(), tokens(1).Uint64(),
			"winner %d must be paid at least the reward", i)
	}

	// 2 withholders slashed: stake reduced by SlashPerOperator.
	for i := 3; i < 5; i++ {
		_, _, stake, _, _ := GetOperator(db, sel[i])
		require.Equal(t, new(uint256.Int).Sub(tokens(2), SlashPerOperator).Uint64(), stake.Uint64(),
			"withholder %d must be slashed", i)
	}
	// Slashed total = 2 * SlashPerOperator.
	require.Equal(t, new(uint256.Int).Mul(SlashPerOperator, uint256.NewInt(2)).Uint64(), res.Slashed.Uint64())

	// The slashed pool (0.2 token) is split among 3 winners (0.066.. each) with
	// the remainder refunded to the requester; total reward paid >= 3 tokens.
	require.GreaterOrEqual(t, res.Paid.Uint64(), tokens(3).Uint64())
}

// ===========================================================================
// No quorum → Failed + refund
// ===========================================================================

func TestNoQuorumFailsAndRefunds(t *testing.T) {
	db := newMockStateDB()
	lg := newLedger(db)
	jobID, sel := setupJob(t, db, lg, 5, 5, 3, tokens(1), 10)

	commitBlock := uint64(12)
	revealBlock := 10 + CommitBlocks + 1

	// 5 operators reveal 5 DIFFERENT hashes → no group reaches threshold 3.
	for i := range 5 {
		nonce := common.BigToHash(big.NewInt(int64(200 + i)))
		out := common.BigToHash(big.NewInt(int64(900 + i))) // all distinct
		require.NoError(t, commitFor(t, db, jobID, sel[i], out, common.HexToHash("0xE"), nonce, commitBlock))
		require.NoError(t, RevealResponse(db, jobID, sel[i], out, common.HexToHash("0xE"), nonce, revealBlock))
	}

	reqBefore := db.GetBalance(requester).Uint64()
	creditBefore := GetCredit(db, requester).Uint64()

	settleBlock := 10 + CommitBlocks + RevealBlocks + 1
	res, err := Settle(db, lg, jobID, settleBlock)
	require.NoError(t, err)
	require.Equal(t, JobFailed, res.Status)
	require.Equal(t, common.Hash{}, res.CanonicalHash)
	require.Equal(t, uint32(0), res.WinnerCount)

	// No canonical result.
	require.Equal(t, common.Hash{}, GetCanonicalResult(db, jobID))

	// Full escrow (5 tokens) refunded to requester's credit. No one was slashed
	// (all revealed), so slashed pool is zero.
	require.Zero(t, res.Slashed.Uint64())
	require.Equal(t, creditBefore+tokens(5).Uint64(), GetCredit(db, requester).Uint64())
	_ = reqBefore

	// Requester can withdraw the refund.
	paid, err := WithdrawRewards(db, lg, requester)
	require.NoError(t, err)
	require.Equal(t, tokens(5).Uint64(), paid.Uint64())
}

func TestNoQuorumSlashesWithholdersCompensatesRequester(t *testing.T) {
	db := newMockStateDB()
	lg := newLedger(db)
	jobID, sel := setupJob(t, db, lg, 5, 5, 3, tokens(1), 10)

	commitBlock := uint64(12)
	revealBlock := 10 + CommitBlocks + 1

	// 2 operators reveal distinct hashes (no quorum); 3 commit but withhold.
	for i := range 2 {
		nonce := common.BigToHash(big.NewInt(int64(300 + i)))
		out := common.BigToHash(big.NewInt(int64(800 + i)))
		require.NoError(t, commitFor(t, db, jobID, sel[i], out, common.HexToHash("0xE"), nonce, commitBlock))
		require.NoError(t, RevealResponse(db, jobID, sel[i], out, common.HexToHash("0xE"), nonce, revealBlock))
	}
	for i := 2; i < 5; i++ {
		nonce := common.BigToHash(big.NewInt(int64(300 + i)))
		require.NoError(t, commitFor(t, db, jobID, sel[i], common.HexToHash("0x012e"), common.HexToHash("0xE"), nonce, commitBlock))
	}

	settleBlock := 10 + CommitBlocks + RevealBlocks + 1
	res, err := Settle(db, lg, jobID, settleBlock)
	require.NoError(t, err)
	require.Equal(t, JobFailed, res.Status)

	// 3 withholders slashed.
	require.Equal(t, new(uint256.Int).Mul(SlashPerOperator, uint256.NewInt(3)).Uint64(), res.Slashed.Uint64())
	// Requester refunded escrow (5 tokens) + slashed pool (0.3 token).
	want := new(uint256.Int).Add(tokens(5), new(uint256.Int).Mul(SlashPerOperator, uint256.NewInt(3)))
	require.Equal(t, want.Uint64(), GetCredit(db, requester).Uint64())
}

// ===========================================================================
// Settle idempotency / replay + timing
// ===========================================================================

func TestSettleTooEarly(t *testing.T) {
	db := newMockStateDB()
	lg := newLedger(db)
	jobID, _ := setupJob(t, db, lg, 5, 5, 3, tokens(1), 10)
	revealDeadline := 10 + CommitBlocks + RevealBlocks
	// At revealDeadline settle is too early (must be strictly after).
	_, err := Settle(db, lg, jobID, revealDeadline)
	require.ErrorIs(t, err, ErrSettleTooEarly)
}

func TestSettleIdempotentReplayRejected(t *testing.T) {
	db := newMockStateDB()
	lg := newLedger(db)
	jobID, sel := setupJob(t, db, lg, 5, 5, 3, tokens(1), 10)
	out := common.HexToHash("0x0a55")
	for i := range 3 {
		nonce := common.BigToHash(big.NewInt(int64(400 + i)))
		require.NoError(t, commitFor(t, db, jobID, sel[i], out, common.HexToHash("0xE"), nonce, 12))
		require.NoError(t, RevealResponse(db, jobID, sel[i], out, common.HexToHash("0xE"), nonce, 10+CommitBlocks+1))
	}
	settleBlock := 10 + CommitBlocks + RevealBlocks + 1
	_, err := Settle(db, lg, jobID, settleBlock)
	require.NoError(t, err)

	creditAfterFirst := GetCredit(db, sel[0]).Uint64()

	// Replay → rejected, no double-pay.
	_, err = Settle(db, lg, jobID, settleBlock)
	require.ErrorIs(t, err, ErrJobAlreadySettled)
	require.Equal(t, creditAfterFirst, GetCredit(db, sel[0]).Uint64(), "replay must not double-pay")
}

func TestSettleUnknownJob(t *testing.T) {
	db := newMockStateDB()
	lg := newLedger(db)
	_, err := Settle(db, lg, common.HexToHash("0xdead"), 9_999_999)
	require.ErrorIs(t, err, ErrJobUnknown)
}

// ===========================================================================
// WithdrawRewards
// ===========================================================================

func TestWithdrawRewards(t *testing.T) {
	db := newMockStateDB()
	lg := newLedger(db)
	jobID, sel := setupJob(t, db, lg, 5, 5, 3, tokens(1), 10)
	out := common.HexToHash("0x0a55")
	for i := range 3 {
		nonce := common.BigToHash(big.NewInt(int64(500 + i)))
		require.NoError(t, commitFor(t, db, jobID, sel[i], out, common.HexToHash("0xE"), nonce, 12))
		require.NoError(t, RevealResponse(db, jobID, sel[i], out, common.HexToHash("0xE"), nonce, 10+CommitBlocks+1))
	}
	_, err := Settle(db, lg, jobID, 10+CommitBlocks+RevealBlocks+1)
	require.NoError(t, err)

	op := sel[0]
	credit := GetCredit(db, op).Uint64()
	require.Positive(t, credit)
	opStart := db.GetBalance(op).Uint64()
	paid, err := WithdrawRewards(db, lg, op)
	require.NoError(t, err)
	require.Equal(t, credit, paid.Uint64())
	require.Equal(t, opStart+credit, db.GetBalance(op).Uint64())
	require.Zero(t, GetCredit(db, op).Uint64())

	// Second withdraw → nothing.
	_, err = WithdrawRewards(db, lg, op)
	require.ErrorIs(t, err, ErrNoCredit)
}

// ===========================================================================
// Value conservation across a full lifecycle (the core economic invariant)
// ===========================================================================

func TestValueConservationFullLifecycle(t *testing.T) {
	db := newMockStateDB()
	lg := newLedger(db)

	// Register 7 operators (N=5 + RED-A margin 2), open a job, run commit/reveal
	// with 3 agreeing + 2 withholding among the 5 selected, settle, then everyone
	// withdraws. The grand total of all balances must be invariant throughout
	// (the burned fee MOVES to BurnAddress — value is not destroyed — so BurnAddress
	// is in the account set), and the escrow must always equal bonded stake + open
	// job escrow + unwithdrawn credit.
	nOps := 7
	registerN(t, db, lg, spec1, nOps, tokens(2))
	fund(db, requester, tokens(1000))

	allAccounts := []common.Address{requester, ContractAddress, BurnAddress}
	for i := range nOps {
		allAccounts = append(allAccounts, opAddr(i))
	}
	total := func() *uint256.Int {
		sum := new(uint256.Int)
		for _, a := range allAccounts {
			sum.Add(sum, db.GetBalance(a))
		}
		return sum
	}
	want := total()

	jobID, err := RequestInference(db, lg, requester, spec1, prompt1, 5, 3, tokens(1), 10)
	require.NoError(t, err)
	require.Equal(t, want.Uint64(), total().Uint64(), "escrow pull conserves value")

	sel := make([]common.Address, 5)
	for i := range uint32(5) {
		sel[i] = SelectedAt(db, jobID, i)
	}

	out := common.HexToHash("0x0a5e")
	for i := range 3 {
		nonce := common.BigToHash(big.NewInt(int64(600 + i)))
		require.NoError(t, commitFor(t, db, jobID, sel[i], out, common.HexToHash("0xE"), nonce, 12))
	}
	for i := 3; i < 5; i++ {
		nonce := common.BigToHash(big.NewInt(int64(600 + i)))
		require.NoError(t, commitFor(t, db, jobID, sel[i], common.HexToHash("0x0e0f"), common.HexToHash("0xE"), nonce, 12))
	}
	for i := range 3 {
		nonce := common.BigToHash(big.NewInt(int64(600 + i)))
		require.NoError(t, RevealResponse(db, jobID, sel[i], out, common.HexToHash("0xE"), nonce, 10+CommitBlocks+1))
	}

	_, err = Settle(db, lg, jobID, 10+CommitBlocks+RevealBlocks+1)
	require.NoError(t, err)
	require.Equal(t, want.Uint64(), total().Uint64(), "settle conserves value")

	// Conservation of escrow accounting: escrow balance == sum(bonded stake) +
	// sum(unwithdrawn credit) (job escrow is now zero after settle). The burned fee
	// is NOT in the escrow account (it moved to BurnAddress), so it does not appear
	// here — confirming the fee leaves the escrow accounting cleanly. Stake is summed
	// over ALL registered operators (the 2 unselected ones still hold bonded stake
	// in the escrow account).
	escrowAcct := db.GetBalance(ContractAddress)
	accounted := new(uint256.Int)
	for _, a := range allAccounts {
		if a == ContractAddress {
			continue
		}
		accounted.Add(accounted, GetCredit(db, a))
	}
	for i := range nOps {
		_, _, stake, _, _ := GetOperator(db, opAddr(i))
		accounted.Add(accounted, stake)
	}
	require.Equal(t, escrowAcct.Uint64(), accounted.Uint64(),
		"escrow == sum(bonded stake) + sum(unwithdrawn credit) after settle")

	// Everyone withdraws rewards; total still conserved.
	for i := range 5 {
		if GetCredit(db, sel[i]).Sign() > 0 {
			_, err := WithdrawRewards(db, lg, sel[i])
			require.NoError(t, err)
		}
	}
	if GetCredit(db, requester).Sign() > 0 {
		_, err := WithdrawRewards(db, lg, requester)
		require.NoError(t, err)
	}
	require.Equal(t, want.Uint64(), total().Uint64(), "withdrawals conserve value")
}

// keccak is the exact hash the package uses; tests reconstruct preimages with it
// so the wire-spec assertions are honest (same function, not a re-implementation).
func keccak(parts ...[]byte) []byte { return crypto.Keccak256(parts...) }
