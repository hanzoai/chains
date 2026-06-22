// Copyright (C) 2026, Hanzo AI Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package aiquorum

import (
	"encoding/binary"
	"math/big"
	"testing"

	"github.com/holiman/uint256"
	"github.com/luxfi/geth/common"
	"github.com/luxfi/precompile/contract"
	"github.com/luxfi/precompile/precompileconfig"
	"github.com/stretchr/testify/require"
)

// ===========================================================================
// Run-dispatcher tests: calldata encode/decode, gas, readOnly, variable-N gas.
// These drive the REAL production evmLedger (newLedger over the StateDB), so the
// accounting + custody path under test is exactly the one the EVM runs.
// ===========================================================================

func selBytes(sel uint32) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, sel)
	return b
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

func addrWord(a common.Address) []byte {
	w := make([]byte, 32)
	copy(w[12:], a.Bytes())
	return w
}

// advance sets the block height the next Run will observe.
func (a *mockAccessibleState) advance(n uint64) { a.blk.n = n }

// run is a thin wrapper that calls Precompile.Run at the AS's current block.
func run(t *testing.T, as *mockAccessibleState, caller common.Address, input []byte, gas uint64, readOnly bool) ([]byte, uint64, error) {
	t.Helper()
	return Precompile.Run(as, caller, ContractAddress, input, gas, readOnly)
}

// encRegister builds calldata for registerOperator(uint256,bytes32,bytes32).
func encRegister(stake *uint256.Int, spec, endpoint common.Hash) []byte {
	out := selBytes(SelectorRegisterOperator)
	out = append(out, h32(stake).Bytes()...)
	out = append(out, spec.Bytes()...)
	out = append(out, endpoint.Bytes()...)
	return out
}

// encRequest builds calldata for requestInference(bytes32,bytes32,uint32,uint32,uint256).
func encRequest(spec, prompt common.Hash, n, threshold uint32, reward *uint256.Int) []byte {
	out := selBytes(SelectorRequestInference)
	out = append(out, spec.Bytes()...)
	out = append(out, prompt.Bytes()...)
	out = append(out, padLeft32Uint32(n)...)
	out = append(out, padLeft32Uint32(threshold)...)
	out = append(out, h32(reward).Bytes()...)
	return out
}

func encCommit(jobID, commit common.Hash) []byte {
	out := selBytes(SelectorCommitResponse)
	out = append(out, jobID.Bytes()...)
	out = append(out, commit.Bytes()...)
	return out
}

func encReveal(jobID, output, embed, nonce common.Hash) []byte {
	out := selBytes(SelectorRevealResponse)
	out = append(out, jobID.Bytes()...)
	out = append(out, output.Bytes()...)
	out = append(out, embed.Bytes()...)
	out = append(out, nonce.Bytes()...)
	return out
}

func encSettle(jobID common.Hash) []byte {
	return append(selBytes(SelectorSettle), jobID.Bytes()...)
}

func TestRunRegisterReadOnlyRejected(t *testing.T) {
	as := newAS()
	_, _, err := run(t, as, opAddr(1), encRegister(tokens(2), spec1, common.Hash{}), 1_000_000, true)
	require.ErrorIs(t, err, ErrReadOnly)
}

func TestRunUnknownSelector(t *testing.T) {
	as := newAS()
	_, _, err := run(t, as, requester, selBytes(0xDEADBEEF), 1_000_000, false)
	require.ErrorIs(t, err, ErrUnknownOp)
}

func TestRunInputTooShort(t *testing.T) {
	as := newAS()
	_, _, err := run(t, as, requester, []byte{1, 2, 3}, 1_000_000, false)
	require.ErrorIs(t, err, ErrInputTooShort)
}

func TestRunOutOfGas(t *testing.T) {
	as := newAS()
	as.db.balance[opAddr(1)] = tokens(5)
	_, _, err := run(t, as, opAddr(1), encRegister(tokens(2), spec1, common.Hash{}), 10, false)
	require.ErrorIs(t, err, contract.ErrOutOfGas)
}

func TestRunMalformedAddressWord(t *testing.T) {
	as := newAS()
	bad := selBytes(SelectorGetOperator)
	w := make([]byte, 32)
	w[0] = 0xFF // dirty high byte
	bad = append(bad, w...)
	_, _, err := run(t, as, requester, bad, 1_000_000, false)
	require.Error(t, err)
}

func TestRunGetOperatorAndCredit(t *testing.T) {
	as := newAS()
	op := opAddr(1)
	as.db.balance[op] = tokens(5)
	_, _, err := run(t, as, op, encRegister(tokens(2), spec1, common.HexToHash("0xe")), 1_000_000, false)
	require.NoError(t, err)

	ret, _, err := run(t, as, requester, append(selBytes(SelectorGetOperator), addrWord(op)...), 1_000_000, false)
	require.NoError(t, err)
	require.Len(t, ret, 160)
	require.Equal(t, byte(1), ret[31], "exists")
	require.Equal(t, byte(0), ret[63], "not unbonding")
	require.Equal(t, tokens(2).Uint64(), new(uint256.Int).SetBytes(ret[64:96]).Uint64())
	require.Equal(t, spec1, common.BytesToHash(ret[96:128]))
}

// TestRunVariableGasScalesWithN proves the O(N) selection surcharge is charged:
// a larger N consumes strictly more gas through Run.
func TestRunVariableGasScalesWithN(t *testing.T) {
	mk := func(n uint32) uint64 {
		as := newAS()
		// Register comfortably above N + requiredMargin(N) for the largest N tested
		// (N=12 needs >= 18) so the RED-A margin admits both requests.
		registerN(t, as.db, newLedger(as.db), spec1, 20, tokens(2))
		fund(as.db, requester, tokens(1000))
		_, remaining, err := run(t, as, requester, encRequest(spec1, prompt1, n, n/2+1, tokens(1)), 5_000_000, false)
		require.NoError(t, err)
		return 5_000_000 - remaining
	}
	used4 := mk(4)
	used12 := mk(12)
	require.Greater(t, used12, used4, "larger N must cost more gas (per-operator surcharge)")
	// The delta should be ~ (12-4)*GasRequestPerOp.
	require.Equal(t, uint64(12-4)*GasRequestPerOp, used12-used4)
}

func TestRunBadNDoesNotChargePerOpSurcharge(t *testing.T) {
	as := newAS()
	fund(as.db, requester, tokens(1000))
	// N=0 must be rejected at the base-gas stage (before the per-N surcharge), and
	// it must return the post-base remaining gas (a normal revert, not all-burn).
	ret, remaining, err := run(t, as, requester, encRequest(spec1, prompt1, 0, 0, tokens(1)), 5_000_000, false)
	require.ErrorIs(t, err, ErrBadN)
	require.Nil(t, ret)
	// Only the base was charged; remaining = supplied - base.
	require.Equal(t, uint64(5_000_000)-GasRequestInferenceBase, remaining)
}

// TestRunRedAMarginRejectsWithGethRevert proves the RED-A margin check, when it
// rejects through the production Run path, behaves like a geth-canonical revert:
// it returns the POST-deduction remaining gas (the work charged so far, the rest
// refunded) and NEVER all-gas-burns (which could fork a co-validator). The fee is
// never charged on a rejected request.
func TestRunRedAMarginRejectsWithGethRevert(t *testing.T) {
	as := newAS()
	// Register exactly N operators (no margin headroom): N=5 needs E>=7, only 5 here.
	registerN(t, as.db, newLedger(as.db), spec1, 5, tokens(2))
	fund(as.db, requester, tokens(1000))
	reqBalBefore := as.db.GetBalance(requester).Uint64()
	burnBefore := as.db.GetBalance(BurnAddress).Uint64()

	ret, remaining, err := run(t, as, requester, encRequest(spec1, prompt1, 5, 3, tokens(1)), 5_000_000, false)
	require.ErrorIs(t, err, ErrEligibleBelowMargin)
	require.Nil(t, ret)
	// Geth-canonical revert: base + per-N + scan were charged, the REST is returned
	// (NOT zero — that would be an all-gas-burn fork hazard).
	require.Positive(t, remaining, "revert returns remaining gas, never all-burn")
	charged := uint64(5_000_000) - remaining
	wantCharged := GasRequestInferenceBase + GasRequestPerOp*5 + GasSelectScanPerMember*5
	require.Equal(t, wantCharged, charged,
		"exactly base + per-N + per-member-scan charged before the margin rejection")
	// No money moved on the rejected request (fail-closed): neither escrow nor fee.
	require.Equal(t, reqBalBefore, as.db.GetBalance(requester).Uint64(), "rejected request debits nothing")
	require.Equal(t, burnBefore, as.db.GetBalance(BurnAddress).Uint64(), "rejected request burns no fee")
}

// TestRunRedAFeeBurnedThroughDispatch proves the non-refundable fee is burned on a
// SUCCESSFUL request driven through the production Run path (calldata → dispatch →
// fee burn), and that the escrow account grows only by the refundable reward.
func TestRunRedAFeeBurnedThroughDispatch(t *testing.T) {
	as := newAS()
	registerN(t, as.db, newLedger(as.db), spec1, 7, tokens(2)) // N=5 + margin 2
	fund(as.db, requester, tokens(1000))
	escrowBefore := as.db.GetBalance(ContractAddress).Uint64() // 7 * 2 token stake
	reqBefore := as.db.GetBalance(requester).Uint64()
	burnBefore := as.db.GetBalance(BurnAddress).Uint64()

	ret, _, err := run(t, as, requester, encRequest(spec1, prompt1, 5, 3, tokens(1)), 5_000_000, false)
	require.NoError(t, err)
	require.Len(t, ret, 32, "returns the job id")

	fee := new(uint256.Int).Mul(RequestFeePerOperator, uint256.NewInt(5)).Uint64()
	reward := tokens(5).Uint64()
	require.Equal(t, escrowBefore+reward, as.db.GetBalance(ContractAddress).Uint64(),
		"escrow grows by refundable reward only (fee nets to zero on it)")
	require.Equal(t, burnBefore+fee, as.db.GetBalance(BurnAddress).Uint64(), "fee burned through dispatch")
	require.Equal(t, reqBefore-reward-fee, as.db.GetBalance(requester).Uint64(),
		"requester debited reward escrow + burned fee")
}

func TestRequiredGas(t *testing.T) {
	for _, tc := range []struct {
		sel uint32
		gas uint64
	}{
		{SelectorRegisterOperator, GasRegisterOperator},
		{SelectorDeregisterOperator, GasDeregisterOperator},
		{SelectorWithdrawStake, GasWithdrawStake},
		{SelectorRequestInference, GasRequestInferenceBase},
		{SelectorCommitResponse, GasCommitResponse},
		{SelectorRevealResponse, GasRevealResponse},
		{SelectorSettle, GasSettleBase},
		{SelectorWithdrawRewards, GasWithdrawRewards},
		{SelectorGetOperator, GasGetOperator},
		{SelectorGetCredit, GasGetCredit},
		{SelectorGetJob, GasGetJob},
		{SelectorGetCanonicalResult, GasGetCanonicalResult},
		{SelectorComputeModelSpec, GasComputeModelSpec},
		{SelectorIsSelected, GasIsSelected},
		{0xDEADBEEF, GasGetCredit},
	} {
		require.Equal(t, tc.gas, Precompile.RequiredGas(selBytes(tc.sel)))
	}
	require.Equal(t, GasGetCredit, Precompile.RequiredGas([]byte{1}))
}

func TestRunComputeModelSpecMatchesGo(t *testing.T) {
	as := newAS()
	s := ModelSpec{
		ModelID:            "zen-omni",
		ModelHash:          common.HexToHash("0x01"),
		TokenizerHash:      common.HexToHash("0x02"),
		RuntimeVersion:     "sglang-0.4",
		SamplingHash:       common.HexToHash("0x03"),
		PromptTemplateHash: common.HexToHash("0x04"),
		EmbeddingModelHash: common.HexToHash("0x05"),
	}
	// Build calldata in field order: string, h, h, string, h, h, h.
	in := selBytes(SelectorComputeModelSpec)
	in = append(in, padLeft32(uint256.NewInt(uint64(len(s.ModelID))).Bytes())...)
	in = append(in, padRight32([]byte(s.ModelID))...)
	in = append(in, s.ModelHash.Bytes()...)
	in = append(in, s.TokenizerHash.Bytes()...)
	in = append(in, padLeft32(uint256.NewInt(uint64(len(s.RuntimeVersion))).Bytes())...)
	in = append(in, padRight32([]byte(s.RuntimeVersion))...)
	in = append(in, s.SamplingHash.Bytes()...)
	in = append(in, s.PromptTemplateHash.Bytes()...)
	in = append(in, s.EmbeddingModelHash.Bytes()...)

	ret, _, err := run(t, as, requester, in, 1_000_000, false)
	require.NoError(t, err)
	require.Equal(t, ComputeModelSpecHash(s), common.BytesToHash(ret),
		"on-chain computeModelSpecHash must equal the Go implementation (prover-verifiable)")
}

// ===========================================================================
// FULL LIFECYCLE through the dispatcher: register x5 → request → commit x5 →
// reveal x3 (one dissenter that doesn't reveal pattern) → settle → withdraw.
// This is the integration test the prompt asked for, driven end to end via Run
// with opaque-but-consistent output hashes (3 agree, 2 withhold).
// ===========================================================================

func TestLifecycleThroughDispatch(t *testing.T) {
	as := newAS()
	as.advance(100)

	// Register 7 operators via Run (N=5 + RED-A margin 2). The beacon picks 5 of 7.
	const nOps = 7
	for i := 0; i < nOps; i++ {
		op := opAddr(i)
		as.db.balance[op] = tokens(5)
		_, _, err := run(t, as, op, encRegister(tokens(2), spec1, common.HexToHash("0xee")), 1_000_000, false)
		require.NoError(t, err, "register op %d", i)
	}

	// Requester opens a job: N=5, threshold=3, reward=1 token.
	fund(as.db, requester, tokens(1000))
	ret, _, err := run(t, as, requester, encRequest(spec1, prompt1, 5, 3, tokens(1)), 5_000_000, false)
	require.NoError(t, err)
	var jobID common.Hash
	copy(jobID[:], ret)
	require.NotEqual(t, common.Hash{}, jobID)

	// Enumerate the selected operators via isSelected over all 7; exactly N=5 hit.
	selected := make([]common.Address, 0, 5)
	for i := 0; i < nOps; i++ {
		op := opAddr(i)
		ret, _, err := run(t, as, requester, append(append(selBytes(SelectorIsSelected), jobID.Bytes()...), addrWord(op)...), 1_000_000, false)
		require.NoError(t, err)
		if ret[31] == 1 {
			selected = append(selected, op)
		}
	}
	require.Len(t, selected, 5, "N=5 drawn from a pool of 7")

	// The agreed answer (opaque to the chain) and a dissent answer.
	answer := common.HexToHash("0x0a11ce")
	dissent := common.HexToHash("0x0d1ff")
	embed := common.HexToHash("0x0e3b")

	// Commit window: all 5 commit. 0,1,2 commit the answer; 3,4 commit dissent.
	as.advance(105) // inside commit window [100, 100+CommitBlocks]
	nonces := make([]common.Hash, 5)
	for i := 0; i < 5; i++ {
		nonces[i] = common.BigToHash(big.NewInt(int64(7000 + i)))
		out := answer
		if i >= 3 {
			out = dissent
		}
		commit := ComputeCommit(jobID, spec1, prompt1, out, embed, selected[i], nonces[i])
		_, _, err := run(t, as, selected[i], encCommit(jobID, commit), 1_000_000, false)
		require.NoError(t, err, "commit op %d", i)
	}

	// Reveal window: only 0,1,2 reveal (the agreeing majority). 3,4 withhold.
	as.advance(100 + CommitBlocks + 5) // inside reveal window
	for i := 0; i < 3; i++ {
		_, _, err := run(t, as, selected[i], encReveal(jobID, answer, embed, nonces[i]), 1_000_000, false)
		require.NoError(t, err, "reveal op %d", i)
	}

	// Settle after the reveal window.
	as.advance(100 + CommitBlocks + RevealBlocks + 1)
	ret, _, err = run(t, as, requester, encSettle(jobID), 5_000_000, false)
	require.NoError(t, err)
	require.Len(t, ret, 160)
	require.Equal(t, JobSettled, ret[31])
	require.Equal(t, answer, common.BytesToHash(ret[32:64]))
	require.Equal(t, uint32(3), binary.BigEndian.Uint32(ret[92:96]))

	// getCanonicalResult via Run.
	ret, _, err = run(t, as, requester, append(selBytes(SelectorGetCanonicalResult), jobID.Bytes()...), 1_000_000, false)
	require.NoError(t, err)
	require.Equal(t, answer, common.BytesToHash(ret))

	// Winners withdraw rewards via Run; each receives >= reward.
	for i := 0; i < 3; i++ {
		before := as.db.GetBalance(selected[i]).Uint64()
		ret, _, err := run(t, as, selected[i], selBytes(SelectorWithdrawRewards), 1_000_000, false)
		require.NoError(t, err)
		paid := new(uint256.Int).SetBytes(ret).Uint64()
		require.GreaterOrEqual(t, paid, tokens(1).Uint64())
		require.Equal(t, before+paid, as.db.GetBalance(selected[i]).Uint64())
	}

	// Withholders are slashed: their stake is 2 - SlashPerOperator. Deregister +
	// cooldown + withdrawStake returns the reduced stake.
	for i := 3; i < 5; i++ {
		ret, _, err := run(t, as, selected[i], selBytes(SelectorDeregisterOperator), 1_000_000, false)
		require.NoError(t, err)
		require.Equal(t, byte(1), ret[31])
	}
	// Advance past cooldown and withdraw.
	as.advance(100 + CommitBlocks + RevealBlocks + 1 + UnbondCooldownBlocks)
	for i := 3; i < 5; i++ {
		ret, _, err := run(t, as, selected[i], selBytes(SelectorWithdrawStake), 1_000_000, false)
		require.NoError(t, err)
		returned := new(uint256.Int).SetBytes(ret)
		require.Equal(t, new(uint256.Int).Sub(tokens(2), SlashPerOperator).Uint64(), returned.Uint64(),
			"withholder %d stake must be slashed by SlashPerOperator", i)
	}
}

// TestRunReadViews exercises every read-view handler through Run (getJob,
// getCredit, getCanonicalResult, isSelected) so the full ABI read surface is
// covered by the production dispatch path.
func TestRunReadViews(t *testing.T) {
	as := newAS()
	as.advance(50)
	registerN(t, as.db, newLedger(as.db), spec1, 7, tokens(2)) // N=5 + RED-A margin 2
	fund(as.db, requester, tokens(1000))

	ret, _, err := run(t, as, requester, encRequest(spec1, prompt1, 5, 3, tokens(1)), 5_000_000, false)
	require.NoError(t, err)
	var jobID common.Hash
	copy(jobID[:], ret)

	// getJob → status Committing, N=5, threshold=3, requester, deadlines.
	ret, _, err = run(t, as, requester, append(selBytes(SelectorGetJob), jobID.Bytes()...), 1_000_000, false)
	require.NoError(t, err)
	require.Len(t, ret, 192)
	require.Equal(t, JobCommitting, ret[31])
	require.Equal(t, uint32(5), binary.BigEndian.Uint32(ret[60:64]))
	require.Equal(t, uint32(3), binary.BigEndian.Uint32(ret[92:96]))
	require.Equal(t, requester, common.BytesToAddress(ret[108:128]))
	require.Equal(t, uint64(50)+CommitBlocks, binary.BigEndian.Uint64(ret[152:160]))
	require.Equal(t, uint64(50)+CommitBlocks+RevealBlocks, binary.BigEndian.Uint64(ret[184:192]))

	// getCredit (zero before any payout) via Run.
	ret, _, err = run(t, as, requester, append(selBytes(SelectorGetCredit), addrWord(opAddr(0))...), 1_000_000, false)
	require.NoError(t, err)
	require.Zero(t, new(uint256.Int).SetBytes(ret).Uint64())

	// getCanonicalResult (zero before settle) via Run.
	ret, _, err = run(t, as, requester, append(selBytes(SelectorGetCanonicalResult), jobID.Bytes()...), 1_000_000, false)
	require.NoError(t, err)
	require.Equal(t, common.Hash{}, common.BytesToHash(ret))

	// isSelected for a selected and a (likely) non-selected via Run — at least one
	// of the 5 registered is selected since N=5 of 5.
	ret, _, err = run(t, as, requester, append(append(selBytes(SelectorIsSelected), jobID.Bytes()...), addrWord(SelectedAt(as.db, jobID, 0))...), 1_000_000, false)
	require.NoError(t, err)
	require.Equal(t, byte(1), ret[31])
}

// TestRunReadViewsRejectShortCalldata covers the bounds-check error paths in the
// calldata readers through Run (each read handler must reject truncated input).
func TestRunReadViewsRejectShortCalldata(t *testing.T) {
	as := newAS()
	// getJob with no bytes32 arg.
	_, _, err := run(t, as, requester, selBytes(SelectorGetJob), 1_000_000, false)
	require.ErrorIs(t, err, ErrInputTooShort)
	// getCredit with no address arg.
	_, _, err = run(t, as, requester, selBytes(SelectorGetCredit), 1_000_000, false)
	require.ErrorIs(t, err, ErrInputTooShort)
	// isSelected missing the address word.
	_, _, err = run(t, as, requester, append(selBytes(SelectorIsSelected), make([]byte, 32)...), 1_000_000, false)
	require.ErrorIs(t, err, ErrInputTooShort)
	// commit missing the commit word.
	_, _, err = run(t, as, requester, append(selBytes(SelectorCommitResponse), make([]byte, 32)...), 1_000_000, false)
	require.ErrorIs(t, err, ErrInputTooShort)
	// computeModelSpecHash with a dynamic length that overruns the buffer.
	bad := selBytes(SelectorComputeModelSpec)
	bad = append(bad, padLeft32(uint256.NewInt(9999).Bytes())...) // claims 9999 bytes
	bad = append(bad, []byte("short")...)
	_, _, err = run(t, as, requester, bad, 1_000_000, false)
	require.ErrorIs(t, err, ErrInputTooShort)
	// readUint32 rejecting an oversized value (high bytes set).
	overN := selBytes(SelectorRequestInference)
	overN = append(overN, spec1.Bytes()...)
	overN = append(overN, prompt1.Bytes()...)
	oversized := make([]byte, 32)
	oversized[0] = 0x01 // value > uint32
	overN = append(overN, oversized...)
	overN = append(overN, padLeft32Uint32(3)...)
	overN = append(overN, h32(tokens(1)).Bytes()...)
	_, _, err = run(t, as, requester, overN, 5_000_000, false)
	require.Error(t, err)
}

// TestRunDeregisterAndWithdrawStakeViaDispatch covers the deregister/withdraw
// handlers through Run (the lifecycle test only exercises the slashed path).
func TestRunDeregisterAndWithdrawStakeViaDispatch(t *testing.T) {
	as := newAS()
	as.advance(10)
	op := opAddr(1)
	as.db.balance[op] = tokens(5)
	_, _, err := run(t, as, op, encRegister(tokens(2), spec1, common.Hash{}), 1_000_000, false)
	require.NoError(t, err)

	// deregister via Run.
	_, _, err = run(t, as, op, selBytes(SelectorDeregisterOperator), 1_000_000, false)
	require.NoError(t, err)

	// withdrawStake before cooldown → revert (returns post-deduction gas).
	_, _, err = run(t, as, op, selBytes(SelectorWithdrawStake), 1_000_000, false)
	require.ErrorIs(t, err, ErrCooldownActive)

	// After cooldown → full stake returned.
	as.advance(10 + UnbondCooldownBlocks)
	ret, _, err := run(t, as, op, selBytes(SelectorWithdrawStake), 1_000_000, false)
	require.NoError(t, err)
	require.Equal(t, tokens(2).Uint64(), new(uint256.Int).SetBytes(ret).Uint64())
}

// TestRunModuleWiring covers the module + config plumbing (parity with aimarket).
func TestRunModuleWiring(t *testing.T) {
	require.Equal(t, ConfigKey, Module.ConfigKey)
	require.Equal(t, ContractAddress, Module.Address)

	c := &configurator{}
	cfg := c.MakeConfig()
	require.Equal(t, ConfigKey, cfg.Key())
	require.NoError(t, c.Configure(mockChainCfg{}, cfg, newMockStateDB(), &mockBlockCtx{n: 1}))

	require.Nil(t, cfg.Timestamp())
	require.False(t, cfg.IsDisabled())
	require.NoError(t, cfg.Verify(mockChainCfg{}))
	require.True(t, cfg.Equal(&Config{}))

	ts := uint64(42)
	cfg2 := &Config{Upgrade: precompileconfig.Upgrade{BlockTimestamp: &ts}}
	require.Equal(t, &ts, cfg2.Timestamp())
	require.False(t, cfg.(*Config).Equal(cfg2))

	dis := &Config{Upgrade: precompileconfig.Upgrade{Disable: true}}
	require.True(t, dis.IsDisabled())
}
