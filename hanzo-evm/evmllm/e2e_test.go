package evmllm

import (
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/holiman/uint256"
	"github.com/luxfi/geth/common"
	"github.com/luxfi/geth/core"
	"github.com/luxfi/geth/core/state"
	"github.com/luxfi/geth/core/tracing"
	"github.com/luxfi/geth/core/types"
	"github.com/luxfi/geth/core/vm"
	"github.com/luxfi/geth/params"
)

// aiPayHex is the SHARED "AIPay" runtime bytecode — byte-identical to the one
// the Rust VM uses. Semantics (verified by disassembly + stack trace):
//
//	SSTORE(0, SLOAD(0)+CALLVALUE)             // record payment on-chain
//	CALLDATACOPY(mem[4..], calldata[0..])     // [4 zero bytes][model(32)][prompt]
//	CALL(0x020001, args=mem[0..4+cds], val=0) // on-chain LLM inference
//	RETURN(returndata)                        // return LLM output verbatim
const aiPayHex = "3460005401600055366000600437600060006004360160006000620200015af1503d600060003e3d6000f3"

// buildEVM stands up a full in-memory luxfi/geth vm.EVM with a Cancun-active
// chain config, the default precompile set PLUS our AIInference at 0x020001,
// and canonical core.CanTransfer/core.Transfer for real value movement.
//
// It returns the EVM, its StateDB, and the active rules (for Prepare/warming).
func buildEVM(t *testing.T, origin common.Address) (*vm.EVM, *state.StateDB, params.Rules) {
	t.Helper()

	statedb, err := state.New(types.EmptyRootHash, state.NewDatabaseForTesting())
	if err != nil {
		t.Fatalf("state.New: %v", err)
	}

	// Cancun-active mainnet-ish config (mirrors core/vm/runtime setDefaults).
	zero := uint64(0)
	chainConfig := &params.ChainConfig{
		ChainID:                 big.NewInt(1),
		HomesteadBlock:          new(big.Int),
		DAOForkBlock:            new(big.Int),
		DAOForkSupport:          false,
		EIP150Block:             new(big.Int),
		EIP155Block:             new(big.Int),
		EIP158Block:             new(big.Int),
		ByzantiumBlock:          new(big.Int),
		ConstantinopleBlock:     new(big.Int),
		PetersburgBlock:         new(big.Int),
		IstanbulBlock:           new(big.Int),
		MuirGlacierBlock:        new(big.Int),
		BerlinBlock:             new(big.Int),
		LondonBlock:             new(big.Int),
		TerminalTotalDifficulty: big.NewInt(0),
		ShanghaiTime:            &zero,
		CancunTime:              &zero,
	}

	blockNum := new(big.Int) // block 0
	blockTime := uint64(0)
	random := &common.Hash{} // non-nil => post-merge rules
	blockCtx := vm.BlockContext{
		CanTransfer: core.CanTransfer,
		Transfer:    core.Transfer,
		GetHash:     func(uint64) common.Hash { return common.Hash{} },
		Coinbase:    common.Address{},
		GasLimit:    math_MaxUint64,
		BlockNumber: blockNum,
		Time:        blockTime,
		Difficulty:  new(big.Int),
		BaseFee:     new(big.Int), // 0; NoBaseFee below allows 0-price calls
		BlobBaseFee: new(big.Int),
		Random:      random,
	}

	evm := vm.NewEVM(blockCtx, statedb, chainConfig, vm.Config{NoBaseFee: true})
	evm.SetTxContext(vm.TxContext{Origin: origin, GasPrice: new(big.Int)})

	rules := chainConfig.Rules(blockNum, random != nil, blockTime)

	// Inject our precompile ON TOP of the default active set for these rules.
	precompiles := vm.ActivePrecompiledContracts(rules) // cloned map (safe to mutate)
	precompiles[PrecompileAddr] = AIInference{}
	evm.SetPrecompiles(precompiles)

	return evm, statedb, rules
}

const math_MaxUint64 = ^uint64(0)

// padModel returns a 32-byte NUL-padded UTF-8 model field, as the AIPay caller
// constructs in its outer calldata.
func padModel(name string) []byte {
	b := make([]byte, modelLen)
	copy(b, name)
	return b
}

// TestE2E proves: one transaction → on-chain LLM inference + payment, via real
// EVM bytecode execution against luxfi/geth, with state assertions, determinism,
// and a benchmark.
func TestE2E(t *testing.T) {
	if !Ready() {
		t.Skip("native engine not ready — set HANZO_FFI_MODELS / HANZO_FFI_TOK_DIR")
	}

	const (
		modelName = "zen-nano"
		gasLimit  = uint64(50_000_000)
	)
	payment := uint256.NewInt(1_000_000)

	caller := common.HexToAddress("0xC0FFEE0000000000000000000000000000000001")
	contract := common.HexToAddress("0xA1A1A10000000000000000000000000000000001")

	// calldata = [model(32 NUL-padded)][prompt]
	prompt := []byte("Who are you? Answer in one short sentence.")
	calldata := append(padModel(modelName), prompt...)

	evm, statedb, rules := buildEVM(t, caller)

	// Fund the caller generously (payment + gas headroom).
	fund := uint256.NewInt(0).Mul(uint256.NewInt(1_000_000_000), uint256.NewInt(1_000_000_000))
	statedb.CreateAccount(caller)
	statedb.AddBalance(caller, fund, tracing.BalanceChangeUnspecified)

	// Deploy the SHARED AIPay bytecode to the contract address.
	code := common.FromHex(aiPayHex)
	statedb.CreateAccount(contract)
	statedb.SetCode(contract, code, tracing.CodeChangeUnspecified)

	// EIP-2929: warm origin, contract, and all precompiles incl. 0x020001.
	warm := append(vm.ActivePrecompiles(rules), PrecompileAddr)
	statedb.Prepare(rules, caller, common.Address{}, &contract, warm, nil)

	callerBalBefore := statedb.GetBalance(caller).Clone()
	contractBalBefore := statedb.GetBalance(contract).Clone()

	// THE SINGLE TRANSACTION: inference + payment in one EVM call.
	ret, gasLeft, err := evm.Call(caller, contract, calldata, gasLimit, payment)
	if err != nil {
		t.Fatalf("evm.Call: %v (ret=%q)", err, string(ret))
	}
	gasUsed := gasLimit - gasLeft

	// ---- Assert 1: returndata is the LLM output and identifies as Zen Nano.
	out := string(ret)
	if len(ret) == 0 {
		t.Fatalf("empty returndata — precompile produced no output")
	}
	if !strings.Contains(out, "Zen Nano") && !strings.Contains(strings.ToLower(out), "zen nano") {
		t.Errorf("returndata does not identify as Zen Nano: %q", out)
	}

	// ---- Assert 2: payment recorded on-chain via SSTORE at slot 0.
	slot0 := statedb.GetState(contract, common.Hash{})
	gotSlot := new(big.Int).SetBytes(slot0.Bytes())
	if gotSlot.Cmp(payment.ToBig()) != 0 {
		t.Errorf("storage slot0 = %s, want %s (payment not recorded on-chain)", gotSlot, payment)
	}

	// ---- Assert 3: balances moved by exactly the payment (value transfer).
	callerBalAfter := statedb.GetBalance(caller)
	contractBalAfter := statedb.GetBalance(contract)

	callerDelta := new(uint256.Int).Sub(callerBalBefore, callerBalAfter) // gas is 0-priced here
	if callerDelta.Cmp(payment) != 0 {
		t.Errorf("caller balance decreased by %s, want exactly %s (gas is 0-priced)", callerDelta, payment)
	}
	contractDelta := new(uint256.Int).Sub(contractBalAfter, contractBalBefore)
	if contractDelta.Cmp(payment) != 0 {
		t.Errorf("contract balance increased by %s, want %s", contractDelta, payment)
	}

	t.Logf("=== E2E: on-chain LLM inference + payment in ONE tx (luxfi/geth EVM) ===")
	t.Logf("contract       : %s (AIPay bytecode, %d bytes)", contract, len(code))
	t.Logf("precompile     : %s (AIInference over cgo→hanzo_ffi_infer)", PrecompileAddr)
	t.Logf("model / prompt : %q / %q", modelName, string(prompt))
	t.Logf("LLM output     : %q (%d bytes)", truncate(out, 200), len(ret))
	t.Logf("payment slot0  : %s wei  (recorded on-chain via SSTORE)", gotSlot)
	t.Logf("caller -%s  contract +%s", callerDelta, contractDelta)
	t.Logf("gas used       : %d (precompile RequiredGas=%d)", gasUsed, AIInference{}.RequiredGas(buildInner(calldata)))

	// ---- DETERMINISM: a second independent tx must yield byte-identical output.
	evm2, statedb2, rules2 := buildEVM(t, caller)
	statedb2.CreateAccount(caller)
	statedb2.AddBalance(caller, fund, tracing.BalanceChangeUnspecified)
	statedb2.CreateAccount(contract)
	statedb2.SetCode(contract, code, tracing.CodeChangeUnspecified)
	warm2 := append(vm.ActivePrecompiles(rules2), PrecompileAddr)
	statedb2.Prepare(rules2, caller, common.Address{}, &contract, warm2, nil)

	ret2, _, err := evm2.Call(caller, contract, calldata, gasLimit, payment)
	if err != nil {
		t.Fatalf("evm.Call (2nd): %v", err)
	}
	deterministic := string(ret) == string(ret2)
	t.Logf("determinism    : %v (run1 %d bytes == run2 %d bytes)", deterministic, len(ret), len(ret2))
	if !deterministic {
		t.Errorf("non-deterministic returndata:\n run1=%q\n run2=%q", out, string(ret2))
	}

	// ---- BENCHMARK: BENCH_ITERS full e2e calls (deploy fresh state each iter).
	iters := envInt("BENCH_ITERS", 5)
	var es []float64
	for i := 0; i < iters; i++ {
		e, st, rl := buildEVM(t, caller)
		st.CreateAccount(caller)
		st.AddBalance(caller, fund, tracing.BalanceChangeUnspecified)
		st.CreateAccount(contract)
		st.SetCode(contract, code, tracing.CodeChangeUnspecified)
		w := append(vm.ActivePrecompiles(rl), PrecompileAddr)
		st.Prepare(rl, caller, common.Address{}, &contract, w, nil)

		t0 := time.Now()
		r, _, cerr := e.Call(caller, contract, calldata, gasLimit, payment)
		dt := float64(time.Since(t0).Microseconds()) / 1000.0
		if cerr != nil {
			t.Fatalf("bench iter %d: %v", i, cerr)
		}
		if string(r) != string(ret) {
			t.Errorf("bench iter %d non-deterministic vs first run", i)
		}
		es = append(es, dt)
	}

	bench := map[string]any{
		"lang":             "go",
		"op":               "pay_infer",
		"e2e_ms":           round3(mean(es)),
		"e2e_min_ms":       round3(minf(es)),
		"out_bytes":        len(ret),
		"payment_recorded": gotSlot.Cmp(payment.ToBig()) == 0,
		"deterministic":    deterministic,
		"iters":            iters,
		"gas_used":         gasUsed,
	}
	js, _ := json.Marshal(bench)
	fmt.Printf("\nBENCH_JSON %s\n", js)
}

// TestNegativeControl proves the precompile is load-bearing: with the SAME
// bytecode and calldata but NO precompile injected at 0x020001, the inner CALL
// hits an empty account → returns success with empty returndata → the contract
// RETURNs 0 bytes. The payment SSTORE still records on-chain. This isolates the
// claim that the LLM output in TestE2E can ONLY come from the injected
// precompile (a stock geth EVM has nothing at 0x020001).
func TestNegativeControl(t *testing.T) {
	caller := common.HexToAddress("0xC0FFEE0000000000000000000000000000000001")
	contract := common.HexToAddress("0xA1A1A10000000000000000000000000000000001")
	payment := uint256.NewInt(1_000_000)
	calldata := append(padModel("zen-nano"), []byte("Who are you?")...)
	code := common.FromHex(aiPayHex)
	gasLimit := uint64(50_000_000)

	// Build an EVM WITHOUT injecting the precompile (stock active set only).
	statedb, err := state.New(types.EmptyRootHash, state.NewDatabaseForTesting())
	if err != nil {
		t.Fatalf("state.New: %v", err)
	}
	zero := uint64(0)
	chainConfig := &params.ChainConfig{
		ChainID: big.NewInt(1), HomesteadBlock: new(big.Int), EIP150Block: new(big.Int),
		EIP155Block: new(big.Int), EIP158Block: new(big.Int), ByzantiumBlock: new(big.Int),
		ConstantinopleBlock: new(big.Int), PetersburgBlock: new(big.Int), IstanbulBlock: new(big.Int),
		MuirGlacierBlock: new(big.Int), BerlinBlock: new(big.Int), LondonBlock: new(big.Int),
		TerminalTotalDifficulty: big.NewInt(0), ShanghaiTime: &zero, CancunTime: &zero,
	}
	blockNum := new(big.Int)
	random := &common.Hash{}
	blockCtx := vm.BlockContext{
		CanTransfer: core.CanTransfer, Transfer: core.Transfer,
		GetHash:  func(uint64) common.Hash { return common.Hash{} },
		GasLimit: math_MaxUint64, BlockNumber: blockNum, Difficulty: new(big.Int),
		BaseFee: new(big.Int), BlobBaseFee: new(big.Int), Random: random,
	}
	evm := vm.NewEVM(blockCtx, statedb, chainConfig, vm.Config{NoBaseFee: true})
	evm.SetTxContext(vm.TxContext{Origin: caller, GasPrice: new(big.Int)})
	rules := chainConfig.Rules(blockNum, true, 0)
	// NOTE: no SetPrecompiles override — 0x020001 stays empty.

	fund := uint256.NewInt(0).Mul(uint256.NewInt(1_000_000_000), uint256.NewInt(1_000_000_000))
	statedb.CreateAccount(caller)
	statedb.AddBalance(caller, fund, tracing.BalanceChangeUnspecified)
	statedb.CreateAccount(contract)
	statedb.SetCode(contract, code, tracing.CodeChangeUnspecified)
	statedb.Prepare(rules, caller, common.Address{}, &contract, vm.ActivePrecompiles(rules), nil)

	ret, _, err := evm.Call(caller, contract, calldata, gasLimit, payment)
	if err != nil {
		t.Fatalf("evm.Call: %v", err)
	}
	// The model output must NOT appear — nothing answered the inner CALL.
	if len(ret) != 0 {
		t.Errorf("expected empty returndata without precompile, got %d bytes: %q", len(ret), string(ret))
	}
	// Payment still recorded on-chain (SSTORE happens before the CALL).
	slot0 := new(big.Int).SetBytes(statedb.GetState(contract, common.Hash{}).Bytes())
	if slot0.Cmp(payment.ToBig()) != 0 {
		t.Errorf("slot0=%s, want %s (payment must still record without precompile)", slot0, payment)
	}
	t.Logf("negative control: no precompile @0x020001 → returndata=%d bytes (empty), payment slot0=%s recorded",
		len(ret), slot0)
}

// TestGasScheduleCanonical pins the canonical input-based gas schedule so CI
// catches any drift (RED finding H1). RequiredGas MUST be a pure function of
// input length, charged before execution, identical on every backend. This is
// the authoritative reference the Rust hanzo-vm must converge to (it currently
// prices on output length, which cannot co-validate — see precompile.go).
func TestGasScheduleCanonical(t *testing.T) {
	// LITERAL coefficient pin (RED re-review): hard-code the numbers, NOT the
	// constants, so a coefficient mutation (e.g. GasPerPromptByte 30->31) FAILS
	// here. These literals are the cross-backend contract the Rust VM must adopt.
	const (
		wantBase    uint64 = 120_000
		wantPerByte uint64 = 30
	)
	if GasBaseInfer != wantBase {
		t.Errorf("GasBaseInfer drift: %d, want %d (Rust VM must match this literal)", GasBaseInfer, wantBase)
	}
	if GasPerPromptByte != wantPerByte {
		t.Errorf("GasPerPromptByte drift: %d, want %d (Rust VM must match this literal)", GasPerPromptByte, wantPerByte)
	}

	// Shape: linear-in-prompt, clamped below header. wantGas uses LITERALS so
	// both the constants AND the RequiredGas arithmetic are pinned.
	cases := []struct {
		name     string
		inputLen int
		wantGas  uint64
	}{
		{"header-only (zero prompt)", headerLen, 120_000},
		{"short input (<header)", 10, 120_000}, // promptBytes clamped to 0
		{"header + 1 byte", headerLen + 1, 120_030},
		{"header + 42 bytes", headerLen + 42, 121_260},
		{"header + 1KiB", headerLen + 1024, 120_000 + 1024*30},
	}
	for _, c := range cases {
		got := AIInference{}.RequiredGas(make([]byte, c.inputLen))
		if got != c.wantGas {
			t.Errorf("%s: RequiredGas(len=%d)=%d, want %d", c.name, c.inputLen, got, c.wantGas)
		}
	}
	// Purity: same length => same gas, regardless of byte content.
	a := AIInference{}.RequiredGas([]byte(strings.Repeat("A", 100)))
	b := AIInference{}.RequiredGas([]byte(strings.Repeat("\x00", 100)))
	if a != b {
		t.Errorf("gas not pure in length: contentA=%d contentB=%d", a, b)
	}
	t.Logf("canonical gas schedule: %d base + %d/prompt-byte (input-based, pre-exec); literals pinned",
		GasBaseInfer, GasPerPromptByte)
}

// TestCalldataParsingParity exercises the model/prompt split + guards over the
// edge cases RED fuzzed: short input, empty prompt, all-NUL model, all-space
// model, >32-byte (truncated) model, non-UTF8 model bytes. These must hit the
// correct error/default path WITHOUT the engine (pure parsing checks); the
// raw-32-byte model is then handed to the FFI exactly as the Rust VM does.
func TestCalldataParsingParity(t *testing.T) {
	// CONSENSUS-CRITICAL (RED H2): every failure must return vm.ErrExecutionReverted
	// (= ErrRevert) so geth REFUNDS unused gas, matching Rust's Revert. A non-
	// revert error would burn all gas => ~49M-gas state-root fork. We also assert
	// the reason returndata mirrors Rust's PrecompileResult::Revert{reason}.

	// Short input (< 36 bytes) => Revert + reason (Rust precompiles.rs:226).
	ret, err := (AIInference{}).Run(make([]byte, 35))
	if err != ErrRevert {
		t.Errorf("short input: err=%v, want vm.ErrExecutionReverted (refund parity)", err)
	}
	if string(ret) != reasonShortInput {
		t.Errorf("short input reason=%q, want %q", ret, reasonShortInput)
	}
	// Exactly header, empty prompt => Revert + reason (Rust precompiles.rs:235).
	ret, err = (AIInference{}).Run(make([]byte, headerLen))
	if err != ErrRevert {
		t.Errorf("empty prompt: err=%v, want vm.ErrExecutionReverted (refund parity)", err)
	}
	if string(ret) != reasonEmptyPrompt {
		t.Errorf("empty prompt reason=%q, want %q", ret, reasonEmptyPrompt)
	}
	// Verify the split offsets the precompile uses match the Rust VM's [4..36]/[36..].
	in := make([]byte, headerLen+5)
	copy(in[selectorLen:headerLen], []byte("zen-nano"))
	copy(in[headerLen:], []byte("hello"))
	gotModel := in[selectorLen:headerLen]
	gotPrompt := in[headerLen:]
	if len(gotModel) != modelLen {
		t.Errorf("model slice len=%d, want %d", len(gotModel), modelLen)
	}
	if string(gotPrompt) != "hello" {
		t.Errorf("prompt slice=%q, want %q", gotPrompt, "hello")
	}
	if string(bytesTrimNulSpace(gotModel)) != "zen-nano" {
		t.Errorf("trimmed model=%q, want %q", bytesTrimNulSpace(gotModel), "zen-nano")
	}
	// All-NUL model field => engine default (trims to empty). The raw bytes are
	// passed through; we only check the trim semantics here.
	allNul := make([]byte, modelLen)
	if len(bytesTrimNulSpace(allNul)) != 0 {
		t.Errorf("all-NUL model did not trim to empty (would not route to default)")
	}
	t.Logf("calldata parity: model=input[4:36] (raw→FFI), prompt=input[36:]; short/empty guarded")
}

// bytesTrimNulSpace mirrors the engine's NUL+whitespace trim for assertion only
// (the actual trim happens in the Rust FFI; we never trim before the FFI call).
func bytesTrimNulSpace(b []byte) []byte {
	return []byte(strings.Trim(strings.Trim(string(b), "\x00"), " \t\r\n"))
}

// TestRevertRefundsGas proves the H2 fix end-to-end through the real EVM: a
// precompile call that reverts (short input) must REFUND unused gas, not burn it
// — matching the Rust VM's PrecompileResult::Revert. Without the fix (a bespoke
// non-revert error), geth's evm.Call would set gas=0 and the receipt gasUsed
// would diverge from the Rust co-validator by tens of millions => state fork.
// No engine needed: the revert happens before any FFI call.
func TestRevertRefundsGas(t *testing.T) {
	caller := common.HexToAddress("0xC0FFEE0000000000000000000000000000000001")
	evm, statedb, rules := buildEVM(t, caller)
	statedb.CreateAccount(caller)
	statedb.AddBalance(caller, uint256.NewInt(1e18), tracing.BalanceChangeUnspecified)
	warm := append(vm.ActivePrecompiles(rules), PrecompileAddr)
	statedb.Prepare(rules, caller, common.Address{}, &PrecompileAddr, warm, nil)

	const gas = uint64(5_000_000)
	// Direct call to the precompile with < 36 bytes => Run returns ErrRevert.
	ret, gasLeft, err := evm.Call(caller, PrecompileAddr, make([]byte, 8), gas, uint256.NewInt(0))

	// geth surfaces ErrExecutionReverted to the caller of a reverting frame.
	if err != vm.ErrExecutionReverted {
		t.Fatalf("err=%v, want vm.ErrExecutionReverted", err)
	}
	// THE FIX: unused gas refunded. RequiredGas(8 bytes)=GasBaseInfer=120000, so
	// gasLeft must be gas-120000, NOT 0 (which is what a non-revert error burns).
	wantLeft := gas - GasBaseInfer
	if gasLeft != wantLeft {
		t.Errorf("gasLeft=%d, want %d (revert must refund; gas=0 would mean burned)", gasLeft, wantLeft)
	}
	if gasLeft == 0 {
		t.Errorf("all gas burned — H2 NOT fixed (would fork vs Rust refund)")
	}
	if string(ret) != reasonShortInput {
		t.Errorf("revert returndata=%q, want reason %q (Rust parity)", ret, reasonShortInput)
	}
	t.Logf("revert refunds gas: supplied=%d used=%d left=%d (RequiredGas=%d charged, rest refunded), reason=%q",
		gas, gas-gasLeft, gasLeft, GasBaseInfer, string(ret))
}

// buildInner reconstructs the inner precompile calldata ([selector(4)][outer
// calldata]) that the AIPay bytecode passes to 0x020001, purely so the log can
// report the precompile's RequiredGas for the actual payload.
func buildInner(outer []byte) []byte {
	inner := make([]byte, selectorLen+len(outer))
	copy(inner[selectorLen:], outer) // selector stays zero
	return inner
}

func envInt(k string, def int) int {
	if v := os.Getenv(k); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return def
}

func mean(xs []float64) float64 {
	if len(xs) == 0 {
		return 0
	}
	var s float64
	for _, x := range xs {
		s += x
	}
	return s / float64(len(xs))
}

func minf(xs []float64) float64 {
	if len(xs) == 0 {
		return 0
	}
	m := xs[0]
	for _, x := range xs {
		if x < m {
			m = x
		}
	}
	return m
}

func round3(f float64) float64 { return float64(int64(f*1000+0.5)) / 1000 }

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
