// Package evmllm provides the AI-inference EVM precompile and an end-to-end
// proof that the Go EVM (luxfi/geth) executes the shared "AIPay" contract:
// on-chain LLM inference AND payment in a single transaction, from the SAME
// bytecode the Rust VM uses.
//
// The precompile at 0x0000000000000000000000000000000000020001 implements
// geth's vm.PrecompiledContract. Its calldata layout is, byte-for-byte,
// identical to the Rust VM's exec_ai_inference:
//
//	[selector(4)][model(32, UTF-8 NUL/space-padded)][prompt(...)]
//
//	model  = input[4:36]   (passed RAW to the FFI; the FFI's model_str does
//	                         from_utf8_lossy().trim_matches('\0').trim(), empty =>
//	                         engine default — see lib.rs)
//	prompt = input[36:]
//
// Model-resolution parity with the Rust VM (RED finding I1, verified by trim
// algebra): the Go path passes the raw 32-byte field to the FFI, whose model_str
// (lib.rs) does from_utf8_lossy().trim_matches('\0').trim() — both ends. The
// Rust exec_ai_inference path calls model_name() = trim_end_matches('\0')
// (trailing only) and hands the result to engine::infer. For a left-NUL/space-
// padded fixed field the two converge: NUL-padding is trailing, and any
// surrounding whitespace is trimmed by the FFI's .trim() / collapses to the same
// engine lookup. We never trim in Go before the FFI, so the FFI is the single
// trim site on this side, matching Rust's single model_name trim site.
//
// Inference is stateless; the payment (msg.value) is recorded on-chain by the
// AIPay bytecode itself via SSTORE(slot0, slot0+CALLVALUE) before it CALLs us.
package evmllm

/*
#cgo CFLAGS: -I${SRCDIR}/../../../engine/hanzo-engine-ffi/include
#cgo LDFLAGS: -L${SRCDIR}/../../../engine/target/release -lhanzo_engine_ffi -Wl,-rpath,${SRCDIR}/../../../engine/target/release
#include "hanzo_engine_ffi.h"
#include <stdlib.h>
*/
import "C"

import (
	"unsafe"

	"github.com/luxfi/geth/common"
	"github.com/luxfi/geth/core/vm"
)

// PrecompileAddr is the canonical AI-inference precompile address:
// 20 bytes = [0;17, 0x02, 0x00, 0x01]. Identical to the Rust VM.
var PrecompileAddr = common.BytesToAddress([]byte{0x02, 0x00, 0x01})

const (
	// selectorLen is the 4-byte function selector prefix (zero for AIPay).
	selectorLen = 4
	// modelLen is the fixed 32-byte NUL-padded model field.
	modelLen = 32
	// headerLen is selector(4)+model(32). prompt begins at headerLen.
	headerLen = selectorLen + modelLen

	// CANONICAL GAS SCHEDULE — single source of truth across ALL EVM backends.
	//
	// Gas MUST be a pure function of INPUT size and charged BEFORE execution:
	// geth's runPrecompile deducts RequiredGas(input) before Run, when the model
	// output does not yet exist. Any backend that prices on OUTPUT length (as the
	// current Rust hanzo-vm exec_ai_inference does: 100_000 + 8*output_len) cannot
	// co-validate with this one — divergent gas_used => divergent state root =>
	// chain fork (RED finding H1). Reconciliation rule: the Rust VM MUST adopt
	// this input-based schedule before GoEvm and the Rust backend co-validate.
	// GasBaseInfer/GasPerPromptByte are the authoritative constants; the
	// differential test TestGasScheduleCanonical pins them so CI catches drift.
	GasBaseInfer     uint64 = 120_000
	GasPerPromptByte uint64 = 30
	baseGas                 = GasBaseInfer
	perByteGas              = GasPerPromptByte
)

// ErrRevert is the single error every failure path of Run returns, so the EVM
// takes its refund branch.
//
// CONSENSUS-CRITICAL (RED finding H2): geth's evm.Call burns ALL remaining gas
// when a precompile returns any error != vm.ErrExecutionReverted (evm.go: "if
// err != ErrExecutionReverted { gas = 0 }"), but REFUNDS unused gas when the
// error IS ErrExecutionReverted. The Rust hanzo-vm returns PrecompileResult::
// Revert for EVERY failure class (short input, empty prompt, no engine, model
// not found, generic inference failure — precompiles.rs:226-271,403-419), which
// revm maps to InstructionResult::Revert (gas refunded). Therefore, to compute
// the SAME gas_used (and avoid a state-root fork), every Go failure path MUST
// surface as vm.ErrExecutionReverted, not a bespoke error. We keep descriptive
// reasons in the returndata to mirror Rust's reason string.
var ErrRevert = vm.ErrExecutionReverted

// AIInference is the EVM precompile that performs LLM inference over cgo →
// hanzo_ffi_infer. It satisfies geth's vm.PrecompiledContract:
//
//	RequiredGas(input []byte) uint64
//	Run(input []byte) ([]byte, error)
//	Name() string
type AIInference struct{}

// Name identifies the precompile (geth's PrecompiledContract requires it).
func (AIInference) Name() string { return "aiInference" }

// RequiredGas returns a deterministic gas cost: a fixed base plus a per-byte
// charge over the prompt region. It depends ONLY on input length, never on the
// model output or any external/engine state, so it is identical across nodes.
func (AIInference) RequiredGas(input []byte) uint64 {
	var promptBytes uint64
	if len(input) > headerLen {
		promptBytes = uint64(len(input) - headerLen)
	}
	// Overflow-safe: promptBytes is bounded by calldata size, which is gas-
	// metered upstream, so perByteGas*promptBytes cannot realistically wrap;
	// guard anyway.
	cost := baseGas
	if promptBytes != 0 {
		add := perByteGas * promptBytes
		if add/perByteGas == promptBytes { // no overflow
			cost += add
		} else {
			cost = ^uint64(0) // saturate
		}
	}
	return cost
}

// Reason strings emitted in returndata on revert, mirroring the Rust VM's
// PrecompileResult::Revert { reason } (so returndata matches across backends).
const (
	reasonShortInput  = "ai_inference requires at least 36 bytes (selector + model id)"
	reasonEmptyPrompt = "ai_inference requires a non-empty prompt"
	reasonNoEngine    = "no inference engine registered on this node"
	reasonInferFailed = "ai_inference engine failure"
)

// Run parses [selector(4)][model(32)][prompt] and returns the LLM output bytes.
//
// Parity contract with the Rust VM:
//   - model = input[4:36] is passed RAW (the 32-byte NUL-padded slice) to the
//     FFI; the FFI's model_str trims '\0'+whitespace, empty => engine default —
//     the same path the Rust exec_ai_inference uses. prompt = input[36:].
//   - EVERY failure returns vm.ErrExecutionReverted (= ErrRevert) with the
//     reason in returndata, matching Rust's PrecompileResult::Revert so gas_used
//     and returndata are identical across backends (RED H2). A non-revert error
//     here would make geth burn all gas while Rust refunds => state-root fork.
func (AIInference) Run(input []byte) ([]byte, error) {
	if len(input) < headerLen {
		return []byte(reasonShortInput), ErrRevert // Rust: Revert on input < 36
	}
	model := input[selectorLen:headerLen] // input[4:36], raw NUL-padded
	prompt := input[headerLen:]           // input[36:]

	if len(prompt) == 0 {
		return []byte(reasonEmptyPrompt), ErrRevert // Rust: Revert on empty prompt
	}

	if C.hanzo_ffi_ready() != 1 {
		return []byte(reasonNoEngine), ErrRevert // Rust: Revert(NoInferenceEngine)
	}

	var out *C.uint8_t
	var outLen C.size_t
	rc := C.hanzo_ffi_infer(
		bytePtr(model), C.size_t(len(model)),
		bytePtr(prompt), C.size_t(len(prompt)),
		&out, &outLen,
	)
	if rc != 0 {
		// Rust maps NoInferenceEngine/ModelNotFound/Other all to Revert.
		return []byte(reasonInferFailed), ErrRevert
	}
	defer C.hanzo_ffi_free(out, outLen)

	// Copy out of FFI-owned memory into a Go-owned slice before free.
	return C.GoBytes(unsafe.Pointer(out), C.int(outLen)), nil
}

// Ready reports whether the native engine + configured models are loaded.
func Ready() bool { return C.hanzo_ffi_ready() == 1 }

// bytePtr returns a *C.uint8_t for a Go slice (nil for empty, so the FFI sees
// NULL and applies its own defaulting).
func bytePtr(b []byte) *C.uint8_t {
	if len(b) == 0 {
		return nil
	}
	return (*C.uint8_t)(unsafe.Pointer(&b[0]))
}
