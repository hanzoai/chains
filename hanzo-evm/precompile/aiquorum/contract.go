// Copyright (C) 2026, Hanzo AI Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package aiquorum

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/holiman/uint256"
	"github.com/luxfi/geth/common"
	"github.com/luxfi/geth/core/tracing"
	"github.com/luxfi/precompile/contract"
)

var _ contract.StatefulPrecompiledContract = (*quorumContract)(nil)

// Precompile is the singleton AI Quorum settlement contract instance.
var Precompile = &quorumContract{}

// Method selectors (first 4 bytes of input). Mirrors the aimarket / lux
// ai_mining scheme: big-endian uint32, distinct high byte per method, so the
// dispatch is uniform across Hanzo precompiles. Each comment is the canonical
// ABI signature it corresponds to.
const (
	SelectorRegisterOperator   uint32 = 0x01000000 // registerOperator(uint256,bytes32,bytes32)
	SelectorDeregisterOperator uint32 = 0x02000000 // deregisterOperator()
	SelectorWithdrawStake      uint32 = 0x03000000 // withdrawStake()
	SelectorRequestInference   uint32 = 0x04000000 // requestInference(bytes32,bytes32,uint32,uint32,uint256)
	SelectorCommitResponse     uint32 = 0x05000000 // commitResponse(bytes32,bytes32)
	SelectorRevealResponse     uint32 = 0x06000000 // revealResponse(bytes32,bytes32,bytes32,bytes32)
	SelectorSettle             uint32 = 0x07000000 // settle(bytes32)
	SelectorWithdrawRewards    uint32 = 0x08000000 // withdrawRewards()
	SelectorGetOperator        uint32 = 0x09000000 // getOperator(address)
	SelectorGetCredit          uint32 = 0x0A000000 // getCredit(address)
	SelectorGetJob             uint32 = 0x0B000000 // getJob(bytes32)
	SelectorGetCanonicalResult uint32 = 0x0C000000 // getCanonicalResult(bytes32)
	SelectorComputeModelSpec   uint32 = 0x0D000000 // computeModelSpecHash(string,bytes32,bytes32,string,bytes32,bytes32,bytes32)
	SelectorIsSelected         uint32 = 0x0E000000 // isSelected(bytes32,address)
)

// Gas schedule. Reads = ReadGasCostPerSlot (5k), writes = WriteGasCostPerSlot
// (20k), sized to the exact slots each op touches so state growth is honestly
// priced. Operations whose cost scales with N (selection, tally, slash) charge a
// base in the dispatcher and an additional GasPerOperator * N inside the handler
// once N is known — keeping RequiredGas an honest floor and the real O(N) cost
// charged at execution.
const (
	// RegisterOperator: meta + spec + endpoint + stake + model-index + model-mem
	// + seen = 7 writes.
	GasRegisterOperator uint64 = 7 * contract.WriteGasCostPerSlot
	// DeregisterOperator: read meta, write meta.
	GasDeregisterOperator uint64 = contract.ReadGasCostPerSlot + contract.WriteGasCostPerSlot
	// WithdrawStake: read meta + read stake, write stake + write meta.
	GasWithdrawStake uint64 = 2*contract.ReadGasCostPerSlot + 2*contract.WriteGasCostPerSlot

	// RequestInference base: read nonce + write job(4 slots) + reward + escrow +
	// nonce. Per-operator: 2 eligibility reads (meta+stake) + 2 selection writes
	// (selected flag + sel-list). Charged as base + GasRequestPerOp*N.
	GasRequestInferenceBase  uint64 = contract.ReadGasCostPerSlot + 7*contract.WriteGasCostPerSlot
	GasRequestPerOp          uint64 = 2*contract.ReadGasCostPerSlot + 2*contract.WriteGasCostPerSlot
	// GasSelectScanPerMember prices the eligibility SCAN, which reads the WHOLE
	// per-ModelSpec operator array (O(total registered), not O(N)) to build the
	// eligible working set. selectOperators reads up to 4 slots per member
	// (meta + spec + endpoint via readOperator, then stake). Without this term a
	// requester pays only O(N) while every validator does O(total) work — a
	// consensus gas-mispricing + state-bloat griefing vector (RED-H): an attacker
	// mass-registers under a popular ModelSpec to inflate the execution cost of
	// every honest request for that spec while paying nothing for the bloat.
	// Charging the scan honestly removes the asymmetry.
	GasSelectScanPerMember uint64 = 4 * contract.ReadGasCostPerSlot

	// CommitResponse: read job(4 slots) + read selected + read commit, write commit.
	GasCommitResponse uint64 = 6*contract.ReadGasCostPerSlot + contract.WriteGasCostPerSlot
	// RevealResponse: read job(4) + read commit + read reveal-flag + read
	// reveal-count + keccak, write reveal + flag + list + count.
	GasRevealResponse uint64 = 7*contract.ReadGasCostPerSlot + GasKeccakCommit + 4*contract.WriteGasCostPerSlot

	// Settle base: read job(4) + reward + escrow + settled + reveal-count, write
	// job-meta + escrow + canonical + settled. Per-operator (tally + slash):
	// read reveal-list + reveal-hash + commit-flag + reveal-flag + stake, write
	// stake + credit. Charged as base + GasSettlePerOp*N.
	GasSettleBase  uint64 = 8*contract.ReadGasCostPerSlot + 4*contract.WriteGasCostPerSlot
	GasSettlePerOp uint64 = 5*contract.ReadGasCostPerSlot + 2*contract.WriteGasCostPerSlot

	// WithdrawRewards: read credit, write credit.
	GasWithdrawRewards uint64 = contract.ReadGasCostPerSlot + contract.WriteGasCostPerSlot

	GasGetOperator        uint64 = 4 * contract.ReadGasCostPerSlot
	GasGetCredit          uint64 = contract.ReadGasCostPerSlot
	GasGetJob             uint64 = 4 * contract.ReadGasCostPerSlot
	GasGetCanonicalResult uint64 = contract.ReadGasCostPerSlot
	GasIsSelected         uint64 = contract.ReadGasCostPerSlot

	// GasKeccakCommit prices the in-reveal keccak over the ~196-byte commit
	// preimage. EVM SHA3 is 30 + 6/word; 7 words → 30+42 = 72; rounded to 100.
	GasKeccakCommit uint64 = 100
	// GasComputeModelSpec prices the model-spec hash view; dominated by one
	// keccak over a bounded buffer.
	GasComputeModelSpec uint64 = 500
)

var (
	ErrInputTooShort = errors.New("aiquorum: input too short")
	ErrUnknownOp     = errors.New("aiquorum: unknown method selector")
	ErrReadOnly      = errors.New("aiquorum: state modification in read-only context")
)

// quorumContract is the stateful precompile.
type quorumContract struct{}

// Run is the EVM entry point. It decodes the selector, gates writes on readOnly,
// deducts gas, and dispatches. Error/gas semantics match aimarket + geth:
//   - decode / read-only failures (before gas deduction) return suppliedGas;
//   - DeductGas failure (out of gas) returns 0;
//   - a handler logic error returns the post-deduction remaining gas (the work
//     was charged, the rest refunded) — a standard revert, never all-gas-burn,
//     so it can never fork a co-validator.
func (c *quorumContract) Run(
	accessibleState contract.AccessibleState,
	caller common.Address,
	addr common.Address,
	input []byte,
	suppliedGas uint64,
	readOnly bool,
) (ret []byte, remainingGas uint64, err error) {
	if len(input) < 4 {
		return nil, suppliedGas, ErrInputTooShort
	}
	selector := binary.BigEndian.Uint32(input[:4])
	data := input[4:]

	db := newSlotDB(accessibleState.GetStateDB())
	block := accessibleState.GetBlockContext().Number().Uint64()

	switch selector {
	case SelectorRegisterOperator:
		if readOnly {
			return nil, suppliedGas, ErrReadOnly
		}
		gas, err := contract.DeductGas(suppliedGas, GasRegisterOperator)
		if err != nil {
			return nil, 0, err
		}
		return c.runRegisterOperator(accessibleState, db, caller, data, gas)

	case SelectorDeregisterOperator:
		if readOnly {
			return nil, suppliedGas, ErrReadOnly
		}
		gas, err := contract.DeductGas(suppliedGas, GasDeregisterOperator)
		if err != nil {
			return nil, 0, err
		}
		return c.runDeregisterOperator(db, caller, block, gas)

	case SelectorWithdrawStake:
		if readOnly {
			return nil, suppliedGas, ErrReadOnly
		}
		gas, err := contract.DeductGas(suppliedGas, GasWithdrawStake)
		if err != nil {
			return nil, 0, err
		}
		return c.runWithdrawStake(accessibleState, db, caller, block, gas)

	case SelectorRequestInference:
		if readOnly {
			return nil, suppliedGas, ErrReadOnly
		}
		gas, err := contract.DeductGas(suppliedGas, GasRequestInferenceBase)
		if err != nil {
			return nil, 0, err
		}
		return c.runRequestInference(accessibleState, db, caller, data, block, gas)

	case SelectorCommitResponse:
		if readOnly {
			return nil, suppliedGas, ErrReadOnly
		}
		gas, err := contract.DeductGas(suppliedGas, GasCommitResponse)
		if err != nil {
			return nil, 0, err
		}
		return c.runCommitResponse(db, caller, data, block, gas)

	case SelectorRevealResponse:
		if readOnly {
			return nil, suppliedGas, ErrReadOnly
		}
		gas, err := contract.DeductGas(suppliedGas, GasRevealResponse)
		if err != nil {
			return nil, 0, err
		}
		return c.runRevealResponse(db, caller, data, block, gas)

	case SelectorSettle:
		if readOnly {
			return nil, suppliedGas, ErrReadOnly
		}
		gas, err := contract.DeductGas(suppliedGas, GasSettleBase)
		if err != nil {
			return nil, 0, err
		}
		return c.runSettle(accessibleState, db, data, block, gas)

	case SelectorWithdrawRewards:
		if readOnly {
			return nil, suppliedGas, ErrReadOnly
		}
		gas, err := contract.DeductGas(suppliedGas, GasWithdrawRewards)
		if err != nil {
			return nil, 0, err
		}
		return c.runWithdrawRewards(accessibleState, db, caller, gas)

	case SelectorGetOperator:
		gas, err := contract.DeductGas(suppliedGas, GasGetOperator)
		if err != nil {
			return nil, 0, err
		}
		return c.runGetOperator(db, data, gas)

	case SelectorGetCredit:
		gas, err := contract.DeductGas(suppliedGas, GasGetCredit)
		if err != nil {
			return nil, 0, err
		}
		return c.runGetCredit(db, data, gas)

	case SelectorGetJob:
		gas, err := contract.DeductGas(suppliedGas, GasGetJob)
		if err != nil {
			return nil, 0, err
		}
		return c.runGetJob(db, data, gas)

	case SelectorGetCanonicalResult:
		gas, err := contract.DeductGas(suppliedGas, GasGetCanonicalResult)
		if err != nil {
			return nil, 0, err
		}
		return c.runGetCanonicalResult(db, data, gas)

	case SelectorComputeModelSpec:
		gas, err := contract.DeductGas(suppliedGas, GasComputeModelSpec)
		if err != nil {
			return nil, 0, err
		}
		return c.runComputeModelSpec(data, gas)

	case SelectorIsSelected:
		gas, err := contract.DeductGas(suppliedGas, GasIsSelected)
		if err != nil {
			return nil, 0, err
		}
		return c.runIsSelected(db, data, gas)

	default:
		return nil, suppliedGas, fmt.Errorf("%w: %#x", ErrUnknownOp, selector)
	}
}

// RequiredGas reports a worst-case gas floor for the input's selector. For the
// O(N) ops (request/settle) it returns the base; the per-N surcharge is deducted
// inside Run once N is read, so this is an honest lower bound the EVM pre-charges.
func (c *quorumContract) RequiredGas(input []byte) uint64 {
	if len(input) < 4 {
		return GasGetCredit
	}
	switch binary.BigEndian.Uint32(input[:4]) {
	case SelectorRegisterOperator:
		return GasRegisterOperator
	case SelectorDeregisterOperator:
		return GasDeregisterOperator
	case SelectorWithdrawStake:
		return GasWithdrawStake
	case SelectorRequestInference:
		return GasRequestInferenceBase
	case SelectorCommitResponse:
		return GasCommitResponse
	case SelectorRevealResponse:
		return GasRevealResponse
	case SelectorSettle:
		return GasSettleBase
	case SelectorWithdrawRewards:
		return GasWithdrawRewards
	case SelectorGetOperator:
		return GasGetOperator
	case SelectorGetCredit:
		return GasGetCredit
	case SelectorGetJob:
		return GasGetJob
	case SelectorGetCanonicalResult:
		return GasGetCanonicalResult
	case SelectorComputeModelSpec:
		return GasComputeModelSpec
	case SelectorIsSelected:
		return GasIsSelected
	default:
		return GasGetCredit
	}
}

// ---------------------------------------------------------------------------
// Handlers — ABI-style 32-byte words; strings/bytes as [len:uint256][data...].
// ---------------------------------------------------------------------------

// registerOperator(uint256 stake, bytes32 modelSpecHash, bytes32 endpointHash)
func (c *quorumContract) runRegisterOperator(as contract.AccessibleState, db StateDB, caller common.Address, data []byte, gas uint64) ([]byte, uint64, error) {
	stake, off, err := readUint256(data, 0)
	if err != nil {
		return nil, gas, err
	}
	spec, off, err := readBytes32(data, off)
	if err != nil {
		return nil, gas, err
	}
	endpoint, _, err := readBytes32(data, off)
	if err != nil {
		return nil, gas, err
	}
	lg := newLedger(as.GetStateDB())
	if err := RegisterOperator(db, lg, caller, stake, spec, endpoint); err != nil {
		return nil, gas, err
	}
	return word1(), gas, nil
}

// deregisterOperator()
func (c *quorumContract) runDeregisterOperator(db StateDB, caller common.Address, block, gas uint64) ([]byte, uint64, error) {
	if err := DeregisterOperator(db, caller, block); err != nil {
		return nil, gas, err
	}
	return word1(), gas, nil
}

// withdrawStake() -> amountReturned
func (c *quorumContract) runWithdrawStake(as contract.AccessibleState, db StateDB, caller common.Address, block, gas uint64) ([]byte, uint64, error) {
	lg := newLedger(as.GetStateDB())
	stake, err := WithdrawStake(db, lg, caller, block)
	if err != nil {
		return nil, gas, err
	}
	return h32(stake).Bytes(), gas, nil
}

// requestInference(bytes32 modelSpecHash, bytes32 promptHash, uint32 N, uint32 threshold, uint256 rewardPerOperator) -> jobId
func (c *quorumContract) runRequestInference(as contract.AccessibleState, db StateDB, caller common.Address, data []byte, block, gas uint64) ([]byte, uint64, error) {
	spec, off, err := readBytes32(data, 0)
	if err != nil {
		return nil, gas, err
	}
	prompt, off, err := readBytes32(data, off)
	if err != nil {
		return nil, gas, err
	}
	n, err := readUint32(data, off)
	if err != nil {
		return nil, gas, err
	}
	threshold, err := readUint32(data, off+32)
	if err != nil {
		return nil, gas, err
	}
	reward, _, err := readUint256(data, off+64)
	if err != nil {
		return nil, gas, err
	}
	// Validate N before charging per-N gas, so a bad-N call doesn't burn the
	// per-operator surcharge.
	if n < minN || n > maxN {
		return nil, gas, ErrBadN
	}
	// Charge the O(N) selection surcharge now that N is known.
	gas, err = contract.DeductGas(gas, GasRequestPerOp*uint64(n))
	if err != nil {
		return nil, 0, err
	}
	// Charge the O(total) eligibility-SCAN surcharge: selection reads the entire
	// per-ModelSpec operator array. Pricing it here makes mass-registration bloat
	// pay for the execution cost it imposes on every requester (RED-H fix). The
	// single modelCount read is part of the scan and folded into the per-member
	// price below.
	scanMembers := modelCount(db, spec)
	gas, err = contract.DeductGas(gas, GasSelectScanPerMember*uint64(scanMembers))
	if err != nil {
		return nil, 0, err
	}
	lg := newLedger(as.GetStateDB())
	jobID, err := RequestInference(db, lg, caller, spec, prompt, n, threshold, reward, block)
	if err != nil {
		return nil, gas, err
	}
	return jobID.Bytes(), gas, nil
}

// commitResponse(bytes32 jobId, bytes32 commit)
func (c *quorumContract) runCommitResponse(db StateDB, caller common.Address, data []byte, block, gas uint64) ([]byte, uint64, error) {
	jobID, off, err := readBytes32(data, 0)
	if err != nil {
		return nil, gas, err
	}
	commit, _, err := readBytes32(data, off)
	if err != nil {
		return nil, gas, err
	}
	if err := CommitResponse(db, jobID, caller, commit, block); err != nil {
		return nil, gas, err
	}
	return word1(), gas, nil
}

// revealResponse(bytes32 jobId, bytes32 outputHash, bytes32 embeddingHash, bytes32 nonce)
func (c *quorumContract) runRevealResponse(db StateDB, caller common.Address, data []byte, block, gas uint64) ([]byte, uint64, error) {
	jobID, off, err := readBytes32(data, 0)
	if err != nil {
		return nil, gas, err
	}
	outputHash, off, err := readBytes32(data, off)
	if err != nil {
		return nil, gas, err
	}
	embeddingHash, off, err := readBytes32(data, off)
	if err != nil {
		return nil, gas, err
	}
	nonce, _, err := readBytes32(data, off)
	if err != nil {
		return nil, gas, err
	}
	if err := RevealResponse(db, jobID, caller, outputHash, embeddingHash, nonce, block); err != nil {
		return nil, gas, err
	}
	return word1(), gas, nil
}

// settle(bytes32 jobId) -> (status, canonicalHash, winnerCount, paid, slashed)
func (c *quorumContract) runSettle(as contract.AccessibleState, db StateDB, data []byte, block, gas uint64) ([]byte, uint64, error) {
	jobID, _, err := readBytes32(data, 0)
	if err != nil {
		return nil, gas, err
	}
	// Charge the O(N) tally+slash surcharge using the stored job's N (read it
	// before settling). An unknown job has N=0; Settle will reject it.
	job := readJob(db, jobID)
	if job.N > 0 {
		gas, err = contract.DeductGas(gas, GasSettlePerOp*uint64(job.N))
		if err != nil {
			return nil, 0, err
		}
	}
	lg := newLedger(as.GetStateDB())
	res, err := Settle(db, lg, jobID, block)
	if err != nil {
		return nil, gas, err
	}
	out := make([]byte, 160)
	out[31] = res.Status
	copy(out[32:64], res.CanonicalHash.Bytes())
	binary.BigEndian.PutUint32(out[92:96], res.WinnerCount)
	copy(out[96:128], h32(res.Paid).Bytes())
	copy(out[128:160], h32(res.Slashed).Bytes())
	return out, gas, nil
}

// withdrawRewards() -> amountPaid
func (c *quorumContract) runWithdrawRewards(as contract.AccessibleState, db StateDB, caller common.Address, gas uint64) ([]byte, uint64, error) {
	lg := newLedger(as.GetStateDB())
	paid, err := WithdrawRewards(db, lg, caller)
	if err != nil {
		return nil, gas, err
	}
	return h32(paid).Bytes(), gas, nil
}

// getOperator(address op) -> (exists, unbonding, stake, modelSpecHash, endpointHash)
func (c *quorumContract) runGetOperator(db StateDB, data []byte, gas uint64) ([]byte, uint64, error) {
	op, _, err := readAddress(data, 0)
	if err != nil {
		return nil, gas, err
	}
	exists, unbonding, stake, spec, endpoint := GetOperator(db, op)
	out := make([]byte, 160)
	if exists {
		out[31] = 1
	}
	if unbonding {
		out[63] = 1
	}
	copy(out[64:96], h32(stake).Bytes())
	copy(out[96:128], spec.Bytes())
	copy(out[128:160], endpoint.Bytes())
	return out, gas, nil
}

// getCredit(address op) -> credit
func (c *quorumContract) runGetCredit(db StateDB, data []byte, gas uint64) ([]byte, uint64, error) {
	op, _, err := readAddress(data, 0)
	if err != nil {
		return nil, gas, err
	}
	return h32(GetCredit(db, op)).Bytes(), gas, nil
}

// getJob(bytes32 jobId) -> (status, N, threshold, requester, commitDeadline, revealDeadline)
func (c *quorumContract) runGetJob(db StateDB, data []byte, gas uint64) ([]byte, uint64, error) {
	jobID, _, err := readBytes32(data, 0)
	if err != nil {
		return nil, gas, err
	}
	j := GetJob(db, jobID)
	out := make([]byte, 192)
	out[31] = j.Status
	binary.BigEndian.PutUint32(out[60:64], j.N)
	binary.BigEndian.PutUint32(out[92:96], j.Threshold)
	copy(out[108:128], j.Requester.Bytes())
	binary.BigEndian.PutUint64(out[152:160], j.CommitDeadline)
	binary.BigEndian.PutUint64(out[184:192], j.RevealDeadline)
	return out, gas, nil
}

// getCanonicalResult(bytes32 jobId) -> canonicalOutputHash
func (c *quorumContract) runGetCanonicalResult(db StateDB, data []byte, gas uint64) ([]byte, uint64, error) {
	jobID, _, err := readBytes32(data, 0)
	if err != nil {
		return nil, gas, err
	}
	return GetCanonicalResult(db, jobID).Bytes(), gas, nil
}

// isSelected(bytes32 jobId, address op) -> bool
func (c *quorumContract) runIsSelected(db StateDB, data []byte, gas uint64) ([]byte, uint64, error) {
	jobID, off, err := readBytes32(data, 0)
	if err != nil {
		return nil, gas, err
	}
	op, _, err := readAddress(data, off)
	if err != nil {
		return nil, gas, err
	}
	if IsSelected(db, jobID, op) {
		return word1(), gas, nil
	}
	return make([]byte, 32), gas, nil
}

// computeModelSpecHash(string modelId, bytes32 modelHash, bytes32 tokenizerHash,
// string runtimeVersion, bytes32 samplingHash, bytes32 promptTemplateHash,
// bytes32 embeddingModelHash) -> modelSpecHash
//
// Calldata uses a flat (non-ABI-head/tail) layout matching the other handlers:
// the two strings are carried inline as [len:uint256][data padded to 32] in
// field order. This lets an external prover verify its model_spec_hash on-chain.
func (c *quorumContract) runComputeModelSpec(data []byte, gas uint64) ([]byte, uint64, error) {
	modelID, off, err := readBytes(data, 0)
	if err != nil {
		return nil, gas, err
	}
	if len(modelID) > maxStringLen {
		return nil, gas, ErrStringTooLong
	}
	modelHash, off, err := readBytes32(data, off)
	if err != nil {
		return nil, gas, err
	}
	tokenizerHash, off, err := readBytes32(data, off)
	if err != nil {
		return nil, gas, err
	}
	runtimeVersion, off, err := readBytes(data, off)
	if err != nil {
		return nil, gas, err
	}
	if len(runtimeVersion) > maxStringLen {
		return nil, gas, ErrStringTooLong
	}
	samplingHash, off, err := readBytes32(data, off)
	if err != nil {
		return nil, gas, err
	}
	promptTemplateHash, off, err := readBytes32(data, off)
	if err != nil {
		return nil, gas, err
	}
	embeddingModelHash, _, err := readBytes32(data, off)
	if err != nil {
		return nil, gas, err
	}
	h := ComputeModelSpecHash(ModelSpec{
		ModelID:            string(modelID),
		ModelHash:          modelHash,
		TokenizerHash:      tokenizerHash,
		RuntimeVersion:     string(runtimeVersion),
		SamplingHash:       samplingHash,
		PromptTemplateHash: promptTemplateHash,
		EmbeddingModelHash: embeddingModelHash,
	})
	return h.Bytes(), gas, nil
}

// ---------------------------------------------------------------------------
// Calldata readers (ABI-style 32-byte words; bounds-checked) — identical
// semantics to aimarket so the dispatch is uniform across precompiles.
// ---------------------------------------------------------------------------

func readWord(data []byte, off int) ([]byte, int, error) {
	if off < 0 || off+32 > len(data) {
		return nil, 0, ErrInputTooShort
	}
	return data[off : off+32], off + 32, nil
}

func readUint256(data []byte, off int) (*uint256.Int, int, error) {
	w, next, err := readWord(data, off)
	if err != nil {
		return nil, 0, err
	}
	return new(uint256.Int).SetBytes(w), next, nil
}

func readUint32(data []byte, off int) (uint32, error) {
	w, _, err := readWord(data, off)
	if err != nil {
		return 0, err
	}
	for _, b := range w[:28] {
		if b != 0 {
			return 0, fmt.Errorf("aiquorum: value at offset %d exceeds uint32", off)
		}
	}
	return binary.BigEndian.Uint32(w[28:32]), nil
}

func readAddress(data []byte, off int) (common.Address, int, error) {
	w, next, err := readWord(data, off)
	if err != nil {
		return common.Address{}, 0, err
	}
	for _, b := range w[:12] {
		if b != 0 {
			return common.Address{}, 0, fmt.Errorf("aiquorum: malformed address word at offset %d", off)
		}
	}
	return common.BytesToAddress(w[12:32]), next, nil
}

func readBytes32(data []byte, off int) (common.Hash, int, error) {
	w, next, err := readWord(data, off)
	if err != nil {
		return common.Hash{}, 0, err
	}
	return common.BytesToHash(w), next, nil
}

// maxDynamicLen bounds any single ABI dynamic field read from calldata, checked
// BEFORE slicing. Above every legitimate field (a model id / runtime version is
// capped at maxStringLen) so it never rejects valid input.
const maxDynamicLen = 64 * 1024

// readBytes decodes a [len:uint256][data...] tail. The data is consumed padded
// up to a 32-byte boundary so subsequent fixed words stay 32-aligned (matching
// the encoders in the tests and the aimarket layout).
func readBytes(data []byte, off int) ([]byte, int, error) {
	w, next, err := readWord(data, off)
	if err != nil {
		return nil, 0, err
	}
	lw := new(uint256.Int).SetBytes(w)
	if !lw.IsUint64() || lw.Uint64() > maxDynamicLen {
		return nil, 0, fmt.Errorf("aiquorum: dynamic length too large at offset %d", off)
	}
	n := int(lw.Uint64())
	if next+n > len(data) {
		return nil, 0, ErrInputTooShort
	}
	val := data[next : next+n]
	padded := (n + 31) / 32 * 32
	end := next + padded
	if end > len(data) {
		// The data is present but not padded to a full word; accept the value and
		// advance only past the data (still 32-safe for the final field).
		end = next + n
	}
	return val, end, nil
}

// word1 returns the 32-byte big-endian word 0x..01 (boolean true).
func word1() []byte {
	out := make([]byte, 32)
	out[31] = 1
	return out
}

// ---------------------------------------------------------------------------
// State + Ledger adapters over contract.StateDB (escrow = ContractAddress).
// ---------------------------------------------------------------------------

type slotDB struct{ db contract.StateDB }

func newSlotDB(db contract.StateDB) *slotDB { return &slotDB{db} }

func (s *slotDB) GetState(a common.Address, k common.Hash) common.Hash { return s.db.GetState(a, k) }
func (s *slotDB) SetState(a common.Address, k, v common.Hash) common.Hash {
	return s.db.SetState(a, k, v)
}

// evmLedger adapts contract.StateDB balance methods to the Ledger interface,
// using ContractAddress as the single escrow account. Custody is balance
// mutation only (no value-CALL → no reentrancy surface).
type evmLedger struct{ db contract.StateDB }

func newLedger(db contract.StateDB) *evmLedger { return &evmLedger{db} }

func (l *evmLedger) GetBalance(a common.Address) *uint256.Int { return l.db.GetBalance(a) }

func (l *evmLedger) Pull(from common.Address, amount *uint256.Int) error {
	if l.db.GetBalance(from).Lt(amount) {
		return ErrInsufficientFunds
	}
	l.db.SubBalance(from, amount, tracing.BalanceChangeTransfer)
	l.db.AddBalance(ContractAddress, amount, tracing.BalanceChangeTransfer)
	return nil
}

func (l *evmLedger) Pay(to common.Address, amount *uint256.Int) error {
	if l.db.GetBalance(ContractAddress).Lt(amount) {
		return ErrEscrowUnderflow
	}
	l.db.SubBalance(ContractAddress, amount, tracing.BalanceChangeTransfer)
	l.db.AddBalance(to, amount, tracing.BalanceChangeTransfer)
	return nil
}
