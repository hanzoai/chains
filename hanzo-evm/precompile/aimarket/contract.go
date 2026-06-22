// Copyright (C) 2026, Hanzo AI Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package aimarket

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/holiman/uint256"
	"github.com/luxfi/geth/common"
	"github.com/luxfi/geth/core/tracing"
	"github.com/luxfi/precompile/contract"
)

var _ contract.StatefulPrecompiledContract = (*marketContract)(nil)

// Precompile is the singleton AI Market contract instance.
var Precompile = &marketContract{attest: DefaultAttest}

// Method selectors (first 4 bytes of input). These mirror the lux ai_mining
// scheme (big-endian uint32, distinct high byte per method) so the dispatch is
// uniform across Hanzo precompiles. Each constant's comment is the canonical
// ABI signature it corresponds to.
const (
	SelectorRegisterOffering uint32 = 0x01000000 // registerOffering(string,uint256,uint32)
	SelectorGetOffering      uint32 = 0x02000000 // getOffering(address,string)
	SelectorMeter            uint32 = 0x03000000 // meter(address,string,uint32)
	SelectorWithdraw         uint32 = 0x04000000 // withdraw()
	SelectorRequestInference uint32 = 0x05000000 // requestInference(address,string,uint32)
	SelectorSettleInference  uint32 = 0x06000000 // settleInference(bytes32,bytes32,bytes)
	SelectorGetCredit        uint32 = 0x07000000 // getCredit(address)
	SelectorGetRequest       uint32 = 0x08000000 // getRequest(bytes32)
)

// Gas costs. Reads are cheap (one slot read); writes are SSTORE-class. The
// bases follow lux contract.ReadGasCostPerSlot (5,000) / WriteGasCostPerSlot
// (20,000) and account for the number of slots each op touches.
// Gas constants count the exact slots each op touches so state growth is
// honestly priced (under-pricing state writes is a DoS vector, even though it
// cannot move funds). Reads = ReadGasCostPerSlot (5k), writes =
// WriteGasCostPerSlot (20k).
const (
	GasRegisterOffering uint64 = contract.WriteGasCostPerSlot // 1 write: offering
	GasGetOffering      uint64 = contract.ReadGasCostPerSlot  // 1 read

	// Meter: read offering + read credit, write credit.
	GasMeter uint64 = 2*contract.ReadGasCostPerSlot + contract.WriteGasCostPerSlot
	// Withdraw: read credit, write credit (zero).
	GasWithdraw uint64 = contract.ReadGasCostPerSlot + contract.WriteGasCostPerSlot
	// RequestInference: Meter (2 reads + 1 write) + read nonce + write
	// request + write cost + write nonce = 3 reads, 4 writes.
	GasRequestInference uint64 = 3*contract.ReadGasCostPerSlot + 4*contract.WriteGasCostPerSlot
	// SettleInference: read settled-marker + read request, write request +
	// write settled-marker, plus the attestation verify.
	GasSettleInference uint64 = 2*contract.ReadGasCostPerSlot + 2*contract.WriteGasCostPerSlot + GasAttestVerify
	GasGetCredit       uint64 = contract.ReadGasCostPerSlot
	GasGetRequest      uint64 = contract.ReadGasCostPerSlot

	// GasAttestVerify prices the in-settlement attestation check. Sized like
	// the EVM ecrecover (3,000) — and the lux ai_mining ML-DSA verify — so
	// swapping in a real PQ verifier does not change the gas schedule.
	GasAttestVerify uint64 = 3000
)

var (
	ErrInputTooShort = errors.New("aimarket: input too short")
	ErrUnknownOp     = errors.New("aimarket: unknown method selector")
	ErrReadOnly      = errors.New("aimarket: state modification in read-only context")
)

// marketContract is the stateful precompile. The attest function is injected
// so the consensus build can wire ML-DSA / secp256k1 / threshold verification
// without touching the accounting logic.
type marketContract struct {
	attest AttestFunc
}

// Run is the EVM entry point. It decodes the 4-byte selector, gates writes on
// readOnly, deducts gas, and dispatches to the typed handler.
func (c *marketContract) Run(
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

	switch selector {
	case SelectorRegisterOffering:
		if readOnly {
			return nil, suppliedGas, ErrReadOnly
		}
		gas, err := contract.DeductGas(suppliedGas, GasRegisterOffering)
		if err != nil {
			return nil, 0, err
		}
		return c.runRegisterOffering(db, caller, data, gas)

	case SelectorGetOffering:
		gas, err := contract.DeductGas(suppliedGas, GasGetOffering)
		if err != nil {
			return nil, 0, err
		}
		return c.runGetOffering(db, data, gas)

	case SelectorMeter:
		if readOnly {
			return nil, suppliedGas, ErrReadOnly
		}
		gas, err := contract.DeductGas(suppliedGas, GasMeter)
		if err != nil {
			return nil, 0, err
		}
		return c.runMeter(accessibleState, db, caller, data, gas)

	case SelectorWithdraw:
		if readOnly {
			return nil, suppliedGas, ErrReadOnly
		}
		gas, err := contract.DeductGas(suppliedGas, GasWithdraw)
		if err != nil {
			return nil, 0, err
		}
		return c.runWithdraw(accessibleState, db, caller, gas)

	case SelectorRequestInference:
		if readOnly {
			return nil, suppliedGas, ErrReadOnly
		}
		gas, err := contract.DeductGas(suppliedGas, GasRequestInference)
		if err != nil {
			return nil, 0, err
		}
		return c.runRequestInference(accessibleState, db, caller, data, gas)

	case SelectorSettleInference:
		if readOnly {
			return nil, suppliedGas, ErrReadOnly
		}
		gas, err := contract.DeductGas(suppliedGas, GasSettleInference)
		if err != nil {
			return nil, 0, err
		}
		return c.runSettleInference(db, data, gas)

	case SelectorGetCredit:
		gas, err := contract.DeductGas(suppliedGas, GasGetCredit)
		if err != nil {
			return nil, 0, err
		}
		return c.runGetCredit(db, data, gas)

	case SelectorGetRequest:
		gas, err := contract.DeductGas(suppliedGas, GasGetRequest)
		if err != nil {
			return nil, 0, err
		}
		return c.runGetRequest(db, data, gas)

	default:
		return nil, suppliedGas, fmt.Errorf("%w: %#x", ErrUnknownOp, selector)
	}
}

// RequiredGas reports worst-case gas for the input's selector (used by the EVM
// to pre-charge before Run).
func (c *marketContract) RequiredGas(input []byte) uint64 {
	if len(input) < 4 {
		return GasGetOffering
	}
	switch binary.BigEndian.Uint32(input[:4]) {
	case SelectorRegisterOffering:
		return GasRegisterOffering
	case SelectorGetOffering:
		return GasGetOffering
	case SelectorMeter:
		return GasMeter
	case SelectorWithdraw:
		return GasWithdraw
	case SelectorRequestInference:
		return GasRequestInference
	case SelectorSettleInference:
		return GasSettleInference
	case SelectorGetCredit:
		return GasGetCredit
	case SelectorGetRequest:
		return GasGetRequest
	default:
		return GasGetOffering
	}
}

// ---------------------------------------------------------------------------
// Handlers — calldata layout uses ABI-style 32-byte words, with strings/bytes
// carried as [len:uint256][data...] tail so dynamic fields are unambiguous.
// ---------------------------------------------------------------------------

// registerOffering(string modelName, uint256 price, uint32 maxSizeTokens)
//
//	word0      price (uint256)
//	word1      maxSizeTokens (right-aligned uint32)
//	word2      modelName length (uint256)
//	word3..    modelName bytes (padded to 32)
func (c *marketContract) runRegisterOffering(db StateDB, caller common.Address, data []byte, gas uint64) ([]byte, uint64, error) {
	price, off, err := readUint256(data, 0)
	if err != nil {
		return nil, gas, err
	}
	maxSize, err := readUint32(data, off)
	if err != nil {
		return nil, gas, err
	}
	name, _, err := readBytes(data, off+32)
	if err != nil {
		return nil, gas, err
	}
	if err := RegisterOffering(db, caller, name, price, maxSize); err != nil {
		return nil, gas, err
	}
	return word1(), gas, nil
}

// getOffering(address operator, string modelName) -> (price, maxSize, exists)
func (c *marketContract) runGetOffering(db StateDB, data []byte, gas uint64) ([]byte, uint64, error) {
	operator, off, err := readAddress(data, 0)
	if err != nil {
		return nil, gas, err
	}
	name, _, err := readBytes(data, off)
	if err != nil {
		return nil, gas, err
	}
	o := GetOffering(db, operator, name)
	out := make([]byte, 96)
	copy(out[0:32], h32(o.Price).Bytes())
	binary.BigEndian.PutUint32(out[60:64], o.MaxSizeTokens)
	if o.Exists {
		out[95] = 1
	}
	return out, gas, nil
}

// meter(address operator, string modelName, uint32 tokensUsed) -> costWei
func (c *marketContract) runMeter(as contract.AccessibleState, db StateDB, caller common.Address, data []byte, gas uint64) ([]byte, uint64, error) {
	operator, off, err := readAddress(data, 0)
	if err != nil {
		return nil, gas, err
	}
	tokens, err := readUint32(data, off)
	if err != nil {
		return nil, gas, err
	}
	name, _, err := readBytes(data, off+32)
	if err != nil {
		return nil, gas, err
	}
	lg := newLedger(as.GetStateDB())
	cost, err := Meter(db, lg, caller, operator, name, tokens)
	if err != nil {
		return nil, gas, err
	}
	return h32(cost).Bytes(), gas, nil
}

// withdraw() -> amountPaid
func (c *marketContract) runWithdraw(as contract.AccessibleState, db StateDB, caller common.Address, gas uint64) ([]byte, uint64, error) {
	lg := newLedger(as.GetStateDB())
	paid, err := Withdraw(db, lg, caller)
	if err != nil {
		return nil, gas, err
	}
	return h32(paid).Bytes(), gas, nil
}

// requestInference(address operator, string modelName, uint32 tokensUsed) -> (recordId, costWei)
func (c *marketContract) runRequestInference(as contract.AccessibleState, db StateDB, caller common.Address, data []byte, gas uint64) ([]byte, uint64, error) {
	operator, off, err := readAddress(data, 0)
	if err != nil {
		return nil, gas, err
	}
	tokens, err := readUint32(data, off)
	if err != nil {
		return nil, gas, err
	}
	name, _, err := readBytes(data, off+32)
	if err != nil {
		return nil, gas, err
	}
	lg := newLedger(as.GetStateDB())
	recordId, cost, err := RequestInference(db, lg, caller, operator, name, tokens)
	if err != nil {
		return nil, gas, err
	}
	out := make([]byte, 64)
	copy(out[0:32], recordId.Bytes())
	copy(out[32:64], h32(cost).Bytes())
	return out, gas, nil
}

// settleInference(bytes32 recordId, bytes32 resultHash, bytes operatorSig) -> operator
func (c *marketContract) runSettleInference(db StateDB, data []byte, gas uint64) ([]byte, uint64, error) {
	recordId, _, err := readBytes32(data, 0)
	if err != nil {
		return nil, gas, err
	}
	resultHash, _, err := readBytes32(data, 32)
	if err != nil {
		return nil, gas, err
	}
	sig, _, err := readBytes(data, 64)
	if err != nil {
		return nil, gas, err
	}
	operator, err := SettleInference(db, recordId, resultHash, sig, c.attest)
	if err != nil {
		return nil, gas, err
	}
	out := make([]byte, 32)
	copy(out[12:32], operator.Bytes())
	return out, gas, nil
}

// getCredit(address operator) -> credit
func (c *marketContract) runGetCredit(db StateDB, data []byte, gas uint64) ([]byte, uint64, error) {
	operator, _, err := readAddress(data, 0)
	if err != nil {
		return nil, gas, err
	}
	return h32(GetCredit(db, operator)).Bytes(), gas, nil
}

// getRequest(bytes32 recordId) -> (operator, tokens, status)
func (c *marketContract) runGetRequest(db StateDB, data []byte, gas uint64) ([]byte, uint64, error) {
	recordId, _, err := readBytes32(data, 0)
	if err != nil {
		return nil, gas, err
	}
	operator, tokens, status := GetRequest(db, recordId)
	out := make([]byte, 96)
	copy(out[12:32], operator.Bytes())
	binary.BigEndian.PutUint32(out[60:64], tokens)
	out[95] = status
	return out, gas, nil
}

// ---------------------------------------------------------------------------
// Calldata readers (ABI-style 32-byte words; bounds-checked)
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
	// Reject any value that does not fit in a uint32 (high 28 bytes must be 0).
	for _, b := range w[:28] {
		if b != 0 {
			return 0, fmt.Errorf("aimarket: value at offset %d exceeds uint32", off)
		}
	}
	return binary.BigEndian.Uint32(w[28:32]), nil
}

func readAddress(data []byte, off int) (common.Address, int, error) {
	w, next, err := readWord(data, off)
	if err != nil {
		return common.Address{}, 0, err
	}
	// Address is right-aligned; the high 12 bytes must be zero.
	for _, b := range w[:12] {
		if b != 0 {
			return common.Address{}, 0, fmt.Errorf("aimarket: malformed address word at offset %d", off)
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

// maxDynamicLen bounds any single ABI dynamic field (model name, signature)
// read out of calldata. It is far above every legitimate field — a model name
// is capped at modelNameMaxLen (64) and the largest attestation we anticipate
// is an ML-DSA / threshold signature on the order of a few KiB — so it never
// rejects valid input, while bounding the claimed length BEFORE we slice. This
// makes readBytes match its stated contract (a sane cap) rather than only
// trusting the buffer bound.
const maxDynamicLen = 64 * 1024

// readBytes decodes a [len:uint256][data...] tail. The length word is read at
// `off`; the data immediately follows. The claimed length must fit a machine
// int, not exceed maxDynamicLen, and not run past the buffer.
func readBytes(data []byte, off int) ([]byte, int, error) {
	w, next, err := readWord(data, off)
	if err != nil {
		return nil, 0, err
	}
	// Length must fit in a machine int and stay within the sane cap.
	lw := new(uint256.Int).SetBytes(w)
	if !lw.IsUint64() || lw.Uint64() > maxDynamicLen {
		return nil, 0, fmt.Errorf("aimarket: dynamic length too large at offset %d", off)
	}
	n := int(lw.Uint64())
	if next+n > len(data) {
		return nil, 0, ErrInputTooShort
	}
	return data[next : next+n], next + n, nil
}

// word1 returns the 32-byte big-endian word 0x..01 (boolean true).
func word1() []byte {
	out := make([]byte, 32)
	out[31] = 1
	return out
}

// ---------------------------------------------------------------------------
// State + Ledger adapters over contract.StateDB
// ---------------------------------------------------------------------------

// slotDB adapts contract.StateDB to the package StateDB (slot access only).
type slotDB struct{ db contract.StateDB }

func newSlotDB(db contract.StateDB) *slotDB { return &slotDB{db} }

func (s *slotDB) GetState(a common.Address, k common.Hash) common.Hash { return s.db.GetState(a, k) }
func (s *slotDB) SetState(a common.Address, k, v common.Hash) common.Hash {
	return s.db.SetState(a, k, v)
}

// evmLedger adapts contract.StateDB balance methods to the Ledger interface,
// using ContractAddress as the escrow account.
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
