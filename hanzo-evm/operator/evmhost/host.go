// Copyright (C) 2026, Hanzo AI Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package evmhost is a minimal, in-memory contract.AccessibleState for driving a
// real Hanzo stateful precompile (aiquorum) through its production Run path
// outside a full geth node — slot-level state, native-value balances, and a
// settable block height. It is the SAME shape as the precompile's own test mock;
// extracted into a non-test package so the capstone binary AND the capstone test
// can both drive the precompile without copying the harness.
//
// It is a test/proof harness, not production state: it keeps everything in maps
// and never persists. The point is that the code it DRIVES (aiquorum.Precompile.Run,
// the selectors, gas, ABI decode, fee burn, settlement) is the real production
// precompile — only the StateDB/Ledger backing it is in-memory.
package evmhost

import (
	"context"
	"math/big"

	"github.com/holiman/uint256"
	"github.com/luxfi/geth/common"
	"github.com/luxfi/geth/core/tracing"
	ethtypes "github.com/luxfi/geth/core/types"
	"github.com/luxfi/precompile/contract"
	"github.com/luxfi/precompile/precompileconfig"
)

// StateDB is an in-memory contract.StateDB: slot storage keyed by (address, slot)
// plus native balances. Implements exactly the geth-compatible interface the
// precompile consumes.
type StateDB struct {
	state   map[common.Address]map[common.Hash]common.Hash
	balance map[common.Address]*uint256.Int
}

// NewStateDB returns an empty in-memory state.
func NewStateDB() *StateDB {
	return &StateDB{
		state:   make(map[common.Address]map[common.Hash]common.Hash),
		balance: make(map[common.Address]*uint256.Int),
	}
}

func (m *StateDB) GetState(addr common.Address, key common.Hash) common.Hash {
	if m.state[addr] == nil {
		return common.Hash{}
	}
	return m.state[addr][key]
}

func (m *StateDB) SetState(addr common.Address, key, val common.Hash) common.Hash {
	if m.state[addr] == nil {
		m.state[addr] = make(map[common.Hash]common.Hash)
	}
	old := m.state[addr][key]
	m.state[addr][key] = val
	return old
}

func (m *StateDB) bal(a common.Address) *uint256.Int {
	if m.balance[a] == nil {
		m.balance[a] = new(uint256.Int)
	}
	return m.balance[a]
}

// Fund sets an account balance (test setup helper).
func (m *StateDB) Fund(a common.Address, wei *uint256.Int) {
	m.balance[a] = new(uint256.Int).Set(wei)
}

func (m *StateDB) GetBalance(a common.Address) *uint256.Int {
	return new(uint256.Int).Set(m.bal(a))
}

func (m *StateDB) AddBalance(a common.Address, v *uint256.Int, _ tracing.BalanceChangeReason) uint256.Int {
	prev := new(uint256.Int).Set(m.bal(a))
	m.balance[a] = new(uint256.Int).Add(prev, v)
	return *prev
}

func (m *StateDB) SubBalance(a common.Address, v *uint256.Int, _ tracing.BalanceChangeReason) uint256.Int {
	prev := new(uint256.Int).Set(m.bal(a))
	m.balance[a] = new(uint256.Int).Sub(prev, v)
	return *prev
}

func (m *StateDB) SetNonce(common.Address, uint64, tracing.NonceChangeReason)         {}
func (m *StateDB) GetNonce(common.Address) uint64                                     { return 0 }
func (m *StateDB) GetBalanceMultiCoin(common.Address, common.Hash) *big.Int           { return big.NewInt(0) }
func (m *StateDB) AddBalanceMultiCoin(common.Address, common.Hash, *big.Int)          {}
func (m *StateDB) SubBalanceMultiCoin(common.Address, common.Hash, *big.Int)          {}
func (m *StateDB) CreateAccount(common.Address)                                       {}
func (m *StateDB) Exist(common.Address) bool                                          { return false }
func (m *StateDB) AddLog(*ethtypes.Log)                                               {}
func (m *StateDB) Logs() []*ethtypes.Log                                              { return nil }
func (m *StateDB) GetPredicateStorageSlots(common.Address, int) ([]byte, bool)        { return nil, false }
func (m *StateDB) TxHash() common.Hash                                                { return common.Hash{} }
func (m *StateDB) Snapshot() int                                                      { return 0 }
func (m *StateDB) RevertToSnapshot(int)                                               {}

var _ contract.StateDB = (*StateDB)(nil)

// blockCtx carries a mutable height so the harness can advance the chain across
// the commit / reveal / settle windows.
type blockCtx struct{ n uint64 }

func (b *blockCtx) Number() *big.Int                                       { return new(big.Int).SetUint64(b.n) }
func (b *blockCtx) Timestamp() uint64                                      { return 1000 + b.n }
func (b *blockCtx) GetPredicateResults(common.Hash, common.Address) []byte { return nil }

type chainCfg struct{}

func (chainCfg) IsDurango(uint64) bool { return true }

type env struct{}

func (env) ReadOnly() bool { return false }

// AccessibleState is the in-memory contract.AccessibleState wrapping a StateDB and
// a settable block height. Drive a precompile with Precompile.Run(host, ...).
type AccessibleState struct {
	db  *StateDB
	blk *blockCtx
}

// New returns a host at block height 1.
func New() *AccessibleState {
	return &AccessibleState{db: NewStateDB(), blk: &blockCtx{n: 1}}
}

// DB exposes the underlying in-memory state for funding + balance assertions.
func (a *AccessibleState) DB() *StateDB { return a.db }

// Advance sets the block height the next Run will observe.
func (a *AccessibleState) Advance(n uint64) { a.blk.n = n }

// Block returns the current height.
func (a *AccessibleState) Block() uint64 { return a.blk.n }

func (a *AccessibleState) GetStateDB() contract.StateDB                 { return a.db }
func (a *AccessibleState) GetBlockContext() contract.BlockContext       { return a.blk }
func (a *AccessibleState) GetConsensusContext() context.Context         { return context.Background() }
func (a *AccessibleState) GetChainConfig() precompileconfig.ChainConfig { return chainCfg{} }
func (a *AccessibleState) GetPrecompileEnv() contract.PrecompileEnvironment {
	return env{}
}

var _ contract.AccessibleState = (*AccessibleState)(nil)
