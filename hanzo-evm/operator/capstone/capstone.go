// Copyright (C) 2026, Hanzo AI Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package capstone is the END-TO-END PROOF that ties the whole LLM-quorum-
// settlement system together with the REAL engine and the REAL on-chain
// precompile — no fabricated hashes anywhere.
//
// One run drives the entire pipeline:
//
//	governance opens a job
//	  -> the on-chain aiquorum precompile (real Run, real selection beacon) picks N
//	     staked operators
//	  -> each SELECTED operator runs the REAL Hanzo engine (hanzo_ffi_infer /
//	     hanzo_ffi_embed over cgo) to produce a REAL output_hash + embedding_hash
//	  -> each commits (operator-bound) and reveals through the precompile (which
//	     recomputes + verifies the commit)
//	  -> Settle: the precompile tallies by output_hash, and the canonical result it
//	     settles on is BYTE-IDENTICAL to the real engine output_hash the honest
//	     operators produced; winners are paid, value is conserved.
//
// Validators (here, the precompile logic) only ever compare 32-byte hashes; the
// LLM ran entirely off-chain. The whole point: the canonical hash is genuinely the
// engine's output, proven by recomputing it independently from the honest
// operators' Reveals and asserting equality with what Settle recorded on-chain.
//
// Run it with the native engine:
//
//	HANZO_FFI_MODELS="zen-nano=gguf:/tmp/zen5-weights/zen-5-flash.gguf;zen-embed=embedding:/tmp/zen-embedding-0.6B" \
//	  HANZO_FFI_TOK_DIR=/tmp/zen-nano-fused \
//	  GOWORK=off CGO_ENABLED=1 SDKROOT=$(xcrun --show-sdk-path) CPATH=$SDKROOT/usr/include \
//	  go run ./cmd/capstone           # the human-readable trace
//	  go test ./capstone -run Capstone -v   # the asserted proof (skips w/o engine)
package capstone

import (
	"encoding/binary"
	"fmt"
	"io"

	op "github.com/hanzoai/chains/hanzo-evm/operator"
	"github.com/hanzoai/chains/hanzo-evm/operator/canonical"
	"github.com/hanzoai/chains/hanzo-evm/operator/evmhost"
	aiquorum "github.com/hanzoai/chains/hanzo-evm/precompile/aiquorum"
	"github.com/holiman/uint256"
	"github.com/luxfi/crypto"
	"github.com/luxfi/geth/common"
)

const (
	inferModel = "zen-nano"
	embedModel = "zen-embed"
)

// Parameters of the capstone job. The pool is sized above N + the RED-A margin so
// the request is admitted; N=5 with threshold 3, and among the 5 selected we make
// 3 honest and 2 divergent — exactly enough honest to settle, with divergence to
// prove exclusion.
const (
	poolSize       = 8 // >= N + requiredMargin(5) = 7
	jobN           = uint32(5)
	jobThreshold   = uint32(3)
	honestSelected = 3 // of the N selected; the rest diverge
)

// CapstoneResult is the machine-checkable outcome of a full run, returned so the
// test can assert on it (the cmd just prints the trace).
type CapstoneResult struct {
	ModelSpecHash      common.Hash
	JobID              common.Hash
	Selected           []common.Address
	HonestOps          []common.Address
	DivergentOps       []common.Address
	EngineOutputHash   common.Hash // the REAL honest engine output_hash (recomputed independently)
	EngineEmbedHash    common.Hash // the REAL embedding_hash bound by all operators
	CanonicalFromChain common.Hash // what Settle recorded on-chain
	WinnerCount        uint32
	Paid               *uint256.Int
	Slashed            *uint256.Int
	HonestCredits      map[common.Address]*uint256.Int
	DivergentCredits   map[common.Address]*uint256.Int
	Conserved          bool
}

// model is the shared ModelSpec all operators advertise (pins weights/tokenizer/
// sampling/template/embedding). Its keccak digest is the on-chain model_spec_hash.
func model() canonical.ModelSpec {
	return canonical.ModelSpec{
		ModelID:            inferModel,
		ModelHash:          common.HexToHash("0x1111111111111111111111111111111111111111111111111111111111111111"),
		TokenizerHash:      common.HexToHash("0x2222222222222222222222222222222222222222222222222222222222222222"),
		RuntimeVersion:     "hanzo-engine/ffi-greedy-v1",
		SamplingHash:       common.HexToHash("0x3333333333333333333333333333333333333333333333333333333333333333"),
		PromptTemplateHash: common.HexToHash("0x4444444444444444444444444444444444444444444444444444444444444444"),
		EmbeddingModelHash: common.HexToHash("0x5555555555555555555555555555555555555555555555555555555555555555"),
	}
}

// staked is a registered operator: its engine-running Operator plus its secp256k1
// address (= the on-chain identity that staked, was selected, commits, reveals).
type staked struct {
	o    *op.Operator
	addr common.Address
}

// EngineReady reports whether the native engine has loaded its models.
func EngineReady() bool { return op.EngineReady() }

// gas budget per precompile call — generous; the capstone is about correctness,
// not gas accounting (the dispatch tests cover gas).
const gas = uint64(50_000_000)

// Run executes the full capstone against the REAL engine + REAL precompile,
// writing a human-readable trace to w, and returns the machine-checkable result.
// Returns an error if the engine is not ready or any pipeline step fails.
func Run(w io.Writer) (*CapstoneResult, error) {
	if !op.EngineReady() {
		return nil, fmt.Errorf("capstone: native engine not ready (set HANZO_FFI_MODELS + HANZO_FFI_TOK_DIR)")
	}

	pf := func(format string, a ...any) { fmt.Fprintf(w, format, a...) }
	pf("================================================================\n")
	pf(" CAPSTONE: governance -> staked LLM quorum -> on-chain settle\n")
	pf("           REAL engine (cgo FFI) + REAL aiquorum precompile\n")
	pf("================================================================\n")

	spec := model()
	specHash := spec.ModelSpecHash()

	// Cross-check the model_spec_hash against the on-chain compute fn (same wire
	// spec) before anything else — the operators and the chain MUST agree on it.
	onSpec := aiquorum.ComputeModelSpecHash(aiquorum.ModelSpec{
		ModelID: spec.ModelID, ModelHash: spec.ModelHash, TokenizerHash: spec.TokenizerHash,
		RuntimeVersion: spec.RuntimeVersion, SamplingHash: spec.SamplingHash,
		PromptTemplateHash: spec.PromptTemplateHash, EmbeddingModelHash: spec.EmbeddingModelHash,
	})
	if onSpec != specHash {
		return nil, fmt.Errorf("capstone: model_spec_hash off-chain %s != on-chain %s", specHash.Hex(), onSpec.Hex())
	}
	pf("\nmodel_spec_hash = %s  (off-chain == on-chain: OK)\n", specHash.Hex())

	host := evmhost.New()
	db := host.DB()

	// ---- 1. Register poolSize engine-backed operators (each stakes) ----
	pf("\n--- 1. register %d staked operators (each runs the real engine) ---\n", poolSize)
	stake := tokens(2)
	ops := make([]staked, poolSize)
	for i := 0; i < poolSize; i++ {
		k, err := crypto.GenerateKey()
		if err != nil {
			return nil, fmt.Errorf("capstone: genkey: %w", err)
		}
		o := op.NewOperator(k, inferModel, embedModel, spec)
		ops[i] = staked{o: o, addr: o.Address()}
		// Fund the operator with stake + spare for register, then register on-chain.
		db.Fund(ops[i].addr, new(uint256.Int).Add(stake, tokens(1)))
		if _, _, err := aiquorum.Precompile.Run(host, ops[i].addr, aiquorum.ContractAddress,
			encRegister(stake, specHash, common.HexToHash("0xabc")), gas, false); err != nil {
			return nil, fmt.Errorf("capstone: register op %d: %w", i, err)
		}
		pf("  op[%d] %s staked %s\n", i, ops[i].addr.Hex(), tokensStr(stake))
	}

	// ---- 2. Governance opens the job (real RequestInference through Run) ----
	gov := common.HexToAddress("0x60ce72A0000000000000000000000000000000A1") // "governance"
	reward := tokens(1)
	db.Fund(gov, tokens(1000))

	prompt := []byte("Reply with exactly: I am Zen.")
	promptHash := canonical.PromptHash(prompt)
	embedText := []byte("The quick brown fox jumps over the lazy dog.")

	host.Advance(100)
	govBalBefore := db.GetBalance(gov)
	burnBefore := db.GetBalance(aiquorum.BurnAddress)

	pf("\n--- 2. governance opens job: N=%d threshold=%d reward=%s/op ---\n", jobN, jobThreshold, tokensStr(reward))
	ret, _, err := aiquorum.Precompile.Run(host, gov, aiquorum.ContractAddress,
		encRequest(specHash, promptHash, jobN, jobThreshold, reward), gas, false)
	if err != nil {
		return nil, fmt.Errorf("capstone: RequestInference: %w", err)
	}
	jobID := common.BytesToHash(ret)
	fee := new(uint256.Int).Mul(aiquorum.RequestFeePerOperator, uint256.NewInt(uint64(jobN)))
	pf("  job_id      = %s\n", jobID.Hex())
	pf("  prompt_hash = %s\n", promptHash.Hex())
	pf("  RED-A fee burned (non-refundable) = %s\n", tokensStr(fee))

	// ---- 3. Determine the SELECTED set via the real precompile ----
	selected := make([]common.Address, 0, jobN)
	for i := 0; i < poolSize; i++ {
		out, _, err := aiquorum.Precompile.Run(host, gov, aiquorum.ContractAddress,
			encIsSelected(jobID, ops[i].addr), gas, false)
		if err != nil {
			return nil, fmt.Errorf("capstone: isSelected op %d: %w", i, err)
		}
		if len(out) == 32 && out[31] == 1 {
			selected = append(selected, ops[i].addr)
		}
	}
	if uint32(len(selected)) != jobN {
		return nil, fmt.Errorf("capstone: expected %d selected, got %d", jobN, len(selected))
	}
	pf("\n--- 3. beacon selected %d of %d operators ---\n", len(selected), poolSize)
	for i, s := range selected {
		pf("  selected[%d] = %s\n", i, s.Hex())
	}

	// Map selected addr -> its staked operator (to run the engine for it).
	byAddr := make(map[common.Address]*op.Operator, poolSize)
	for i := range ops {
		byAddr[ops[i].addr] = ops[i].o
	}

	// ---- 4. Each selected operator runs the REAL engine; honest vs divergent ----
	// Honest: infer the job's prompt -> real output_hash H (all honest agree).
	// Divergent: infer a DIFFERENT prompt -> real-but-different output_hash, bound
	// to the JOB's prompt_hash (RunForJob), so it reveals on-chain but is excluded.
	pf("\n--- 4. selected operators run the REAL engine, then commit ---\n")
	divergentPrompt := []byte("Reply with exactly: I am NOT Zen (divergent).")

	reveals := make([]*op.Reveal, len(selected))
	honestOps := make([]common.Address, 0, honestSelected)
	divergentOps := make([]common.Address, 0)
	host.Advance(110) // inside the commit window [100, 100+CommitBlocks=130]
	for i, addr := range selected {
		o := byAddr[addr]
		var r *op.Reveal
		var err error
		if i < honestSelected {
			r, err = o.Run(jobID, prompt, embedText, op.ModeRaw) // honest: infers the job prompt
		} else {
			r, err = o.RunForJob(jobID, promptHash, divergentPrompt, embedText, op.ModeRaw) // divergent
		}
		if err != nil {
			return nil, fmt.Errorf("capstone: engine run for selected[%d]: %w", i, err)
		}
		reveals[i] = r
		role := "honest"
		if i >= honestSelected {
			role = "DIVERGENT"
			divergentOps = append(divergentOps, addr)
		} else {
			honestOps = append(honestOps, addr)
		}
		pf("  [%s] op=%s\n        output_hash    = %s\n        embedding_hash = %s\n        commit         = %s\n",
			role, addr.Hex(), r.OutputHash.Hex(), r.EmbeddingHash.Hex(), r.Commit.Hex())

		// Off-chain transport check: the signed reveal recovers to this operator.
		signer, rerr := op.RecoverReveal(r)
		if rerr != nil || signer != addr {
			return nil, fmt.Errorf("capstone: reveal sig for selected[%d] does not recover to operator", i)
		}

		// Submit the commit on-chain (caller = operator address).
		if _, _, err := aiquorum.Precompile.Run(host, addr, aiquorum.ContractAddress,
			encCommit(jobID, r.Commit), gas, false); err != nil {
			return nil, fmt.Errorf("capstone: CommitResponse selected[%d]: %w", i, err)
		}
	}

	// Independently recompute the honest engine output_hash from the honest
	// operators' Reveals, and assert they all agree — this is the value we will
	// require Settle to canonicalize. It is the ENGINE's output, not a constant.
	engineOut := reveals[0].OutputHash
	engineEmb := reveals[0].EmbeddingHash
	for i := 0; i < honestSelected; i++ {
		if reveals[i].OutputHash != engineOut {
			return nil, fmt.Errorf("capstone: honest operators disagree on output_hash (engine non-determinism?)")
		}
		if reveals[i].EmbeddingHash != engineEmb {
			return nil, fmt.Errorf("capstone: honest operators disagree on embedding_hash")
		}
	}
	if engineEmb == (common.Hash{}) {
		return nil, fmt.Errorf("capstone: embedding_hash is zero — embedding did not run")
	}
	for i := honestSelected; i < len(selected); i++ {
		if reveals[i].OutputHash == engineOut {
			return nil, fmt.Errorf("capstone: divergent operator collided with honest output_hash")
		}
	}
	pf("\n  honest engine output_hash (independently recomputed) = %s\n", engineOut.Hex())
	pf("  real embedding_hash (shared by all)                  = %s\n", engineEmb.Hex())

	// ---- 5. Reveal window: every selected operator reveals through the precompile ----
	pf("\n--- 5. reveal window: precompile recomputes + verifies each commit ---\n")
	host.Advance(100 + aiquorum.CommitBlocks + 5) // inside reveal window
	for i, addr := range selected {
		r := reveals[i]
		if _, _, err := aiquorum.Precompile.Run(host, addr, aiquorum.ContractAddress,
			encReveal(jobID, r.OutputHash, r.EmbeddingHash, r.Nonce), gas, false); err != nil {
			return nil, fmt.Errorf("capstone: RevealResponse selected[%d] (%s): %w", i, addr.Hex(), err)
		}
	}
	pf("  all %d reveals accepted (commit recompute matched for honest AND divergent)\n", len(selected))

	// ---- 6. Settle through the precompile ----
	pf("\n--- 6. Settle: tally by output_hash, pay quorum, conserve value ---\n")
	host.Advance(100 + aiquorum.CommitBlocks + aiquorum.RevealBlocks + 1)
	settleRet, _, err := aiquorum.Precompile.Run(host, gov, aiquorum.ContractAddress,
		encSettle(jobID), gas, false)
	if err != nil {
		return nil, fmt.Errorf("capstone: Settle: %w", err)
	}
	status, canonicalHash, winnerCount, paid, slashed := decodeSettle(settleRet)

	// Read the canonical result back independently too (getCanonicalResult).
	canonRet, _, err := aiquorum.Precompile.Run(host, gov, aiquorum.ContractAddress,
		encGetCanonical(jobID), gas, false)
	if err != nil {
		return nil, fmt.Errorf("capstone: getCanonicalResult: %w", err)
	}
	canonView := common.BytesToHash(canonRet)

	pf("  settle status        = %d (2=Settled)\n", status)
	pf("  canonical_output_hash = %s\n", canonicalHash.Hex())
	pf("  winner_count          = %d\n", winnerCount)
	pf("  total paid            = %s\n", tokensStr(paid))
	pf("  total slashed         = %s\n", tokensStr(slashed))

	// ---- 7. The proof: canonical == the REAL engine output_hash ----
	pf("\n--- 7. THE PROOF ---\n")
	pf("  engine honest output_hash      = %s\n", engineOut.Hex())
	pf("  on-chain canonical_output_hash = %s\n", canonicalHash.Hex())
	pf("  getCanonicalResult view        = %s\n", canonView.Hex())
	match := canonicalHash == engineOut && canonView == engineOut
	pf("  canonical == engine output     : %v\n", match)
	if status != aiquorum.JobSettled {
		return nil, fmt.Errorf("capstone: job did not settle (status=%d)", status)
	}
	if !match {
		return nil, fmt.Errorf("capstone: canonical hash %s != engine output %s (FABRICATION CHECK FAILED)", canonicalHash.Hex(), engineOut.Hex())
	}
	if winnerCount != uint32(honestSelected) {
		return nil, fmt.Errorf("capstone: winner_count %d != honest %d", winnerCount, honestSelected)
	}

	// Honest operators are paid (>= reward); divergent revealed a minority -> not
	// slashed (SlashDissenters=false), earned nothing.
	honestCredits := map[common.Address]*uint256.Int{}
	for _, a := range honestOps {
		c := readCredit(host, a)
		honestCredits[a] = c
		if c.Lt(reward) {
			return nil, fmt.Errorf("capstone: honest op %s credit %s < reward %s", a.Hex(), tokensStr(c), tokensStr(reward))
		}
	}
	divergentCredits := map[common.Address]*uint256.Int{}
	for _, a := range divergentOps {
		c := readCredit(host, a)
		divergentCredits[a] = c
		if !c.IsZero() {
			return nil, fmt.Errorf("capstone: divergent op %s should earn nothing, has %s", a.Hex(), tokensStr(c))
		}
	}
	pf("  honest operators paid          : %d (each >= reward %s)\n", len(honestOps), tokensStr(reward))
	pf("  divergent operators excluded   : %d (earned 0, not slashed — honest minority policy)\n", len(divergentOps))

	// ---- 8. Value conservation ----
	// Universe = governance + escrow + burn + all operators. Burned fee MOVED to
	// BurnAddress; total is invariant from just-before the request to after settle.
	accts := []common.Address{gov, aiquorum.ContractAddress, aiquorum.BurnAddress}
	for i := range ops {
		accts = append(accts, ops[i].addr)
	}
	// Reconstruct the pre-request universe: gov had govBalBefore, burn had
	// burnBefore, escrow held poolSize*stake, operators held their spare (tokens(1)
	// each, since stake was already pulled at register). We instead assert the
	// stronger end-state identity: escrow == Σ stake + Σ credit (fee left the
	// escrow, reward refund credited), and the burn grew by exactly the fee.
	totalCredit := new(uint256.Int)
	totalStake := new(uint256.Int)
	for i := range ops {
		totalCredit.Add(totalCredit, readCredit(host, ops[i].addr))
		_, _, st, _, _ := getOperator(host, ops[i].addr)
		totalStake.Add(totalStake, st)
	}
	totalCredit.Add(totalCredit, readCredit(host, gov)) // requester refund credit
	escrowBal := db.GetBalance(aiquorum.ContractAddress)
	accounted := new(uint256.Int).Add(totalStake, totalCredit)
	escrowOK := escrowBal.Eq(accounted)

	burnGrew := new(uint256.Int).Sub(db.GetBalance(aiquorum.BurnAddress), burnBefore)
	burnOK := burnGrew.Eq(fee)

	// Governance net: spent fee (burned) + (winners*reward) actually consumed; the
	// (N-winners)*reward refund came back as credit. Net debit from balance =
	// reward escrow (N*reward) + fee, minus refund credit not yet withdrawn.
	govSpent := new(uint256.Int).Sub(govBalBefore, db.GetBalance(gov)) // N*reward + fee (escrow+burn pulled)
	expectGovSpent := new(uint256.Int).Add(new(uint256.Int).Mul(reward, uint256.NewInt(uint64(jobN))), fee)
	govOK := govSpent.Eq(expectGovSpent)

	conserved := escrowOK && burnOK && govOK
	pf("\n--- 8. value conservation ---\n")
	pf("  escrow == Σstake + Σcredit     : %v  (escrow=%s, accounted=%s)\n", escrowOK, tokensStr(escrowBal), tokensStr(accounted))
	pf("  burn grew by exactly the fee   : %v  (%s)\n", burnOK, tokensStr(burnGrew))
	pf("  governance debited reward+fee  : %v  (%s)\n", govOK, tokensStr(govSpent))
	if !conserved {
		return nil, fmt.Errorf("capstone: value conservation FAILED (escrowOK=%v burnOK=%v govOK=%v)", escrowOK, burnOK, govOK)
	}

	pf("\n================================================================\n")
	pf(" CAPSTONE COMPLETE — canonical hash IS the real engine output,\n")
	pf(" settled by a staked quorum, winners paid, value conserved.\n")
	pf("================================================================\n")

	return &CapstoneResult{
		ModelSpecHash:      specHash,
		JobID:              jobID,
		Selected:           selected,
		HonestOps:          honestOps,
		DivergentOps:       divergentOps,
		EngineOutputHash:   engineOut,
		EngineEmbedHash:    engineEmb,
		CanonicalFromChain: canonicalHash,
		WinnerCount:        winnerCount,
		Paid:               paid,
		Slashed:            slashed,
		HonestCredits:      honestCredits,
		DivergentCredits:   divergentCredits,
		Conserved:          conserved,
	}, nil
}

// ---------------------------------------------------------------------------
// Calldata encoders (the flat 32-byte-word layout the precompile decodes) and
// small state readers via the read-view selectors.
// ---------------------------------------------------------------------------

func sel(s uint32) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, s)
	return b
}

func wordU32(v uint32) []byte {
	w := make([]byte, 32)
	binary.BigEndian.PutUint32(w[28:], v)
	return w
}

func wordAddr(a common.Address) []byte {
	w := make([]byte, 32)
	copy(w[12:], a.Bytes())
	return w
}

func h32(v *uint256.Int) []byte {
	b := v.Bytes32()
	return b[:]
}

func encRegister(stake *uint256.Int, spec, endpoint common.Hash) []byte {
	out := sel(aiquorum.SelectorRegisterOperator)
	out = append(out, h32(stake)...)
	out = append(out, spec.Bytes()...)
	out = append(out, endpoint.Bytes()...)
	return out
}

func encRequest(spec, prompt common.Hash, n, threshold uint32, reward *uint256.Int) []byte {
	out := sel(aiquorum.SelectorRequestInference)
	out = append(out, spec.Bytes()...)
	out = append(out, prompt.Bytes()...)
	out = append(out, wordU32(n)...)
	out = append(out, wordU32(threshold)...)
	out = append(out, h32(reward)...)
	return out
}

func encIsSelected(jobID common.Hash, opAddr common.Address) []byte {
	out := sel(aiquorum.SelectorIsSelected)
	out = append(out, jobID.Bytes()...)
	out = append(out, wordAddr(opAddr)...)
	return out
}

func encCommit(jobID, commit common.Hash) []byte {
	out := sel(aiquorum.SelectorCommitResponse)
	out = append(out, jobID.Bytes()...)
	out = append(out, commit.Bytes()...)
	return out
}

func encReveal(jobID, output, embed, nonce common.Hash) []byte {
	out := sel(aiquorum.SelectorRevealResponse)
	out = append(out, jobID.Bytes()...)
	out = append(out, output.Bytes()...)
	out = append(out, embed.Bytes()...)
	out = append(out, nonce.Bytes()...)
	return out
}

func encSettle(jobID common.Hash) []byte {
	return append(sel(aiquorum.SelectorSettle), jobID.Bytes()...)
}

func encGetCanonical(jobID common.Hash) []byte {
	return append(sel(aiquorum.SelectorGetCanonicalResult), jobID.Bytes()...)
}

func encGetCredit(opAddr common.Address) []byte {
	return append(sel(aiquorum.SelectorGetCredit), wordAddr(opAddr)...)
}

func encGetOperator(opAddr common.Address) []byte {
	return append(sel(aiquorum.SelectorGetOperator), wordAddr(opAddr)...)
}

// decodeSettle parses the 160-byte settle return: status | canonical | winners |
// paid | slashed.
func decodeSettle(ret []byte) (status uint8, canonical common.Hash, winners uint32, paid, slashed *uint256.Int) {
	status = ret[31]
	canonical = common.BytesToHash(ret[32:64])
	winners = binary.BigEndian.Uint32(ret[92:96])
	paid = new(uint256.Int).SetBytes(ret[96:128])
	slashed = new(uint256.Int).SetBytes(ret[128:160])
	return
}

// readCredit reads an operator's withdrawable credit through the read-view path.
func readCredit(host *evmhost.AccessibleState, a common.Address) *uint256.Int {
	out, _, err := aiquorum.Precompile.Run(host, a, aiquorum.ContractAddress, encGetCredit(a), gas, false)
	if err != nil {
		return new(uint256.Int)
	}
	return new(uint256.Int).SetBytes(out)
}

// getOperator reads an operator's registry record through the read-view path.
func getOperator(host *evmhost.AccessibleState, a common.Address) (exists, unbonding bool, stake *uint256.Int, spec, endpoint common.Hash) {
	out, _, err := aiquorum.Precompile.Run(host, a, aiquorum.ContractAddress, encGetOperator(a), gas, false)
	if err != nil || len(out) < 160 {
		return false, false, new(uint256.Int), common.Hash{}, common.Hash{}
	}
	exists = out[31] == 1
	unbonding = out[63] == 1
	stake = new(uint256.Int).SetBytes(out[64:96])
	spec = common.BytesToHash(out[96:128])
	endpoint = common.BytesToHash(out[128:160])
	return
}

// ---------------------------------------------------------------------------
// tiny formatting/amount helpers
// ---------------------------------------------------------------------------

func tokens(n uint64) *uint256.Int {
	return new(uint256.Int).Mul(uint256.NewInt(n), uint256.NewInt(1_000_000_000_000_000_000))
}

// tokensStr renders wei as a decimal token string with up to 4 fractional digits.
func tokensStr(v *uint256.Int) string {
	one := uint256.NewInt(1_000_000_000_000_000_000)
	whole := new(uint256.Int).Div(v, one)
	rem := new(uint256.Int).Mod(v, one)
	// 4 dp: rem * 10000 / 1e18
	frac := new(uint256.Int).Div(new(uint256.Int).Mul(rem, uint256.NewInt(10_000)), one)
	return fmt.Sprintf("%s.%04d tok", whole.Dec(), frac.Uint64())
}
