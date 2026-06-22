// Copyright (C) 2026, Hanzo AI Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Command quorumproof drives the REAL native engine and PRINTS the hashes that
// prove an LLM quorum forms off-chain, exactly as the on-chain precompile would
// settle them. It is the human-readable companion to quorum_test.go.
//
// Run:
//
//	HANZO_FFI_MODELS="zen-nano=gguf:/tmp/zen5-weights/zen-5-flash.gguf;zen-embed=embedding:/tmp/zen-embedding-0.6B" \
//	  HANZO_FFI_TOK_DIR=/tmp/zen-nano-fused \
//	  GOWORK=off CGO_ENABLED=1 SDKROOT=$(xcrun --show-sdk-path) CPATH=$SDKROOT/usr/include \
//	  go run ./cmd/quorumproof
package main

import (
	"fmt"
	"os"

	op "github.com/hanzoai/chains/hanzo-evm/operator"
	"github.com/hanzoai/chains/hanzo-evm/operator/canonical"
	aiquorum "github.com/hanzoai/chains/hanzo-evm/precompile/aiquorum"
	"github.com/luxfi/crypto"
	"github.com/luxfi/geth/common"
)

const (
	inferModel = "zen-nano"
	embedModel = "zen-embed"
)

func spec() canonical.ModelSpec {
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

func newOp() *op.Operator {
	k, err := crypto.GenerateKey()
	if err != nil {
		fatal("genkey: %v", err)
	}
	return op.NewOperator(k, inferModel, embedModel, spec())
}

func fatal(f string, a ...any) {
	fmt.Fprintf(os.Stderr, "ERROR: "+f+"\n", a...)
	os.Exit(1)
}

func main() {
	fmt.Println("== LLM quorum settlement — off-chain operator proof (real engine, cgo) ==")
	if !op.EngineReady() {
		fatal("engine not ready — set HANZO_FFI_MODELS and HANZO_FFI_TOK_DIR")
	}
	s := spec()
	specHash := s.ModelSpecHash()

	// On/off-chain spec-hash agreement, printed.
	onSpec := aiquorum.ComputeModelSpecHash(aiquorum.ModelSpec{
		ModelID: s.ModelID, ModelHash: s.ModelHash, TokenizerHash: s.TokenizerHash,
		RuntimeVersion: s.RuntimeVersion, SamplingHash: s.SamplingHash,
		PromptTemplateHash: s.PromptTemplateHash, EmbeddingModelHash: s.EmbeddingModelHash,
	})
	fmt.Printf("\nmodel_spec_hash (off-chain) = %s\n", specHash.Hex())
	fmt.Printf("model_spec_hash (on-chain)  = %s  [%s]\n", onSpec.Hex(), eq(specHash == onSpec))

	jobID := common.HexToHash("0xABCDEF00000000000000000000000000000000000000000000000000000000aa")
	prompt := []byte("Reply with exactly: I am Zen.")
	embedText := []byte("The quick brown fox jumps over the lazy dog.")

	// ---- RAW: three honest operators ----
	fmt.Println("\n--- RAW mode: 3 honest operators (same spec+prompt, distinct keys) ---")
	var reveals []*op.Reveal
	for i := 0; i < 3; i++ {
		o := newOp()
		r, err := o.Run(jobID, prompt, embedText, op.ModeRaw)
		if err != nil {
			fatal("op%d run: %v", i, err)
		}
		reveals = append(reveals, r)
		fmt.Printf("op%d addr=%s\n     output_hash   =%s\n     embedding_hash=%s\n     commit        =%s\n     sig[:8]       =%x\n",
			i, r.Operator.Hex(), r.OutputHash.Hex(), r.EmbeddingHash.Hex(), r.Commit.Hex(), r.Signature[:8])
	}

	sameOut := reveals[0].OutputHash == reveals[1].OutputHash && reveals[1].OutputHash == reveals[2].OutputHash
	sameEmb := reveals[0].EmbeddingHash == reveals[1].EmbeddingHash && reveals[1].EmbeddingHash == reveals[2].EmbeddingHash
	diffCommit := reveals[0].Commit != reveals[1].Commit && reveals[1].Commit != reveals[2].Commit && reveals[0].Commit != reveals[2].Commit
	fmt.Printf("\n  output_hash identical across 3 honest   : %s\n", eq(sameOut))
	fmt.Printf("  embedding_hash identical across 3 honest: %s\n", eq(sameEmb))
	fmt.Printf("  commits all DIFFERENT (operator-bound)  : %s\n", eq(diffCommit))

	// Verify each reveal recovers to its signer and binds its commit.
	allVerify := true
	for _, r := range reveals {
		signer, err := op.RecoverReveal(r)
		if err != nil || signer != r.Operator {
			allVerify = false
		}
	}
	fmt.Printf("  every reveal sig recovers to its operator: %s\n", eq(allVerify))

	// ---- divergent 4th operator ----
	fmt.Println("\n--- RAW mode: 4th divergent operator (tampered output) ---")
	bad := newOp()
	badR, err := bad.Run(jobID, prompt, embedText, op.ModeRaw)
	if err != nil {
		fatal("bad op run: %v", err)
	}
	tampered := append(append([]byte(nil), badR.OutputRaw...), []byte(" -- tampered")...)
	badR.OutputHash = canonical.OutputHashRaw(tampered)
	fmt.Printf("divergent addr=%s\n     output_hash=%s  [%s vs quorum]\n",
		badR.Operator.Hex(), badR.OutputHash.Hex(), neq(badR.OutputHash != reveals[0].OutputHash))

	// Plurality tally (mirrors precompile's group-by-output_hash).
	groups := map[common.Hash]int{}
	for _, r := range reveals {
		groups[r.OutputHash]++
	}
	groups[badR.OutputHash]++
	winner := reveals[0].OutputHash
	const threshold = 3
	fmt.Printf("\n  tally: honest group=%d, divergent group=%d, threshold=%d\n", groups[winner], groups[badR.OutputHash], threshold)
	fmt.Printf("  QUORUM SETTLES on %s : %s\n", winner.Hex(), eq(groups[winner] >= threshold))
	fmt.Printf("  divergent operator EXCLUDED              : %s\n", eq(groups[badR.OutputHash] < threshold))

	// ---- GOVERNANCE: different rationale, same consensus ----
	fmt.Println("\n--- GOVERNANCE mode: 3 operators, DIFFERENT rationale, SAME {vote,bucket} ---")
	hex := specHash.Hex()
	raws := [][]byte{
		[]byte(`{"vote":"yes","confidence_bps":7600,"rationale":"Approve. Core infra; budget justified.","citations":["ipfs://QmA"],"model_spec":"` + hex + `"}`),
		[]byte(`{"vote":"yes","confidence_bps":8200,"rationale":"YES — sound infra spend, numbers check out.","citations":[],"model_spec":"` + hex + `"}`),
		[]byte(`{"vote":"yes","confidence_bps":8499,"rationale":"I support this; minor timeline reservations.","citations":["https://f/42"],"model_spec":"` + hex + `"}`),
	}
	var gov []common.Hash
	for i, raw := range raws {
		d, perr := canonical.ParseDecision(raw, specHash)
		if perr != nil {
			fatal("op%d gov parse: %v", i, perr)
		}
		oh := canonical.OutputHashGovernance(d)
		gov = append(gov, oh)
		fmt.Printf("op%d vote=%s conf=%dbps bucket=%dbps\n     rationale=%q\n     output_hash=%s\n",
			i, d.Vote, d.ConfidenceBps, d.BucketBps(), d.Rationale, oh.Hex())
		// Show the audit record is canonical + injection-safe.
		if i == 0 {
			r := &op.Reveal{JobID: jobID, SpecHash: specHash, OutputHash: oh, Mode: op.ModeGovernance, Decision: &d, Operator: reveals[0].Operator}
			fmt.Printf("     audit JSON (RFC8785) = %s\n", string(r.AuditRecord().CanonicalJSON()))
		}
	}
	govSame := gov[0] == gov[1] && gov[1] == gov[2]
	fmt.Printf("\n  governance consensus identical (rationale excluded): %s\n", eq(govSame))
	fmt.Printf("  GOVERNANCE QUORUM SETTLES on %s\n", gov[0].Hex())

	fmt.Println("\n== PROOF COMPLETE ==")
	ok := (specHash == onSpec) && sameOut && sameEmb && diffCommit && allVerify &&
		groups[winner] >= threshold && groups[badR.OutputHash] < threshold && govSame
	if !ok {
		fatal("one or more proof conditions FAILED (see above)")
	}
	fmt.Println("All conditions hold: honest operators agree (quorum forms), divergent excluded,")
	fmt.Println("governance rationale differs but consensus matches, on/off-chain hashes equal.")
}

func eq(b bool) string {
	if b {
		return "MATCH"
	}
	return "*** MISMATCH ***"
}
func neq(b bool) string {
	if b {
		return "DIFFERENT"
	}
	return "*** SAME (BAD) ***"
}
