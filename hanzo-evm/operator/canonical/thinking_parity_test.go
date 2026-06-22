// Copyright (C) 2026, Hanzo AI Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package canonical

import (
	"encoding/binary"
	"testing"

	"github.com/luxfi/crypto"
	"github.com/luxfi/geth/common"
)

// TestThinkingGovernorGoldenParity pins the cross-language golden vector shared
// with the on-chain ThinkingGovernor Solidity test
// (lux/dao/contracts/foundry-test/ThinkingGovernor.t.sol). If this test and the
// Solidity test agree on these constants, the off-chain operator and the on-chain
// governor hash the SAME bytes — quorum formed off-chain is verifiable on-chain.
//
// Golden vector: modelSpecHash = keccak256("zen/thinking-governor/model-spec/v1"),
// vote = yes (1), confidence bucket = 8000 bps (80%).
func TestThinkingGovernorGoldenParity(t *testing.T) {
	spec := common.BytesToHash(crypto.Keccak256([]byte("zen/thinking-governor/model-spec/v1")))
	const wantSpec = "0xe48ded87386a1be78fd0407f658f49b15bd4e27773758004db1236537ba2ac70"
	if spec.Hex() != wantSpec {
		t.Fatalf("model spec hash = %s, want %s", spec.Hex(), wantSpec)
	}

	d := Decision{ModelSpecHash: spec, Vote: VoteYes, ConfidenceBps: 8000}

	// Bucket must be exactly 8000 (already on-grid, banker's rounding is identity).
	if got := d.BucketBps(); got != 8000 {
		t.Fatalf("BucketBps(8000) = %d, want 8000", got)
	}

	// The 35-byte canonical preimage = spec(32) || 0x01 || 0x1f40.
	const wantPreimage = "e48ded87386a1be78fd0407f658f49b15bd4e27773758004db1236537ba2ac70011f40"
	if got := common.Bytes2Hex(d.consensusPreimage()); got != wantPreimage {
		t.Fatalf("consensusPreimage = %s, want %s", got, wantPreimage)
	}
	if len(d.consensusPreimage()) != 35 {
		t.Fatalf("preimage length = %d, want 35", len(d.consensusPreimage()))
	}

	// The consensus hash (Go-parity quorum key) — MUST equal the Solidity golden.
	const wantHash = "0xdd43f1ec0082fb4e93128362785605a036e583c9d9d29dd0e1493cd83a5660b1"
	if got := OutputHashGovernance(d).Hex(); got != wantHash {
		t.Fatalf("OutputHashGovernance = %s, want %s (Solidity golden)", got, wantHash)
	}
}

// thinkingVerdictDigest builds the digest an operator SIGNS to submit a verdict to
// the on-chain ThinkingGovernor. It mirrors the contract's _verdictDigest exactly:
//
//	keccak256( VERDICT_DOMAIN(32) || u256be(taskId)(32) || modelSpecHash(32) ||
//	           vote(1) || u16be(bucket)(2) || evidenceHash(32) || operator(20) )
//
// matching Solidity abi.encodePacked(bytes32, uint256, bytes32, uint8, uint16,
// bytes32, address). The operator package signs this digest (raw, no EIP-191
// prefix) with crypto.Sign; the relay normalizes v += 27 for ecrecover. The
// CONSENSUS hash (quorum key) remains the separate keccak(spec||vote||bucket) — this
// envelope binds the verdict to a specific task/operator/evidence without perturbing
// quorum parity.
func thinkingVerdictDigest(
	taskID uint64,
	operator common.Address,
	spec common.Hash,
	vote byte,
	bucket uint16,
	evidence common.Hash,
) common.Hash {
	domain := crypto.Keccak256([]byte("hanzo/thinking-governor/verdict/v1"))

	buf := make([]byte, 0, 32+32+32+1+2+32+20)
	buf = append(buf, domain...)              // VERDICT_DOMAIN (bytes32)
	var task [32]byte                         // uint256 big-endian taskId
	binary.BigEndian.PutUint64(task[24:], taskID)
	buf = append(buf, task[:]...)
	buf = append(buf, spec.Bytes()...)        // modelSpecHash (bytes32)
	buf = append(buf, vote)                   // vote (uint8)
	var b2 [2]byte                            // bucket (uint16 big-endian)
	binary.BigEndian.PutUint16(b2[:], bucket)
	buf = append(buf, b2[:]...)
	buf = append(buf, evidence.Bytes()...)    // evidenceHash (bytes32)
	buf = append(buf, operator.Bytes()...)    // operator (address, 20 bytes)
	return common.BytesToHash(crypto.Keccak256(buf))
}

// TestThinkingGovernorVerdictDigestParity pins the SUBMISSION digest golden shared
// with the Solidity test. If this matches, an operator signing thinkingVerdictDigest
// produces a signature the on-chain submitVerdict will ecrecover to that operator —
// the full off-chain→on-chain submission path is byte-parity.
//
// Golden vector: VERDICT_DOMAIN tag, taskId=7, operator=0x..01, spec golden,
// vote=yes(1), bucket=8000, evidence=keccak256("ev-golden").
func TestThinkingGovernorVerdictDigestParity(t *testing.T) {
	// VERDICT_DOMAIN must match the Solidity constant.
	const wantDomain = "0x0c578d46b25c72738e526644e19909fc3e5561532154c246fb4876115bf47a8d"
	gotDomain := common.BytesToHash(crypto.Keccak256([]byte("hanzo/thinking-governor/verdict/v1")))
	if gotDomain.Hex() != wantDomain {
		t.Fatalf("VERDICT_DOMAIN = %s, want %s", gotDomain.Hex(), wantDomain)
	}

	spec := common.BytesToHash(crypto.Keccak256([]byte("zen/thinking-governor/model-spec/v1")))
	evidence := common.BytesToHash(crypto.Keccak256([]byte("ev-golden")))
	const wantEvidence = "0xa92417646bbc9ecd4c96a0e815b20ca7d7ab5a50dbad6d56d2c5c8c09500829d"
	if evidence.Hex() != wantEvidence {
		t.Fatalf("evidence = %s, want %s", evidence.Hex(), wantEvidence)
	}

	op := common.HexToAddress("0x0000000000000000000000000000000000000001")
	got := thinkingVerdictDigest(7, op, spec, 1, 8000, evidence)

	const wantDigest = "0x2ddbb48e0b829a7f762fb1d23757a15404e4ab64a6f95d149518bd2c59935d59"
	if got.Hex() != wantDigest {
		t.Fatalf("verdictDigest = %s, want %s (Solidity golden)", got.Hex(), wantDigest)
	}
}
