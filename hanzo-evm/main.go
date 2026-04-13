// Hanzo EVM plugin — Hanzo C-Chain EVM with all precompiles enabled.
//
// Every precompile is explicitly imported. No umbrella packages.
// Genesis determines which are active at which block/timestamp.
package main

import (
	"context"
	"fmt"
	"os"

	"github.com/luxfi/evm/plugin/evm"
	"github.com/luxfi/log"
	"github.com/luxfi/sys/ulimit"
	"github.com/luxfi/version"
	"github.com/luxfi/vm/rpc"

	// ── Curves ───────────────────────────────────────────
	_ "github.com/luxfi/precompile/ed25519"   // 0x3211 Ed25519 verify
	_ "github.com/luxfi/precompile/secp256r1" // 0x0100 P-256 verify (EIP-7212)
	_ "github.com/luxfi/precompile/sr25519"   // 0x0A00 Substrate SR25519 verify

	// ── Post-Quantum (FIPS 203/204/205) ──────────────────
	_ "github.com/luxfi/precompile/mldsa"    // 0x0200..06 ML-DSA verify (Dilithium)
	_ "github.com/luxfi/precompile/mlkem"    // 0x0200..07 ML-KEM encap/decap (Kyber)
	_ "github.com/luxfi/precompile/slhdsa"   // 0x0600..01 SLH-DSA verify (SPHINCS+)
	_ "github.com/luxfi/precompile/ringtail" // 0x0200..0B Ringtail lattice threshold

	// ── Hashing ──────────────────────────────────────────
	_ "github.com/luxfi/precompile/blake3" // 0x0500..04 Blake3 hash

	// ── Threshold Signatures ─────────────────────────────
	_ "github.com/luxfi/precompile/cggmp21" // 0x0800..03 CGGMP21 ECDSA threshold
	_ "github.com/luxfi/precompile/frost"   // 0x0800..02 FROST EdDSA threshold

	// ── AI ────────────────────────────────────────────────
	_ "github.com/luxfi/precompile/ai" // 0x0300 AI mining / inference

	// ── Consensus (Quasar) ───────────────────────────────
	_ "github.com/luxfi/precompile/quasar" // 0x0300..20-24 BLS + Verkle + Ringtail + Hybrid verify

	// ── Bridge ───────────────────────────────────────────
	_ "github.com/luxfi/precompile/bridge" // 0x0440-0443 Gateway + Router + Verifier + Liquidity

	// ── FHE ──────────────────────────────────────────────
	_ "github.com/luxfi/precompile/fhe" // 0x0700 Fully homomorphic encryption

	// ── ZK Proofs ────────────────────────────────────────
	_ "github.com/luxfi/precompile/zk" // 0x0900 Groth16 + PLONK + fflonk + Halo2

	// ── Encryption / Privacy ─────────────────────────────
	_ "github.com/luxfi/precompile/ecies" // 0x9201 ECIES encrypt/decrypt
	_ "github.com/luxfi/precompile/hpke"  // 0x9200 Hybrid Public Key Encryption
	_ "github.com/luxfi/precompile/ring"  // 0x9202 Ring signatures

	// ── DEX (LX Suite 0x9010-0x9080) ─────────────────────
	_ "github.com/luxfi/precompile/dex" // Pool + Oracle + Router + Hooks + Flash + Book + Vault + Price + Lend + Repayer + Liquidator + Transmuter

	// ── Graph ────────────────────────────────────────────
	_ "github.com/luxfi/precompile/graph" // 0x0500 On-chain GraphQL

	// ── Blob ─────────────────────────────────────────────
	_ "github.com/luxfi/precompile/kzg4844" // 0xB002 EIP-4844 KZG commitments

	// ── Attestation ──────────────────────────────────────
	_ "github.com/luxfi/precompile/attestation" // Remote attestation (TEE)

	// ── Registry ─────────────────────────────────────────
	_ "github.com/luxfi/precompile/registry" // Precompile registry + BLS12-381 curves

	// ── REMOVED (umbrellas — use explicit imports above) ──
	// _ "github.com/luxfi/precompile/pqcrypto"  — use mldsa + mlkem + slhdsa
	// _ "github.com/luxfi/precompile/quantum"    — use mldsa + mlkem + slhdsa + ringtail
	// _ "github.com/luxfi/precompile/threshold"  — use cggmp21 + frost + ringtail
)

func main() {
	versionStr := fmt.Sprintf("Hanzo-EVM/1.0.0 [node=%s, rpcchainvm=%d]", version.Current, version.RPCChainVMProtocol)

	if len(os.Args) > 1 && os.Args[1] == "version" {
		fmt.Println(versionStr)
		os.Exit(0)
	}

	if err := ulimit.Set(ulimit.DefaultFDLimit, log.Root()); err != nil {
		fmt.Fprintf(os.Stderr, "failed to set fd limit: %s\n", err)
		os.Exit(1)
	}

	if err := rpc.Serve(context.Background(), log.Root(), &evm.VM{}); err != nil {
		fmt.Fprintf(os.Stderr, "rpc.Serve error: %s\n", err)
		os.Exit(1)
	}
}
