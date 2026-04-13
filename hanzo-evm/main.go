// Hanzo EVM plugin — Hanzo C-Chain EVM with all precompiles enabled.
//
// All precompiles are activated at genesis via blank imports.
// Each chain's genesis determines which precompiles are active
// at which block/timestamp.
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

	// Post-quantum cryptography
	_ "github.com/luxfi/precompile/blake3"
	_ "github.com/luxfi/precompile/mldsa"
	_ "github.com/luxfi/precompile/mlkem"
	_ "github.com/luxfi/precompile/pqcrypto"
	_ "github.com/luxfi/precompile/slhdsa"

	// Threshold signatures
	_ "github.com/luxfi/precompile/cggmp21"
	_ "github.com/luxfi/precompile/frost"
	_ "github.com/luxfi/precompile/ringtail"

	// Curves
	_ "github.com/luxfi/precompile/ed25519"
	_ "github.com/luxfi/precompile/secp256r1"
	_ "github.com/luxfi/precompile/sr25519"

	// DEX
	_ "github.com/luxfi/precompile/dex"

	// Encryption and privacy
	_ "github.com/luxfi/precompile/ecies"
	_ "github.com/luxfi/precompile/fhe"
	_ "github.com/luxfi/precompile/hpke"
	_ "github.com/luxfi/precompile/ring"

	// Zero-knowledge and graph
	_ "github.com/luxfi/precompile/graph"
	_ "github.com/luxfi/precompile/zk"
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
