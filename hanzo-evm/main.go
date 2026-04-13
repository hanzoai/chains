// Hanzo EVM plugin — Lux EVM with Hanzo AI precompiles.
package main

import (
	"context"
	"fmt"
	"os"

	"github.com/luxfi/evm/plugin/evm"
	"github.com/luxfi/log"
	"github.com/luxfi/sys/ulimit"
	"github.com/luxfi/vm/rpc"

	// Hanzo AI precompiles
	_ "github.com/luxfi/precompile/blake3"
	_ "github.com/luxfi/precompile/mldsa"
	_ "github.com/luxfi/precompile/mlkem"
	_ "github.com/luxfi/precompile/pqcrypto"
	_ "github.com/luxfi/precompile/slhdsa"
	_ "github.com/luxfi/precompile/cggmp21"
	_ "github.com/luxfi/precompile/frost"
	_ "github.com/luxfi/precompile/ringtail"
	_ "github.com/luxfi/precompile/ed25519"
	_ "github.com/luxfi/precompile/secp256r1"
	_ "github.com/luxfi/precompile/sr25519"
	_ "github.com/luxfi/precompile/dex"
	_ "github.com/luxfi/precompile/fhe"
	_ "github.com/luxfi/precompile/zk"
	_ "github.com/luxfi/precompile/graph"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "version" {
		fmt.Println("hanzo-evm/1.0.0")
		os.Exit(0)
	}
	if err := ulimit.Set(ulimit.DefaultFDLimit, log.Root()); err != nil {
		fmt.Fprintf(os.Stderr, "fd limit: %s\n", err)
		os.Exit(1)
	}
	if err := rpc.Serve(context.Background(), log.Root(), &evm.VM{}); err != nil {
		fmt.Fprintf(os.Stderr, "rpc.Serve: %s\n", err)
		os.Exit(1)
	}
}
