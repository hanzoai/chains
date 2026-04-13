// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

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
)

func main() {
	versionStr := fmt.Sprintf("Lux-EVM/1.0.0 [node=%s, rpcchainvm=%d]", version.Current, version.RPCChainVMProtocol)

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
