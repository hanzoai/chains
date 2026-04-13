// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package main

import (
	"context"
	"fmt"
	"os"

	"github.com/luxfi/log"
	"github.com/luxfi/node/vms/dexvm"
	"github.com/luxfi/sys/ulimit"
	"github.com/luxfi/vm/rpc"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "version" {
		fmt.Println("DEX-VM/1.0.0")
		os.Exit(0)
	}

	if err := ulimit.Set(ulimit.DefaultFDLimit, log.Root()); err != nil {
		fmt.Fprintf(os.Stderr, "failed to set fd limit: %s\n", err)
		os.Exit(1)
	}

	vm := dexvm.NewChainVM(log.Root())
	if err := rpc.Serve(context.Background(), log.Root(), vm); err != nil {
		fmt.Fprintf(os.Stderr, "rpc.Serve error: %s\n", err)
		os.Exit(1)
	}
}
