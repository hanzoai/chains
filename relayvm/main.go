// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package main

import (
	"context"
	"fmt"
	"os"

	"github.com/luxfi/log"
	rvm "github.com/luxfi/node/vms/relayvm"
	"github.com/luxfi/sys/ulimit"
	"github.com/luxfi/vm/chain"
	"github.com/luxfi/vm/rpc"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "version" {
		fmt.Println("Relay-VM/1.0.0")
		os.Exit(0)
	}

	if err := ulimit.Set(ulimit.DefaultFDLimit, log.Root()); err != nil {
		fmt.Fprintf(os.Stderr, "failed to set fd limit: %s\n", err)
		os.Exit(1)
	}

	f := &rvm.Factory{}
	raw, err := f.New(log.Root())
	if err != nil {
		fmt.Fprintf(os.Stderr, "factory error: %s\n", err)
		os.Exit(1)
	}

	vm := raw.(chain.ChainVM)
	if err := rpc.Serve(context.Background(), log.Root(), vm); err != nil {
		fmt.Fprintf(os.Stderr, "rpc.Serve error: %s\n", err)
		os.Exit(1)
	}
}
