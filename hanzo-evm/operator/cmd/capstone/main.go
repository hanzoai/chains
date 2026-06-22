// Copyright (C) 2026, Hanzo AI Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Command capstone runs the full LLM-quorum-settlement pipeline against the REAL
// native engine and the REAL aiquorum precompile, printing the end-to-end trace:
// governance -> staked operator quorum (real engine) -> on-chain commit/reveal ->
// Settle, proving the settled canonical hash IS the engine's output.
//
// Run:
//
//	HANZO_FFI_MODELS="zen-nano=gguf:/tmp/zen5-weights/zen-5-flash.gguf;zen-embed=embedding:/tmp/zen-embedding-0.6B" \
//	  HANZO_FFI_TOK_DIR=/tmp/zen-nano-fused \
//	  GOWORK=off CGO_ENABLED=1 SDKROOT=$(xcrun --show-sdk-path) CPATH=$SDKROOT/usr/include \
//	  go run ./cmd/capstone
package main

import (
	"fmt"
	"os"

	"github.com/hanzoai/chains/hanzo-evm/operator/capstone"
)

func main() {
	if _, err := capstone.Run(os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "\nCAPSTONE FAILED: %v\n", err)
		os.Exit(1)
	}
}
