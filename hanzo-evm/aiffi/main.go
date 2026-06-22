//go:build !runtime

// Command aiffi-bench measures the Go EVM's LLM + embedding precompile
// integration overhead, at parity with the Rust VM: it calls the native Hanzo
// engine over cgo (the same engine + models the Rust VM uses) for BOTH text
// generation and embeddings, routed by model name, and times them.
//
// In-process, load-once, no IPC — the path a Go EVM precompile's Run() uses.
//
// Run (needs the cdylib built with `accelerate`):
//
//	HANZO_FFI_MODELS="zen-nano=gguf:/tmp/zen5-weights/zen-5-flash.gguf;zen-embed=embedding:/tmp/zen-embedding-0.6B" \
//	  HANZO_FFI_TOK_DIR=/tmp/zen-nano-fused INFER_MODEL=zen-nano EMBED_MODEL=zen-embed BENCH_ITERS=8 \
//	  GOWORK=off CGO_ENABLED=1 go run .
package main

/*
#cgo CFLAGS: -I${SRCDIR}/../../../engine/hanzo-engine-ffi/include
#cgo LDFLAGS: -L${SRCDIR}/../../../engine/target/release -lhanzo_engine_ffi -Wl,-rpath,${SRCDIR}/../../../engine/target/release
#include "hanzo_engine_ffi.h"
#include <stdlib.h>
*/
import "C"

import (
	"fmt"
	"os"
	"strconv"
	"time"
	"unsafe"
)

func bytePtr(b []byte) *C.uint8_t {
	if len(b) == 0 {
		return nil
	}
	return (*C.uint8_t)(unsafe.Pointer(&b[0]))
}

func ready() bool { return C.hanzo_ffi_ready() == 1 }

// infer runs native text generation on model `model` (empty = default).
func infer(model, prompt string) (string, error) {
	mb, pb := []byte(model), []byte(prompt)
	var out *C.uint8_t
	var outLen C.size_t
	rc := C.hanzo_ffi_infer(bytePtr(mb), C.size_t(len(mb)), bytePtr(pb), C.size_t(len(pb)), &out, &outLen)
	if rc != 0 {
		return "", fmt.Errorf("hanzo_ffi_infer rc=%d", int(rc))
	}
	defer C.hanzo_ffi_free(out, outLen)
	return string(C.GoBytes(unsafe.Pointer(out), C.int(outLen))), nil
}

// embed runs a native embedding on model `model` (empty = default).
func embed(model, text string) ([]float32, error) {
	mb, tb := []byte(model), []byte(text)
	var out *C.float
	var count C.size_t
	rc := C.hanzo_ffi_embed(bytePtr(mb), C.size_t(len(mb)), bytePtr(tb), C.size_t(len(tb)), &out, &count)
	if rc != 0 {
		return nil, fmt.Errorf("hanzo_ffi_embed rc=%d", int(rc))
	}
	defer C.hanzo_ffi_free_f32(out, count)
	src := unsafe.Slice((*float32)(unsafe.Pointer(out)), int(count))
	v := make([]float32, int(count))
	copy(v, src)
	return v, nil
}

func mean(xs []float64) float64 {
	var s float64
	for _, x := range xs {
		s += x
	}
	if len(xs) == 0 {
		return 0
	}
	return s / float64(len(xs))
}
func minf(xs []float64) float64 {
	if len(xs) == 0 {
		return 0
	}
	m := xs[0]
	for _, x := range xs {
		if x < m {
			m = x
		}
	}
	return m
}

func main() {
	iters := 8
	if v := os.Getenv("BENCH_ITERS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			iters = n
		}
	}
	inferModel := os.Getenv("INFER_MODEL")
	embedModel := os.Getenv("EMBED_MODEL")
	prompt := "Who are you and who made you? Answer in one sentence."
	text := "The quick brown fox jumps over the lazy dog."

	fmt.Println("loading native engine + models via cgo (one-time)...")
	if !ready() {
		fmt.Println("ERROR: engine not ready (set HANZO_FFI_MODELS)")
		os.Exit(1)
	}

	// Warm + capability probe.
	out, err := infer(inferModel, prompt)
	if err != nil {
		fmt.Println("ERROR infer:", err)
		os.Exit(1)
	}
	outBytes := len(out)
	emb, embErr := embed(embedModel, text)

	var inferMs, embedMs, floor []float64
	for i := 0; i < iters; i++ {
		t := time.Now()
		if _, err := infer(inferModel, prompt); err != nil {
			fmt.Println("ERROR infer:", err)
			os.Exit(1)
		}
		inferMs = append(inferMs, float64(time.Since(t).Microseconds())/1000.0)

		if embErr == nil {
			t2 := time.Now()
			if _, err := embed(embedModel, text); err != nil {
				fmt.Println("ERROR embed:", err)
				os.Exit(1)
			}
			embedMs = append(embedMs, float64(time.Since(t2).Microseconds())/1000.0)
		}

		t3 := time.Now()
		_ = ready()
		floor = append(floor, float64(time.Since(t3).Nanoseconds())/1000.0) // µs
	}

	fmt.Printf("\n==== GO VM — infer + embed precompile benchmark (%d iters, warm, cgo, CPU+Accelerate) ====\n", iters)
	im := inferModel
	if im == "" {
		im = "default"
	}
	fmt.Printf("[infer model=%q]  cgo %.1f ms (min %.1f)  | out %d B\n", im, mean(inferMs), minf(inferMs), outBytes)
	embJSON := ""
	if embErr == nil {
		em := embedModel
		if em == "" {
			em = "default"
		}
		fmt.Printf("[embed model=%q]  cgo %.1f ms (min %.1f)  | dim %d\n", em, mean(embedMs), minf(embedMs), len(emb))
		embJSON = fmt.Sprintf(",\"embed_vm_ms\":%.3f,\"embed_dim\":%d", mean(embedMs), len(emb))
	} else {
		fmt.Printf("[embed]  unavailable: %v\n", embErr)
	}
	fmt.Printf("pure cgo floor       : %.2f µs  (boundary crossing, no model)\n", mean(floor))
	fmt.Printf("sample output        : %q\n", truncate(out, 80))
	fmt.Printf("\nBENCH_JSON {\"lang\":\"go\",\"iters\":%d,\"infer_vm_ms\":%.3f,\"cgo_floor_us\":%.2f,\"infer_out_bytes\":%d%s}\n",
		iters, mean(inferMs), mean(floor), outBytes, embJSON)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
