// Command aiffi-runtime demonstrates RUNTIME model management on a LIVE Hanzo
// engine over cgo: start with one model, then load / list / embed / unload more
// without restarting the engine — the path a node operator's "load this model
// now" control plane uses.
//
// Build tags keep this in its own binary (it has its own main); build/run it on
// its own:
//
//	HANZO_FFI_MODELS="zen-nano=gguf:/tmp/zen5-weights/zen-5-flash.gguf" \
//	  HANZO_FFI_TOK_DIR=/tmp/zen-nano-fused \
//	  GOWORK=off CGO_ENABLED=1 go run -tags runtime .
//
// It loads zen-embed (embedding) at runtime, embeds with it, lists both models,
// then unloads zen-embed and lists again.
//go:build runtime

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
	"strings"
	"unsafe"
)

func rtBytePtr(b []byte) *C.uint8_t {
	if len(b) == 0 {
		return nil
	}
	return (*C.uint8_t)(unsafe.Pointer(&b[0]))
}

func rtReady() bool { return C.hanzo_ffi_ready() == 1 }

// Load loads one model into the live engine, routable immediately by name.
// kind ∈ {"gguf","plain","embedding"}.
func Load(name, kind, source string) error {
	nb, kb, sb := []byte(name), []byte(kind), []byte(source)
	rc := C.hanzo_ffi_load(
		rtBytePtr(nb), C.size_t(len(nb)),
		rtBytePtr(kb), C.size_t(len(kb)),
		rtBytePtr(sb), C.size_t(len(sb)),
	)
	if rc != 0 {
		return fmt.Errorf("hanzo_ffi_load(%q) rc=%d", name, int(rc))
	}
	return nil
}

// Unload removes one model from the live engine.
func Unload(name string) error {
	nb := []byte(name)
	rc := C.hanzo_ffi_unload(rtBytePtr(nb), C.size_t(len(nb)))
	if rc != 0 {
		return fmt.Errorf("hanzo_ffi_unload(%q) rc=%d", name, int(rc))
	}
	return nil
}

// List returns the live engine's routable model ids.
func List() ([]string, error) {
	var out *C.uint8_t
	var outLen C.size_t
	rc := C.hanzo_ffi_list(&out, &outLen)
	if rc != 0 {
		return nil, fmt.Errorf("hanzo_ffi_list rc=%d", int(rc))
	}
	if outLen == 0 {
		return nil, nil
	}
	defer C.hanzo_ffi_free(out, outLen)
	joined := string(C.GoBytes(unsafe.Pointer(out), C.int(outLen)))
	return strings.Split(joined, "\n"), nil
}

// rtInfer / rtEmbed reuse the proven baseline C ABI (declared once in main.go's
// cgo block; the C functions are the same shared library).
func rtInfer(model, prompt string) (string, error) {
	mb, pb := []byte(model), []byte(prompt)
	var out *C.uint8_t
	var outLen C.size_t
	rc := C.hanzo_ffi_infer(rtBytePtr(mb), C.size_t(len(mb)), rtBytePtr(pb), C.size_t(len(pb)), &out, &outLen)
	if rc != 0 {
		return "", fmt.Errorf("hanzo_ffi_infer rc=%d", int(rc))
	}
	defer C.hanzo_ffi_free(out, outLen)
	return string(C.GoBytes(unsafe.Pointer(out), C.int(outLen))), nil
}

func rtEmbed(model, text string) ([]float32, error) {
	mb, tb := []byte(model), []byte(text)
	var out *C.float
	var count C.size_t
	rc := C.hanzo_ffi_embed(rtBytePtr(mb), C.size_t(len(mb)), rtBytePtr(tb), C.size_t(len(tb)), &out, &count)
	if rc != 0 {
		return nil, fmt.Errorf("hanzo_ffi_embed rc=%d", int(rc))
	}
	defer C.hanzo_ffi_free_f32(out, count)
	src := unsafe.Slice((*float32)(unsafe.Pointer(out)), int(count))
	v := make([]float32, int(count))
	copy(v, src)
	return v, nil
}

func l2norm(v []float32) float64 {
	var s float64
	for _, x := range v {
		s += float64(x) * float64(x)
	}
	if s == 0 {
		return 0
	}
	// math.Sqrt without importing math for one call.
	z := s
	for i := 0; i < 40; i++ {
		z = 0.5 * (z + s/z)
	}
	return z
}

func main() {
	const (
		startModel = "zen-nano"
		embedName  = "zen-embed"
		embedKind  = "embedding"
		embedSrc   = "/tmp/zen-embedding-0.6B"
	)

	fmt.Println("== Hanzo runtime model loading (live engine, cgo, CPU+Accelerate) ==")
	fmt.Println("[1] starting engine with ONLY", startModel, "(HANZO_FFI_MODELS)...")
	if !rtReady() {
		fmt.Println("ERROR: engine not ready — set HANZO_FFI_MODELS=\"zen-nano=gguf:/tmp/zen5-weights/zen-5-flash.gguf\" and HANZO_FFI_TOK_DIR=/tmp/zen-nano-fused")
		os.Exit(1)
	}
	before, err := List()
	if err != nil {
		fmt.Println("ERROR list:", err)
		os.Exit(1)
	}
	fmt.Printf("    models at startup: %v\n", before)

	fmt.Printf("[2] RUNTIME load %q (%s:%s) into the live engine...\n", embedName, embedKind, embedSrc)
	if err := Load(embedName, embedKind, embedSrc); err != nil {
		fmt.Println("ERROR load:", err)
		os.Exit(1)
	}
	fmt.Println("    loaded.")

	fmt.Printf("[3] embed via the RUNTIME-loaded model %q...\n", embedName)
	v, err := rtEmbed(embedName, "The quick brown fox jumps over the lazy dog.")
	if err != nil {
		fmt.Println("ERROR embed:", err)
		os.Exit(1)
	}
	fmt.Printf("    embedding dim = %d, L2 norm = %.4f, head = [%.5f %.5f %.5f ...]\n",
		len(v), l2norm(v), v[0], v[1], v[2])

	fmt.Println("[4] list models (both should appear)...")
	after, err := List()
	if err != nil {
		fmt.Println("ERROR list:", err)
		os.Exit(1)
	}
	fmt.Printf("    models now: %v\n", after)

	fmt.Printf("[5] sanity: infer on original %q still works...\n", startModel)
	out, err := rtInfer(startModel, "Reply with exactly one short sentence.")
	if err != nil {
		fmt.Println("ERROR infer:", err)
		os.Exit(1)
	}
	fmt.Printf("    infer ok, %d bytes: %q\n", len(out), truncateRT(out, 80))

	fmt.Printf("[6] RUNTIME unload %q...\n", embedName)
	if err := Unload(embedName); err != nil {
		fmt.Println("ERROR unload:", err)
		os.Exit(1)
	}
	final, err := List()
	if err != nil {
		fmt.Println("ERROR list:", err)
		os.Exit(1)
	}
	fmt.Printf("    models after unload: %v\n", final)

	fmt.Println("[7] fail-secure checks (should both be rejected):")
	// 7a: re-loading an id that already exists must be rejected at the boundary.
	dupErr := Load(startModel, "gguf", "/tmp/zen5-weights/zen-5-flash.gguf")
	fmt.Printf("    re-load existing %q -> %v\n", startModel, dupErr)
	// 7b: unloading the last remaining model must be refused (engine never empties).
	lastErr := Unload(startModel)
	fmt.Printf("    unload last model %q -> %v\n", startModel, lastErr)
	stillThere, err := List()
	if err != nil {
		fmt.Println("ERROR list:", err)
		os.Exit(1)
	}
	fmt.Printf("    models still present: %v\n", stillThere)

	// Proof assertions.
	ok := len(v) == 1024 &&
		contains(after, startModel) && contains(after, embedName) &&
		contains(final, startModel) && !contains(final, embedName) &&
		dupErr != nil && lastErr != nil && contains(stillThere, startModel)
	if !ok {
		fmt.Println("\nFAIL: expected dim 1024, both models after load, only original after unload, dup+last-unload rejected")
		os.Exit(1)
	}
	fmt.Println("\nPASS: runtime load → embed(dim 1024) → list(both) → unload → list(one);")
	fmt.Println("      fail-secure: duplicate load rejected, last-model unload refused. Engine never restarted.")
}

func contains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

func truncateRT(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
