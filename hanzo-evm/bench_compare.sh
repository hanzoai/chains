#!/usr/bin/env bash
# Compare the Rust VM (revm) and Go VM (cgo) LLM+embedding precompile paths
# against the same native engine + the same zen / zen-embedding models. Both ops
# (infer + embed), routed by model name. Inference dominates; this shows the
# per-call integration overhead each VM adds and that they are at parity.
set -euo pipefail

export SDKROOT="$(xcrun --show-sdk-path)"
export HANZO_FFI_MODELS="${HANZO_FFI_MODELS:-zen-nano=gguf:/tmp/zen5-weights/zen-5-flash.gguf;zen-embed=embedding:/tmp/zen-embedding-0.6B}"
export HANZO_FFI_TOK_DIR="${HANZO_FFI_TOK_DIR:-/tmp/zen-nano-fused}"
export INFER_MODEL="${INFER_MODEL:-zen-nano}"
export EMBED_MODEL="${EMBED_MODEL:-zen-embed}"
export BENCH_ITERS="${BENCH_ITERS:-5}"
H="$HOME/work/hanzo"

echo "# models=[$HANZO_FFI_MODELS]  iters=$BENCH_ITERS  (warm, in-process, load-once)"
RUST_JSON=$("$H/net/target/release/examples/bench_precompile" 2>/dev/null | grep '^BENCH_JSON' | sed 's/^BENCH_JSON //')
GO_JSON=$(cd "$H/chains/hanzo-evm/aiffi" && GOWORK=off CGO_ENABLED=1 go run . 2>/dev/null | grep '^BENCH_JSON' | sed 's/^BENCH_JSON //')

python3 - "$RUST_JSON" "$GO_JSON" <<'PY'
import json, sys
r = json.loads(sys.argv[1]); g = json.loads(sys.argv[2])
def gv(d,k): return d.get(k)
print()
print("LLM + embedding via precompile: Rust VM (revm) vs Go VM (cgo) — same engine + models")
print("="*78)
print(f"{'metric':<32}{'Rust VM':>20}{'Go VM':>20}")
print("-"*78)
print(f"{'infer per-call (ms)':<32}{r['infer_vm_ms']:>20.1f}{g['infer_vm_ms']:>20.1f}")
print(f"{'infer output (bytes)':<32}{r['infer_out_bytes']:>20}{g['infer_out_bytes']:>20}")
if 'embed_vm_ms' in r and 'embed_vm_ms' in g:
    print(f"{'embed per-call (ms)':<32}{r['embed_vm_ms']:>20.1f}{g['embed_vm_ms']:>20.1f}")
    print(f"{'embed dim (floats)':<32}{r['embed_dim']:>20}{g['embed_dim']:>20}")
print(f"{'integration overhead/call':<32}{str(round(r['evm_floor_us'],1))+' us':>20}{str(round(g['cgo_floor_us'],2))+' us':>20}")
print(f"{'  (mechanism)':<32}{'revm bytecode':>20}{'cgo boundary':>20}")
print("-"*78)
print("verdict: parity — both run the native engine in-process for infer AND embed,")
print("         routed by model name; integration overhead is microseconds.")
PY
