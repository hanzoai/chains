// The operator module is intentionally SEPARATE from the parent EVM module
// (github.com/hanzoai/chains/hanzo-evm), mirroring aiffi/: it carries cgo (the
// native engine FFI) and a main, neither of which belong in the pure, cross-
// compiled EVM plugin build. Keeping it out of the parent's `./...` means the
// plugin never has to link libhanzo_engine_ffi.
//
// luxfi/crypto and luxfi/geth are pinned to the EXACT versions the parent uses
// (v1.19.20 / v1.17.5) so canonical's keccak and common types are byte-identical
// to the precompile's. The `replace` points the parent module at ../ so
// crosscheck_test.go can import the REAL precompile/aiquorum and prove on/off-
// chain hash equality against deployed code, not a copy.
//
// Build/run with: GOWORK=off CGO_ENABLED=1 (and SDKROOT/CPATH on macOS).
module github.com/hanzoai/chains/hanzo-evm/operator

go 1.26.4

require (
	github.com/hanzoai/chains/hanzo-evm v0.0.0-00010101000000-000000000000
	github.com/holiman/uint256 v1.3.2
	github.com/luxfi/crypto v1.19.20
	github.com/luxfi/geth v1.17.11
	github.com/luxfi/precompile v0.5.44
)

require (
	github.com/Microsoft/go-winio v0.6.2 // indirect
	github.com/bits-and-blooms/bitset v1.24.4 // indirect
	github.com/cenkalti/backoff v2.2.1+incompatible // indirect
	github.com/cloudflare/circl v1.6.3 // indirect
	github.com/consensys/gnark-crypto v0.20.1 // indirect
	github.com/crate-crypto/go-eth-kzg v1.5.0 // indirect
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.4.1 // indirect
	github.com/ethereum/c-kzg-4844/v2 v2.1.7 // indirect
	github.com/gorilla/rpc v1.2.1 // indirect
	github.com/grandcat/zeroconf v1.0.0 // indirect
	github.com/klauspost/compress v1.18.6 // indirect
	github.com/luxfi/accel v1.2.4 // indirect
	github.com/luxfi/atomic v1.0.0 // indirect
	github.com/luxfi/cache v1.2.1 // indirect
	github.com/luxfi/compress v0.0.5 // indirect
	github.com/luxfi/concurrent v0.0.3 // indirect
	github.com/luxfi/consensus v1.25.17 // indirect
	github.com/luxfi/constants v1.5.8 // indirect
	github.com/luxfi/container v0.0.4 // indirect
	github.com/luxfi/crypto/ipa v1.2.4 // indirect
	github.com/luxfi/database v1.19.2 // indirect
	github.com/luxfi/ids v1.2.15 // indirect
	github.com/luxfi/log v1.4.3 // indirect
	github.com/luxfi/math v1.4.1 // indirect
	github.com/luxfi/math/big v0.1.0 // indirect
	github.com/luxfi/mdns v0.1.1 // indirect
	github.com/luxfi/metric v1.5.8 // indirect
	github.com/luxfi/mock v0.1.1 // indirect
	github.com/luxfi/p2p v1.21.1 // indirect
	github.com/luxfi/pq v1.0.3 // indirect
	github.com/luxfi/runtime v1.1.1 // indirect
	github.com/luxfi/sampler v1.1.0 // indirect
	github.com/luxfi/utils v1.2.0 // indirect
	github.com/luxfi/validators v1.2.0 // indirect
	github.com/luxfi/version v1.0.1 // indirect
	github.com/luxfi/vm v1.2.3 // indirect
	github.com/luxfi/warp v1.19.3 // indirect
	github.com/luxfi/zap v0.8.1 // indirect
	github.com/mattn/go-colorable v0.1.15 // indirect
	github.com/mattn/go-isatty v0.0.22 // indirect
	github.com/miekg/dns v1.1.72 // indirect
	github.com/mr-tron/base58 v1.3.0 // indirect
	github.com/supranational/blst v0.3.16 // indirect
	go.uber.org/mock v0.6.0 // indirect
	golang.org/x/crypto v0.52.0 // indirect
	golang.org/x/exp v0.0.0-20260529124908-c761662dc8c9 // indirect
	golang.org/x/mod v0.36.0 // indirect
	golang.org/x/net v0.55.0 // indirect
	golang.org/x/sync v0.20.0 // indirect
	golang.org/x/sys v0.45.0 // indirect
	golang.org/x/tools v0.45.0 // indirect
	gonum.org/v1/gonum v0.17.0 // indirect
	google.golang.org/protobuf v1.36.12-0.20260120151049-f2248ac996af // indirect
	gopkg.in/natefinch/lumberjack.v2 v2.2.1 // indirect
)

replace github.com/hanzoai/chains/hanzo-evm => ../
