# Hanzo Chains

VM plugin binaries for the Hanzo AI Network. Includes all standard Lux VMs plus Hanzo-specific chains.

## Standard VMs (from Lux)

aivm, bridgevm, dexvm, evm, graphvm, identityvm, keyvm, oraclevm, quantumvm, relayvm, servicenodevm, teleportvm, thresholdvm, zkvm

## Hanzo-Specific VMs

- **hanzo-evm** — Lux EVM with Hanzo AI precompiles (PQ crypto, threshold sigs, DEX, FHE, ZK, Graph)

## Build

```bash
make            # build all
make hanzo-evm  # build one
```

## Install

```bash
lpm install-github hanzoai/chains --pattern "hanzo-evm-{os}-{arch}"
```
