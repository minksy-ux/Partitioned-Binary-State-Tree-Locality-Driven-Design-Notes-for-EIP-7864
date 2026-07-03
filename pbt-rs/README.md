# pbt-rs

Rust reference implementation scaffold for EIP-7864 core tree logic.

Implemented now:

- Node types: Empty / Internal / Stem
- Canonical insert / delete / get
- BLAKE3 root hashing
- Single-key proof generation + verification
- Multi-key batch proof generation + verification
- Ethereum embedding key derivation helpers
- MPT-account migration helper (fixture-oriented)
- Proof format bindings (JSON + bincode)
- WASM-compatible batch verification entry point
- Property-based and round-trip tests

Not yet implemented in this scaffold:

- Poseidon2 backend integration and hash-mode switching
- Native STARK proving backend integration
- Snapshot-scale migration fixtures and full benchmark suite

## Run tests

```bash
cargo test
```

## Run benchmark skeleton

```bash
cargo run --release --bench core_ops
```
