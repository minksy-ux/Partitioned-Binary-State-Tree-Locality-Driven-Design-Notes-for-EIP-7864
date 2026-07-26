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
- Compressed proof format bindings (gzip-compressed bincode)
- WASM-compatible batch verification entry point
- Property-based and round-trip tests

## Gemini prototype notes

- Field options: BabyBear or Goldilocks64
- Construction: sponge-style binary-friendly permutation (prototype)
- Compression API: `gemini_compress(left: [u8; 32], right: [u8; 32]) -> [u8; 32]`
- Stem commitment: tree-based folding across the 256 leaf values

Security warning:

- This Gemini implementation is an engineering prototype.
- Security claims are not established.
- Production use must fall back to Blake3 or Poseidon2 until Gemini is independently reviewed and standardized.

## VectorFold proof mode

- When GeminiHash or Poseidon2 mode is selected, implementations may use optional VectorFold proofs.
- Standard mode (Blake3 or Poseidon2 with classic binary Merkle proofs) remains mandatory.
- Clients must indicate proof mode when serving proofs.
- Canonical tree structure and key derivation are unchanged across modes.

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
cargo bench --bench core_ops
```
