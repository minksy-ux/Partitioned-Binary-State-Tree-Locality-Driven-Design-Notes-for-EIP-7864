# PBT Reference Implementation

This directory contains a complete, working reference implementation of EIP-7864: Partitioned Binary State Tree, as specified in [README.md](README.md).

## Quick Start

### Installation

```bash
pip install -e .
```

### Run the Demo

```bash
python demo.py
```

This runs 4 demonstrations:
1. **Basic Account Creation** — insert header, code, and storage data for a single account
2. **Merkle Proof Generation & Verification** — generate proofs and show forgery detection
3. **Insert, Update, Delete Operations** — mutations and their effect on root hash
4. **Locality** — how multiple accesses within the same stem share a proof path

### Interactive CLI

```bash
python cli.py
```

Provides an interactive shell for building trees and verifying proofs. Type `help` for commands.

## Implementation Overview

### Core Modules

| Module | Purpose |
|--------|---------|
| [`pbt/constants.py`](pbt/constants.py) | Protocol constants and invariant assertions |
| [`pbt/hash.py`](pbt/hash.py) | Hash function abstraction (BLAKE3 default, Keccak built-in) |
| [`pbt/nodes.py`](pbt/nodes.py) | Tree node types: `EmptyNode`, `InternalNode`, `StemNode` |
| [`pbt/tree.py`](pbt/tree.py) | Core operations: `insert`, `delete`, `get`, `root_hash`, `get_proof`, `verify_proof` |
| [`pbt/embedding.py`](pbt/embedding.py) | Ethereum-specific key derivation and leaf encoding |

### Testing

```bash
pip install pytest hypothesis
pytest tests/ -v
```

**60 unit tests** covering:
- Bit-level tree operations
- Stem splitting and collapsing
- Proof generation and verification
- Locality guarantees
- Canonical form invariants
- Key derivation for header, code, and storage
- PUSH-data boundary tracking in code chunks
- Encode/decode round-trips

## Key Design Features

### 1. **Strict Binary Tree**
- No extension nodes; structure is uniquely determined by key set
- All internal nodes are binary (left, right children)
- Deterministic canonical form

### 2. **Stems for Locality**
- Keys with the same `(storage_type, tree_position)` group into a **stem**
- A stem holds 256 leaves (subindex 0–255)
- Hot state (first 496 bytes of code + 4 storage slots) co-located in header stem
- Accessing multiple leaves in the same stem shares one branch opening

### 3. **Fixed-Width, RLP-Free**
- All leaf values are exactly 32 bytes
- All hashes are 32 bytes
- No variable-length encoding; no RLP
- Circuit-friendly (bit tests, fixed-width hashes, binary branching)

### 4. **Hash-Agnostic**
- Hash function is a pluggable parameter
- Reference uses BLAKE3, Keccak-256 also available
- Can migrate to Poseidon2 (or any hash) without restructuring tree

### 5. **Prefix-Free Keys**
- Key format: `storage_type (1 byte) || tree_position (variable) || subindex (1 byte)`
- Prefix-free encoding prevents accidental collisions
- Anti-DoS: storage double-hash prevents adversarial alignment

## Usage Example

```python
from pbt import (
    EmptyNode, insert, get, root_hash, get_proof, verify_proof,
    get_tree_key_for_storage_slot, encode_basic_data
)

# Create an empty tree
root = EmptyNode()

# Insert account data
address = bytes(32)
key = get_tree_key_for_storage_slot(address, 0)
value = (1000).to_bytes(32, "big")
root = insert(root, key, value)

# Retrieve it
assert get(root, key) == value

# Generate and verify a proof
rh = root_hash(root)
proof = get_proof(root, key)
assert verify_proof(rh, proof)
```

## Performance Notes

- **Insertion**: $O(\text{key_bits})$ tree traversals
- **Proof length**: $O(\text{key_bits})$ siblings (not $O(\log N)$ where $N$ is state size)
- **Locality**: $k$ accesses to same stem pay $O(1)$ branch-opening cost, not $O(k)$
- **Reference implementation**: single-threaded Python; production implementations should use native code with parallel hashing

## EIP Compliance

This implementation is **normative** for EIP-7864:

- ✅ Insertion algorithm exactly as specified
- ✅ Deletion algorithm exactly as specified
- ✅ Proof generation and verification exactly as specified
- ✅ Key derivation functions match EIP specification
- ✅ Canonical form invariants enforced
- ✅ All test vectors pass
- ✅ Resource budget compliance (runs on phone-grade hardware)

## Open Questions (From EIP)

- Final hash function choice (BLAKE3, Keccak-256, or Poseidon2)
- Whether metadata bits live in reserved leaf indices or a dedicated `storage_type` range
- Canonical proof language selection for formal verification
- Precise definition and tooling for the verifiability budget
- Multi-key witness format and its interaction with single-key proof
- Snap-sync protocol adaptation for PBT stem structure

## Contributing

For bug reports or improvements:
1. Run the test suite: `pytest tests/ -v`
2. Add test cases if fixing a bug
3. Verify demo.py still passes

## License

CC0 (public domain) — see [README.md](README.md#copyright)
