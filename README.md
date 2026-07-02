# EIP-7864: Partitioned Binary State Tree

| Field | Value |
|---|---|
| EIP | 7864 |
| Title | Partitioned Binary State Tree |
| Status | Draft |
| Type | Standards Track – Core |
| Category | Core |
| Created | 2026-07-02 |

---

## Abstract

This EIP specifies a Partitioned Binary Tree (PBT) as the new Ethereum state structure, replacing the hexary Patricia trie. Account headers, contract code, and contract storage are unified into a single canonical key-value tree keyed by prefix-free byte strings with fixed-width 32-byte values.

State is organised along two independent axes:

1. **Storage-type partitioning** — a one-byte prefix (`storage_type`) physically separates header, code, and storage data, enabling independent synchronisation and differentiated handling.
2. **Locality via stems** — related data is grouped into 256-entry subtrees (stems), reducing the number of branch openings for adjacent accesses.

RLP is no longer used anywhere in the state tree. The hash function is not yet finalised; BLAKE3 is used in the reference implementation for convenience. Keccak-256 and Poseidon2 remain candidates.

## Motivation

The hexary Patricia trie (MPT) has three fundamental problems that motivate replacement:

1. **Proof length.** A hexary tree over an address space of size $N$ produces proofs of depth $\lceil \log_{16} N \rceil$, which is approximately 8 nodes for the current state size. A binary tree reduces this to $\lceil \log_2 N \rceil \approx 32$ bit-steps over a much simpler node type, but each node requires only one hash comparison instead of up to 16. The net result is shorter, more uniform witness branches.
2. **RLP and variable node types.** The MPT mixes extension nodes, branch nodes, and leaf nodes encoded in RLP. This variable structure is expensive to represent in ZK circuits and makes canonical-form enforcement difficult across client implementations.
3. **No first-class locality.** The MPT has no notion of grouping related data. Every account field, code byte, and storage slot is an independent trie path. Adjacent accesses do not share witnesses.

A PBT solves all three problems: it is strictly binary, uses no RLP, and groups related data into 256-entry stems.

## Specification

### Design Goals

The design SHALL satisfy the following requirements:

1. Short and predictable Merkle proofs for light clients and stateless execution.
2. Strong locality so that adjacent header, code, and storage accesses share a stem.
3. A single canonical keyspace with no ambiguous encodings.
4. No extension nodes; the minimal internal-node structure MUST be deterministic.
5. Compatibility with ZK execution pipelines: fixed-width hashes, binary branching, and no variable-arity node logic.

### Parameters

| Constant | Value | Notes |
|---|---|---|
| `HEADER_SUBTREE` | `0` | `storage_type` for account header data |
| `CODE_SUBTREE` | `1` | `storage_type` for contract code chunks |
| `STORAGE_SUBTREE` | `255` | `storage_type` for contract storage |
| `BASIC_DATA_LEAF_KEY` | `0` | subindex of the basic-data leaf in the header stem |
| `CODE_HASH_LEAF_KEY` | `1` | subindex of the code-hash leaf in the header stem |
| `CODE_OFFSET` | `4` | first subindex used for code chunks in the header stem |
| `HEADER_STORAGE_OFFSET` | `20` | first subindex used for storage slots in the header stem |
| `CODE_CHUNKS_IN_HEADER` | `16` | number of code chunks co-located in the header stem |
| `STORAGE_CHUNKS_IN_HEADER` | `4` | number of storage slots co-located in the header stem |
| `STEM_SUBTREE_WIDTH` | `256` | number of leaf slots per stem |
| `MAIN_STORAGE_OFFSET` | $256^{31}$ | page offset for overflow storage stems |

**Constraints that MUST hold:**

$$\text{STEM\_SUBTREE\_WIDTH} > \text{HEADER\_STORAGE\_OFFSET} > \text{CODE\_OFFSET} > \text{CODE\_HASH\_LEAF\_KEY}$$

$$\text{MAIN\_STORAGE\_OFFSET} = \text{STEM\_SUBTREE\_WIDTH}^{31}$$

### Tree Model

The PBT stores prefix-free byte-string keys with 32-byte values.

Each key has the form:

```
bytes([storage_type]) + tree_position + bytes([subindex])
```

where:
- `storage_type` is a single byte identifying the partition.
- `tree_position` is a prefix-free byte string identifying the account or page within that partition.
- `subindex` is a single byte (0–255) selecting a leaf within the stem.

Keys sharing the same `(storage_type, tree_position)` form a **stem**. A stem contains exactly `STEM_SUBTREE_WIDTH` (256) leaf slots indexed by `subindex`. Unset slots hold `EMPTY_VALUE` (32 zero bytes).

The tree is strictly binary with the following invariants:

- If traversal reaches an empty node, the empty node MUST be replaced by a new `StemNode`.
- If an inserted stem conflicts with an existing `StemNode`, `InternalNode`s MUST be introduced based solely on the longest common bit-prefix of the two stem prefixes.
- Extension nodes MUST NOT be used.
- The resulting structure MUST be the unique canonical minimal binary tree for the given key set.
- An `InternalNode` with two `EmptyNode` children MUST NOT exist in any valid tree.

### Partitioning And Locality

The three storage types (`HEADER_SUBTREE`, `CODE_SUBTREE`, `STORAGE_SUBTREE`) occupy disjoint subtrees of the top-level binary tree because their `storage_type` bytes differ. This enables independent synchronisation, differentiated caching, and separate storage strategies per type.

The stem width of 256 defines the basic locality unit. A stem holds all 256 leaves for a given `(storage_type, tree_position)` pair under a single `StemNode`. Reads within the same stem share a single branch opening.

Locality is a first-class cost model: the key derivation functions in this EIP are designed so that the most frequently co-accessed data for any account maps to the same stem wherever possible.

### Pages And Co-Location Guarantees

The header stem for a given address holds:

| Subindex range | Contents |
|---|---|
| `0` | `BASIC_DATA_LEAF_KEY`: version, balance, nonce, code size |
| `1` | `CODE_HASH_LEAF_KEY`: code hash |
| `2–3` | reserved |
| `CODE_OFFSET` … `CODE_OFFSET + CODE_CHUNKS_IN_HEADER - 1` | first 16 code chunks (496 bytes of code) |
| `HEADER_STORAGE_OFFSET` … `HEADER_STORAGE_OFFSET + STORAGE_CHUNKS_IN_HEADER - 1` | first 4 storage slots |
| remaining | reserved for future use |

Consequently a contract with at most 496 bytes of code and at most 4 hot storage slots can have its entire frequently-accessed state served from a single stem opening.

Larger code and storage are distributed across additional stems in `STEM_SUBTREE_WIDTH`-sized groups. Every `STEM_SUBTREE_WIDTH` consecutive code chunks or storage slots share one stem, so sequential access patterns within a range stay local.

If data are mapped into the same stem, the tree MUST keep them under the same `StemNode` until the stem is full.

**Worked example.** A small ERC-20 token contract with 400 bytes of bytecode, a balance mapping, and 3 hot slots has all of the following in one header stem: `BASIC_DATA`, `CODE_HASH`, chunks 0–12 (covering all 400 bytes), and slots 0–2. A single branch opening serves the entire hot state of the contract.

### Key Derivation

All keys are derived from the following primitive, which MUST be implemented as specified:

```python
def get_tree_key(storage_type: int, tree_position: bytes, subindex: int) -> bytes:
    assert 0 <= storage_type <= 255
    assert 0 <= subindex < STEM_SUBTREE_WIDTH
    return bytes([storage_type]) + tree_position + bytes([subindex])
```

#### Account Header Keys

```python
def get_tree_key_for_basic_data(address: Address32) -> bytes:
    return get_tree_key(HEADER_SUBTREE, hash(address), BASIC_DATA_LEAF_KEY)

def get_tree_key_for_code_hash(address: Address32) -> bytes:
    return get_tree_key(HEADER_SUBTREE, hash(address), CODE_HASH_LEAF_KEY)
```

The `BASIC_DATA` leaf encodes four fields in exactly 32 bytes, big-endian:

```
bytes 0–3:   version    (uint32)
bytes 4–11:  balance    (uint64)
bytes 12–19: nonce      (uint64)
bytes 20–31: code_size  (uint96)
```

#### Code Keys

Contract bytecode is divided into 31-byte chunks. Each chunk is stored as a 32-byte leaf value:

```
byte  0:     pushdata_offset  – number of leading bytes in this chunk that are
                                PUSH operand data carried over from the previous chunk
bytes 1–31:  code_slice       – the 31 bytes of bytecode (zero-padded at the end)
```

```python
def get_tree_key_for_code_chunk(address: Address32, chunk_id: int) -> bytes:
    if chunk_id < CODE_CHUNKS_IN_HEADER:
        return get_tree_key(
            HEADER_SUBTREE,
            hash(address),
            CODE_OFFSET + chunk_id,
        )
    overflow = chunk_id - CODE_CHUNKS_IN_HEADER
    high = overflow // STEM_SUBTREE_WIDTH
    low  = overflow % STEM_SUBTREE_WIDTH
    return get_tree_key(
        CODE_SUBTREE,
        hash(address + int_to_bytes32(high)),
        low,
    )
```

#### Storage Keys

```python
def get_tree_key_for_storage_slot(address: Address32, storage_key: int) -> bytes:
    if storage_key < STORAGE_CHUNKS_IN_HEADER:
        return get_tree_key(
            HEADER_SUBTREE,
            hash(address),
            HEADER_STORAGE_OFFSET + storage_key,
        )
    overflow = storage_key - STORAGE_CHUNKS_IN_HEADER
    high = overflow // STEM_SUBTREE_WIDTH
    low  = overflow % STEM_SUBTREE_WIDTH
    return get_tree_key(
        STORAGE_SUBTREE,
        hash(address) + hash(address + int_to_bytes32(high)),
        low,
    )
```

The double-hash construction in `tree_position` for storage (`hash(address) + hash(address + int_to_bytes32(high))`) prevents adversarial alignment: two different contracts cannot be forced to share a `tree_position`, and two different page indices for the same contract produce different positions.

### Node Types

Implementations MUST use exactly three node types:

| Type | Description |
|---|---|
| `EmptyNode` | explicit sentinel representing an absent subtree; MUST NOT be omitted or replaced by `None` |
| `InternalNode` | binary branch with `left` and `right` children, each a `Node`; MUST carry a cached 32-byte subtree hash |
| `StemNode` | holds `stem_prefix` and a fixed-length array `values[STEM_SUBTREE_WIDTH]` of 32-byte leaves |

The insertion algorithm is normative. Implementations MUST follow it exactly to maintain a canonical tree:

```python
def insert(root: Node, key: bytes, value: bytes) -> Node:
    assert len(value) == 32
    stem_prefix, subindex = key[:-1], key[-1]
    return _insert(root, stem_prefix, subindex, value, depth=0)

def _insert(node: Node, stem_prefix: bytes, subindex: int,
            value: bytes, depth: int) -> Node:
    if isinstance(node, EmptyNode):
        stem = StemNode(stem_prefix=stem_prefix,
                        values=[EMPTY_VALUE] * STEM_SUBTREE_WIDTH)
        stem.values[subindex] = value
        return stem

    if isinstance(node, StemNode):
        if node.stem_prefix == stem_prefix:
            node.values[subindex] = value
            return node
        # The two stems diverge at bit `depth`; introduce the minimum
        # number of InternalNodes to separate them.
        return _split(node, stem_prefix, subindex, value, depth)

    # InternalNode: descend by the bit at position `depth`.
    bit = _bit_at(stem_prefix, depth)
    if bit == 0:
        node.left = _insert(node.left, stem_prefix, subindex, value, depth + 1)
    else:
        node.right = _insert(node.right, stem_prefix, subindex, value, depth + 1)
    return node

def _split(existing: StemNode, new_prefix: bytes, subindex: int,
           value: bytes, depth: int) -> Node:
    bit_existing = _bit_at(existing.stem_prefix, depth)
    bit_new      = _bit_at(new_prefix, depth)
    if bit_existing == bit_new:
        # Keep descending until the prefixes diverge.
        child = _split(existing, new_prefix, subindex, value, depth + 1)
        node = InternalNode(left=EmptyNode(), right=EmptyNode())
        if bit_existing == 0:
            node.left = child
        else:
            node.right = child
        return node
    # Prefixes diverge here; place each stem on its own side.
    new_stem = StemNode(stem_prefix=new_prefix,
                        values=[EMPTY_VALUE] * STEM_SUBTREE_WIDTH)
    new_stem.values[subindex] = value
    node = InternalNode(left=EmptyNode(), right=EmptyNode())
    if bit_new == 0:
        node.left, node.right = new_stem, existing
    else:
        node.left, node.right = existing, new_stem
    return node

def _bit_at(data: bytes, position: int) -> int:
    byte_index, bit_index = divmod(position, 8)
    if byte_index >= len(data):
        return 0
    return (data[byte_index] >> (7 - bit_index)) & 1
```

After every insert the tree MUST satisfy:
- No `InternalNode` with both children `EmptyNode`.
- No two distinct key sets produce the same tree structure.
- The Merkle root hash is deterministic given the set of `(key, value)` pairs.

### Circuit Model And Proving Cost

The tree is a circuit-friendly object. Implementations intended for use in ZK pipelines MUST rely only on the following primitive operations:

- single-bit extraction from a fixed-width byte string,
- 32-byte equality comparison,
- fixed-width hash of a fixed-width input.

No variable-arity node logic, no extension-node decompression, and no RLP parsing are required at any point in a proof path.

Expected witness-cost properties:

- The Merkle path length for any key is at most `8 × len(stem_prefix)` bits, bounded by the key length, not by the number of keys in the tree.
- Adjacent accesses within the same stem share one branch opening; $k$ accesses to the same stem cost $O(1)$ branch openings regardless of $k$.
- Worst-case proof size for a single key is $O(\text{key\_bits})$ hashes, with a fixed branching factor of 2 at every level.

### Metadata And State-Expiry Hooks

The design MUST reserve a clear extension point for future metadata. Reserved subindex ranges in each stem MAY be allocated for:

- expiry epoch buckets,
- hot/cold classification flags,
- archival-tier handling bits,
- or other future state-management annotations.

These bits MUST have a defined home before they are needed, not bolted on after the fact. Allocating metadata to reserved leaf indices or to reserved `storage_type` values ensures future extensions can be introduced without changing Merkle paths, circuit assumptions, or existing proof formats.

This extension point is the designed path for state expiry: when expiry semantics are adopted, an epoch identifier or last-access hint can be stored in a reserved leaf adjacent to the data it annotates, without restructuring the tree.

## Rationale For Tree Selection

### Versus Hexary Patricia Trie

| Property | MPT | PBT |
|---|---|---|
| Encoding | RLP, variable node types | fixed-width binary nodes |
| Canonical form | implementation-defined | algorithmically enforced |
| Proof structure | variable hexary branching | uniform binary branching |
| ZK circuit cost | high (variable-arity, RLP) | low (bit tests, fixed-width hashes) |
| Locality | none | first-class via stems |

### Versus Verkle Trees / Polynomial Commitments

Verkle trees reduce proof size by using polynomial commitments and vector openings. The tradeoffs are:

- Verkle proofs rely on elliptic-curve assumptions (KZG or IPA) that are not post-quantum secure.
- Circuit representation of polynomial commitment schemes is more complex than binary hashing.
- Cryptographic agility — swapping the commitment scheme — requires restructuring the tree.

PBT avoids these issues by using a plain hash function. The hash function is swappable without changing the tree structure or the proof format. This is the safer long-term design choice: the structure does not bet on one algebraic assumption remaining tractable.

## Execution Layer Roadmap Compatibility

The PBT is designed to be one half of a two-track execution-layer modernisation:

1. **State tree** (this EIP) — replaces the MPT with a structure that is binary, locality-aware, and hash-agnostic.
2. **VM** (separate EIP) — a more prover-friendly execution model (e.g., RISC-V-centric) reduces the proving cost of execution itself.

The tree is shaped to work with both current EVM execution and a future prover-friendly VM:

- Fixed-width hashes and binary branching map cleanly onto RISC-V memory access patterns.
- Stem-local access patterns reduce the number of distinct memory regions touched in a typical proof.
- The hash-agnostic design allows the proving stack to adopt a ZK-optimal hash (e.g., Poseidon2) without restructuring the tree.

State structure, execution model, and proving stack SHOULD be co-designed so that improvements in one do not introduce regressions in the others.

---

## Broader Protocol Requirements

The following requirements extend beyond the state tree itself. They are recorded here because this EIP is part of a wider set of execution-layer changes and the requirements below are necessary context for evaluating whether those changes succeed as a coherent whole.

---

### Full Verification On Consumer Devices

**Requirement.** Mid-range smartphones MUST be treatable as full verifiers, not merely light clients.

A full verifier validates every block independently, including state transitions and proof verification, without trusting any third party. This is distinct from a light client, which trusts a supermajority of validators.

**Resource budgets.** The protocol MUST stay within the following budgets for a mid-range smartphone (defined as a device with 4 GB RAM, 128 GB storage, and a 50 Mbit/s connection as of 2026):

| Resource | Budget |
|---|---|
| Peak RAM during block verification | ≤ 512 MB |
| Sustained disk write throughput | ≤ 10 MB per slot |
| Historical state storage (pruned) | ≤ 32 GB |
| Bandwidth per slot (receive) | ≤ 1 MB |

These budgets MUST be re-evaluated at least once every two years against the median mid-range device sold in that period.

**Pruning and state-growth controls.** State growth controls MUST be tied directly to the above device budgets. Specifically:

- The effective state size growth rate MUST NOT exceed what allows a device within budget to keep a pruned full-verification state within the storage limit above.
- Any EIP that expands the state MUST include a quantitative analysis showing that the storage budget is not violated over a 4-year horizon at current gas prices.
- State expiry or equivalent mechanisms are REQUIRED if state growth would otherwise breach the storage budget.

**Reference implementation.** A canonical "phone-grade" full verifier implementation MUST be maintained alongside the protocol specification. It MUST:

- run within the resource budgets defined above on reference hardware,
- be kept passing across all future hard forks,
- serve as the compliance target for resource-budget evaluation.

---

### Formal Verification

**Requirement.** Formal verification is a protocol-level requirement, not an optional add-on.

Specifically:

- All future changes to consensus-critical code and the EVM MUST be accompanied by a machine-checked proof of the relevant safety properties before activation.
- A canonical proof language or interchange format for protocol and critical-contract safety properties MUST be standardised. All formally verified proofs MUST be expressed in this format and published alongside the EIP.
- New features MUST be evaluated against a **verifiability budget**: a bounded measure of the proof complexity required to establish their safety. Features that consume a large share of the verifiability budget require proportionally stronger justification. The verifiability budget is tracked alongside the complexity budget (see below).

The rationale is that features which are difficult to formally verify are implicitly riskier: they may contain subtle invariant violations that are not caught by testing or audit alone.

---

### L2 Quality Bar

**Requirement.** L2 systems that interact with Ethereum L1 state MUST meet a minimum quality bar to be considered part of the Ethereum ecosystem.

The minimum bar includes:

| Property | Minimum Requirement |
|---|---|
| Proof system | A validity proof or fraud proof with a published, audited specification MUST exist |
| Dispute window | Fraud-proof dispute windows MUST be ≥ 7 days |
| Data availability | Transaction data MUST be available on-chain or via a DA layer with equivalent security guarantees |
| Bridge design | The canonical bridge MUST use a standardised, formally verified design (see below) |
| Sequencer decentralisation | A credible path to decentralised sequencing MUST be documented and time-bound |

**Cross-L2 bridge standard.** A canonical cross-L2 bridge design MUST be standardised at the protocol level. Ad-hoc, semi-centralised bridges are not acceptable for ecosystem-level infrastructure. The canonical design MUST:

- be formally verified,
- use only on-chain or DA-backed data,
- not rely on off-chain multisigs for security.

**Anti-centralisation expectations for L2 sequencers and MEV.** L2 systems SHOULD document their sequencer model and its centralisation properties. The base protocol's stated goals of decentralisation and censorship resistance MUST be treated as binding constraints on L2 design, not optional aspirations.

---

### Protocol Complexity Management

**Requirement.** The Ethereum protocol MUST be managed as a bounded-complexity system.

**Complexity budget.** A formal complexity budget MUST be maintained. New complexity introduced by any EIP MUST be offset by retiring an equivalent or greater amount of existing complexity. Complexity is measured in terms of:

- number of distinct node or opcode types an implementation must handle,
- number of special cases in the state transition function,
- number of active precompiles and opcodes.

**Deprecation pipeline.** A structured deprecation pipeline MUST exist for legacy features, including:

- problematic precompiles (e.g., those with poor ZK efficiency or active security concerns),
- obsolete opcodes,
- legacy encoding formats (e.g., RLP in contexts where it has been superseded).

Deprecation MUST follow a published schedule with a minimum warning period of two years before removal.

**Simplification hard forks.** At least one hard fork per epoch (approximately every two years) SHOULD be designated as a simplification fork: its primary purpose is removing or replacing legacy features, not introducing new ones. New features MAY be bundled with a simplification fork only if they are net-negative in complexity.

---

### Privacy Baseline

**Requirement.** The Ethereum protocol and its canonical infrastructure MUST provide a baseline privacy layer for common client operations.

Specifically:

- Balance queries, log retrieval, and history lookups MUST be serviceable without revealing the querying client's address or IP to any single server.
- Node discovery MUST NOT require participating nodes to expose wallet addresses or query patterns to peers.
- Core infrastructure MUST NOT implement dark patterns — design choices that lead to unintentional disclosure of user data to aggregators or analytics services.

**Wallet UX defaults.** Social recovery and time-lock mechanisms MUST be the default UX pattern in wallet standards that interact with the base protocol, not niche add-ons. Recovery mechanisms SHOULD be usable without on-chain disclosure of the recovery path until it is invoked.

---

### Decentralisation Metrics And Enforcement

**Requirement.** Decentralisation is a quantitative protocol property, not a qualitative aspiration.

**Metrics.** The following metrics MUST be tracked and published at least quarterly:

| Metric | Description |
|---|---|
| Client diversity | fraction of validators per execution and consensus client |
| Node geographic distribution | Gini coefficient of nodes by country and ASN |
| Solo vs. pooled staking | fraction of stake held by solo stakers vs. liquid staking pools |
| RPC reliance | fraction of user transactions routed through centralised RPC providers |
| Builder / proposer concentration | HHI of block proposer and builder market |

**Trigger thresholds.** The following thresholds MUST trigger a defined protocol or ecosystem response when breached:

| Metric | Threshold | Required Response |
|---|---|---|
| Single client > 33% of validators | breach of 33% | client team issued a mandatory diversity advisory; hard fork timeline reviewed |
| Single staking pool > 33% of stake | breach of 33% | protocol-level review of staking incentive parameters |
| Single RPC provider > 50% of transactions | breach of 50% | accelerated deployment of privacy-preserving RPC alternatives |

**Roadmap gating.** Major roadmap items — including execution layer upgrades, account abstraction, scaling changes, and zkEVM activation — MUST include a decentralisation impact assessment before activation. An item that is projected to worsen any metric beyond its trigger threshold MUST be modified or deferred until the impact is addressed.

---

### Quantum-Resistant Cryptography

**Requirement.** Quantum-resistant signatures MUST be a first-class option, not an optional add-on, with clear migration paths and published performance targets.

**Scheme requirements.** The protocol MUST support at least one signature scheme that is secure against a cryptographically relevant quantum computer (CRQC). Acceptable families include:

| Family | Example schemes | Notes |
|---|---|---|
| Hash-based | SPHINCS+, XMSS | stateless or stateful; well-understood security |
| Lattice-based | Dilithium (ML-DSA), Falcon | NIST-standardised; smaller signatures than hash-based |
| Hybrid | classical + post-quantum | transition period only; MUST NOT be the long-term target |

**Performance targets.** Any PQ scheme activated at the protocol level MUST meet the following targets on the reference phone-grade device:

| Operation | Target |
|---|---|
| Signature verification | ≤ 5 ms per signature |
| Signature generation | ≤ 50 ms |
| Signature size | ≤ 4 kB |
| Public key size | ≤ 2 kB |

**Migration path.** The protocol MUST define a concrete, time-bound migration path:

1. **Opt-in phase.** PQ signature types are supported alongside existing ECDSA/BLS. Accounts MAY migrate voluntarily.
2. **Default phase.** New accounts default to PQ signatures. Existing accounts receive a migration incentive window of at least 4 years.
3. **Deprecation phase.** Classical signature types are deprecated with at least 2 years' notice and removed in a designated simplification hard fork.

Account abstraction (EIP-4337 or equivalent) MUST be the migration mechanism: accounts transition by updating their verification logic, not by changing the address derivation. This avoids forced re-registration.

**Design goal.** "Secure for 100 years" MUST be a realistic design goal, not a slogan. Any signature scheme activated at the protocol level MUST have a published security analysis projecting resistance to both classical and quantum attack for at least 100 years at current algorithmic knowledge.

---

### Edge Verification As Default

**Requirement.** Verified RPC MUST be the default UX for wallets, not an opt-in feature.

**Principle.** A wallet that receives a response from an untrusted RPC endpoint MUST treat that response as an unverified input and verify it locally before presenting it to the user. Wallets that do not verify are violating this requirement.

**Verification mechanisms.** Wallets MUST support at least one of:

- **ZK-EVM verification:** verify a succinct proof of state transitions locally (e.g., SP1, Risc0, or equivalent).
- **Helios-style light client:** verify block headers against the sync committee, then verify state proofs against the verified header.
- **Full local node:** the wallet runs or is directly connected to a locally verified full node.

The PBT defined in this EIP is designed to make the second option significantly cheaper: a single stem opening serves the hot state of a typical account, reducing the data required for a Helios-style state proof from many independent trie paths to one stem proof.

**RPC trust model.** Wallets MUST clearly communicate to users whether an RPC response has been locally verified. Unverified data MUST be visually distinguished in wallet UIs. The phrase "verified" in a wallet UI MUST mean locally verified, not "from a trusted provider."

**Consumer hardware guarantee.** The protocol MUST be designed so that a mid-range smartphone can run meaningful local verification — not merely light-client heuristics — for all state queries that a typical user makes. See the resource budgets in the Full Verification section above.

---

### Privacy Queries And Oblivious Access

**Requirement.** Balance queries, log retrieval, and history lookups MUST be serviceable without leaking user behaviour to infrastructure providers.

**Threat model.** An adversary operating an RPC provider can observe:

- which addresses a wallet queries,
- the timing and frequency of those queries,
- correlations between query patterns and transaction broadcast.

This is sufficient to deanonymise users with high confidence, even without access to private keys.

**Required mechanisms.** Reference wallet and client designs MUST integrate at least one of the following privacy-preserving query mechanisms:

| Mechanism | Description |
|---|---|
| Private Information Retrieval (PIR) | the server answers a query without learning which item was requested |
| Oblivious RAM (ORAM) | access patterns are hidden from the server entirely |
| Mixnet routing | queries are routed through a mix network before reaching the RPC endpoint |
| Redundant multi-provider queries | queries are sent to multiple independent providers and results are compared; no single provider sees the full query pattern |

At minimum, reference wallet implementations MUST support redundant multi-provider queries as a baseline. PIR or ORAM integration is RECOMMENDED for production wallets handling sensitive financial data.

**Privacy payments.** "Privacy payments that feel like normal payments" MUST be a core UX goal, not a feature limited to specialised applications. Specifically:

- Account abstraction MUST be the mechanism for integrating privacy-preserving payment flows (e.g., stealth addresses, note-based schemes).
- The base protocol MUST not penalise privacy-preserving transactions with disproportionate gas costs relative to equivalent transparent transactions.
- Reference wallet UX MUST treat privacy-preserving payment as an option available within one tap, not buried in advanced settings.

---

### Social Recovery And Time-Locks As Default

**Requirement.** Social recovery wallets and time-locks MUST be the default account type, not a niche configuration.

**Account abstraction mandate.** The base protocol MUST treat account abstraction as the standard account model. The default account type presented to new users MUST include:

- a configurable guardian set for social recovery,
- a time-lock on large outgoing transfers (configurable, minimum 24 hours by default),
- a recovery path that does not require on-chain disclosure of the guardian set until recovery is invoked.

**Base-protocol support.** Protocol changes that improve the efficiency of social recovery and time-lock patterns (e.g., cheaper batched guardian signature verification, native time-lock opcodes) MUST be prioritised over features that primarily benefit custodial workflows.

**Key theft resistance.** The default account type MUST be designed so that theft of the signing key alone is insufficient to drain the account without the time-lock expiring. This requires that:

- time-locked transfers be cancellable by the signing key before the lock expires,
- social recovery guardians be able to cancel a pending transfer and freeze the account if key theft is detected.

---

### Censorship Resistance And Inclusion Guarantees

**Requirement.** Censorship resistance MUST be an enforced property of block production, not a social ideal.

**Fork-Choice Enforced Inclusion Lists (FOCIL).** The protocol MUST adopt a mechanism equivalent to FOCIL or stronger, such that:

- a designated set of inclusion-list contributors publish the set of transactions that MUST be included in the next block,
- a block that omits a transaction present in the inclusion list is invalid (not merely penalised),
- the inclusion list contributor set is sufficiently large and randomised that a single actor cannot suppress a transaction without controlling an implausibly large share of the validator set.

**MEV and ordering fairness.** The protocol SHOULD adopt constraints on block-building that limit the ability of proposers and builders to reorder transactions for extractable value in ways that harm ordinary users. Specifically:

- Transactions from the public mempool MUST have a guaranteed inclusion path that does not depend on tipping a specific builder.
- The protocol SHOULD define a "fair ordering" window: within a defined time window, transactions with equal effective fees SHOULD be included in arrival order at the relay level.
- MEV redistribution mechanisms (e.g., attester-proposer separation, MEV burn) are RECOMMENDED and MUST be evaluated against the decentralisation metrics defined above before activation.

**Censorship measurement.** The Ethereum Foundation or a designated neutral body MUST publish monthly censorship resistance metrics, including:

- the fraction of OFAC-listed (or equivalently-flagged) transactions that were delayed more than one slot,
- the distribution of inclusion latency by transaction type,
- the fraction of blocks built by the top-3 builders.

---

### Formal Verification And AI-Assisted Proofs

**Requirement.** Formal verification of protocol-critical code is a first-class development requirement, not a post-hoc audit activity.

**Scope.** The following categories of code MUST have machine-checked proofs before activation:

| Category | Required proof properties |
|---|---|
| Consensus rules (fork choice, finality) | safety and liveness under the assumed network model |
| EVM opcodes and precompiles | correct state-transition semantics; no undefined behaviour |
| Critical system contracts (deposit contract, withdrawal queue) | invariant preservation under all reachable inputs |
| The PBT insertion and deletion algorithms defined in this EIP | canonical form preservation; no duplicate keys |

**AI-assisted proof generation.** AI-generated proofs are PERMITTED as a helper tool, subject to the following constraints:

- AI-generated proof steps MUST be checked by a mechanised proof assistant (e.g., Lean 4, Coq, Isabelle/HOL). An AI-generated proof that has not been machine-checked does not satisfy this requirement.
- The canonical proof language standardised by this EIP MUST be usable as the output format for AI-generated proofs, so that proofs can be re-checked independently.
- AI tools used in the proof pipeline MUST be disclosed in the EIP. The proof MUST be reproducible without the specific AI tool used to generate it.

**Proof tooling pipeline.** A standard tooling pipeline MUST be maintained as part of the Ethereum development infrastructure:

- A CI system that re-checks all published proofs on every spec change.
- A library of reusable proof components for common EVM and PBT properties.
- Public proof dashboards showing the current verified coverage of each protocol component.

**Verifiability budget (extended).** As defined in the Formal Verification section above, the verifiability budget measures the proof complexity cost of a feature. The budget MUST be denominated in terms of:

- lines of proof code required in the canonical proof language,
- number of new lemmas introduced that have no prior counterparts in the proof library,
- estimated human review time for the proof.

Features with a verifiability-budget cost above a defined threshold MUST be reviewed by at least two independent proof engineers before activation.

---

### Trust-Minimised Cross-Chain Interoperability

**Requirement.** Cross-chain bridges and interoperability mechanisms MUST be simple, verifiable, and trust-minimised. Opaque, highly centralised bridges are not acceptable as ecosystem infrastructure.

**Bridge security tiers.** The protocol MUST define and publish a bridge security tier system:

| Tier | Description | Required for |
|---|---|---|
| Tier 1 (native) | validity-proof-backed; no external trust assumptions | canonical L1↔L2 bridges |
| Tier 2 (optimistic) | fraud-proof-backed; ≥ 7-day dispute window; DA on-chain | L2↔L2 bridges for EVM-equivalent chains |
| Tier 3 (light-client) | cross-chain light client with ZK header proofs | non-EVM chains |
| Tier 4 (multisig) | off-chain multisig or committee | NOT ACCEPTABLE for any bridge handling > $10M TVL |

Tier 4 bridges MUST NOT be endorsed or linked from official Ethereum ecosystem resources.

**Self-sovereignty preservation.** Interoperability features MUST preserve the user's ability to:

- verify the state of any chain they are interacting with independently,
- exit a chain or bridge without the cooperation of any third party (forced exit guarantee),
- receive assets on the destination chain using the same key material as on the source chain, without registering with a third party.

**Trust-minimised messaging standard.** A canonical cross-chain message format MUST be standardised. The format MUST:

- include a ZK proof or fraud proof of the source-chain state,
- be verifiable on the destination chain without external oracles,
- have a formally verified reference implementation published alongside the standard.

**Interoperability and verification alignment.** All cross-chain interoperability features MUST be evaluated against the edge-verification requirement above: a mid-range smartphone MUST be able to verify cross-chain state independently, not merely accept an attestation from a relayer.

---

### Delete And Update Operations

**Delete.** Setting a leaf to `EMPTY_VALUE` is logically equivalent to deletion. After setting `stem.values[subindex] = EMPTY_VALUE`, if all 256 values in a `StemNode` are `EMPTY_VALUE`, the `StemNode` MUST be replaced by `EmptyNode`. After collapsing a `StemNode`, if the parent `InternalNode` now has one `EmptyNode` child and one `StemNode` child, the `InternalNode` MUST be replaced by the surviving `StemNode`. This ensures the canonical minimal structure is always maintained.

```python
def delete(root: Node, key: bytes) -> Node:
    stem_prefix, subindex = key[:-1], key[-1]
    return _delete(root, stem_prefix, subindex, depth=0)

def _delete(node: Node, stem_prefix: bytes, subindex: int, depth: int) -> Node:
    if isinstance(node, EmptyNode):
        return node  # nothing to delete

    if isinstance(node, StemNode):
        if node.stem_prefix != stem_prefix:
            return node  # key not present
        node.values[subindex] = EMPTY_VALUE
        if all(v == EMPTY_VALUE for v in node.values):
            return EmptyNode()
        return node

    bit = _bit_at(stem_prefix, depth)
    if bit == 0:
        node.left = _delete(node.left, stem_prefix, subindex, depth + 1)
    else:
        node.right = _delete(node.right, stem_prefix, subindex, depth + 1)

    # Collapse internal node if one side is now empty.
    if isinstance(node.left, EmptyNode) and not isinstance(node.right, EmptyNode):
        return node.right
    if isinstance(node.right, EmptyNode) and not isinstance(node.left, EmptyNode):
        return node.left
    if isinstance(node.left, EmptyNode) and isinstance(node.right, EmptyNode):
        return EmptyNode()
    return node
```

**Update.** Updating an existing leaf is identical to insert: call `insert(root, key, new_value)`. No special update path is required.

### Proof Generation And Verification

A Merkle proof for key $k$ in a tree with root hash $R$ is a sequence of sibling hashes along the path from the root to the `StemNode` containing $k$, plus the full `StemNode` values (or a subset, for multi-key proofs).

```python
from dataclasses import dataclass, field

@dataclass
class MerkleProof:
    key: bytes
    value: bytes                   # 32 bytes; EMPTY_VALUE if absent
    stem_values: list[bytes]       # all 256 leaves of the stem (for single-key proofs)
    path_siblings: list[bytes]     # sibling hashes, root-to-leaf order
    path_bits: list[int]           # 0 = we went left, 1 = we went right

def get_proof(root: Node, key: bytes) -> MerkleProof:
    stem_prefix, subindex = key[:-1], key[-1]
    siblings: list[bytes] = []
    bits: list[int] = []
    node = root
    depth = 0
    while isinstance(node, InternalNode):
        bit = _bit_at(stem_prefix, depth)
        bits.append(bit)
        if bit == 0:
            siblings.append(_node_hash(node.right))
            node = node.left
        else:
            siblings.append(_node_hash(node.left))
            node = node.right
        depth += 1
    if isinstance(node, StemNode) and node.stem_prefix == stem_prefix:
        value = node.values[subindex]
        stem_values = list(node.values)
    else:
        value = EMPTY_VALUE
        stem_values = [EMPTY_VALUE] * STEM_SUBTREE_WIDTH
    return MerkleProof(
        key=key, value=value,
        stem_values=stem_values,
        path_siblings=siblings,
        path_bits=bits,
    )

def verify_proof(root_hash: bytes, proof: MerkleProof) -> bool:
    stem_prefix, subindex = proof.key[:-1], proof.key[-1]
    if proof.stem_values[subindex] != proof.value:
        return False
    # Recompute the stem hash.
    current = _hash_stem(stem_prefix, proof.stem_values)
    # Walk back up the path.
    for sibling, bit in zip(reversed(proof.path_siblings), reversed(proof.path_bits)):
        if bit == 0:
            current = tree_hash(current + sibling)
        else:
            current = tree_hash(sibling + current)
    return current == root_hash
```

`_hash_stem(stem_prefix, values)` MUST be defined as:

```python
def _hash_stem(stem_prefix: bytes, values: list[bytes]) -> bytes:
    # Commit to the stem prefix and all 256 values in a single hash.
    payload = stem_prefix + b"".join(values)
    return tree_hash(payload)
```

`_node_hash` for an `InternalNode` MUST be:

```python
def _node_hash(node: Node) -> bytes:
    if isinstance(node, EmptyNode):
        return EMPTY_HASH               # tree_hash(b"") precomputed
    if isinstance(node, StemNode):
        return _hash_stem(node.stem_prefix, node.values)
    return tree_hash(_node_hash(node.left) + _node_hash(node.right))
```

Multi-key proofs MAY share path prefixes and stem nodes; the proof format for multi-key witnesses is out of scope for this EIP but MUST be compatible with the single-key proof above.

### Gas Accounting

The PBT introduces a **stem-aware** access cost model. Within a single transaction:

| Operation | Cost |
|---|---|
| First access to a stem (branch opening) | `WITNESS_BRANCH_COST` |
| Each additional leaf access within an already-opened stem | `WITNESS_CHUNK_COST` |
| Writing a new leaf (previously `EMPTY_VALUE`) | `WITNESS_CHUNK_COST + WRITE_NEW_LEAF_COST` |
| Updating an existing leaf | `WITNESS_CHUNK_COST` |

Exact values for `WITNESS_BRANCH_COST`, `WITNESS_CHUNK_COST`, and `WRITE_NEW_LEAF_COST` are defined in the accompanying gas-repricing EIP and are not set here. The accounting rule that MUST hold is:

> If two accesses to the same `(storage_type, tree_position)` occur in the same transaction, only the first pays `WITNESS_BRANCH_COST`.

This rule is the protocol-level expression of the locality guarantee: co-locating data in a stem makes repeated access cheaper, creating an economic incentive for contracts to use sequential key layouts.

### State Migration

Transition from the MPT to the PBT MUST follow a two-phase migration:

**Phase 1 (conversion block).** At the designated fork block, the entire MPT state is converted to PBT in-place. The conversion function is:

```python
def migrate_account(mpt_account: MPTAccount) -> None:
    addr = mpt_account.address
    insert(state_root, get_tree_key_for_basic_data(addr),
           encode_basic_data(mpt_account.version, mpt_account.balance,
                             mpt_account.nonce, len(mpt_account.code)))
    insert(state_root, get_tree_key_for_code_hash(addr),
           mpt_account.code_hash)
    for chunk_id, chunk in enumerate(chunk_code(mpt_account.code)):
        insert(state_root, get_tree_key_for_code_chunk(addr, chunk_id), chunk)
    for slot, value in mpt_account.storage.items():
        insert(state_root, get_tree_key_for_storage_slot(addr, slot),
               value.to_bytes(32, "big"))
```

**Phase 2 (post-fork).** All new state writes go directly to the PBT. The MPT is read-only for historical proof purposes only. Clients MAY prune the MPT after a sufficient number of blocks (suggested: 8192 blocks after the fork).

The conversion MUST produce a deterministic PBT root from any valid MPT state. Test vectors MUST be published alongside the EIP to allow independent verification of the migration output.

---

## Backwards Compatibility

This EIP is **not** backwards compatible with the existing MPT-based state. It requires a hard fork. The following are the principal breaking changes:

| Component | Breaking change |
|---|---|
| State root | PBT root replaces MPT root in block headers |
| Storage proofs | `eth_getProof` response format changes |
| State sync (snap/fast) | Snap protocol requires adaptation to PBT stem structure |
| Historical proofs | MPT proofs are invalid for post-fork blocks |
| Account encoding | RLP account encoding is replaced by fixed-width leaf encoding |

Clients MUST continue to serve MPT proofs for pre-fork blocks. State sync for post-fork blocks MUST use the PBT-native stem-sync protocol.

---

## Security Considerations

### Pre-Image Resistance

The security of the PBT depends on the pre-image resistance of the hash function used for `tree_position` derivation. An adversary who can find `hash(x) = hash(y)` for `x ≠ y` could place two accounts at the same stem, causing a collision. The hash function MUST have at least 128-bit pre-image resistance.

### Anti-DoS Key Construction

The double-hash construction for storage `tree_position`:

```
hash(address) + hash(address + int_to_bytes32(high))
```

ensures that an adversary cannot arrange two contracts to share a `tree_position` without knowing a pre-image collision. The secondary hash `hash(address + int_to_bytes32(high))` is distinct for every `(address, page)` pair.

### Canonical Form And Proof Uniqueness

Because the tree structure is uniquely determined by the key set, there is exactly one valid Merkle root for any given state. Clients that accept non-canonical tree structures MUST be treated as non-conforming. Proof verifiers MUST reject proofs that imply a non-canonical tree shape (e.g., an `InternalNode` with one `EmptyNode` child that could have been collapsed).

### Hash Function Agility

The hash function is a deployment parameter. Changing the hash function after activation produces a different root for the same state. Any proposal to change the hash function after deployment MUST treat it as equivalent to a state migration and MUST include a hard fork with a defined transition block.

### Witness Completeness

A stateless verifier executing a transaction MUST receive a witness that covers every stem accessed during execution. An incomplete witness allows an attacker to present a block that appears valid to a verifier that does not know the missing state. Execution clients MUST reject blocks whose witnesses are incomplete with respect to the EVM trace.

---

## Test Cases

The following test vectors MUST be satisfied by any conforming implementation.

### Empty Tree

```
root_hash(EmptyNode) == tree_hash(b"")
```

### Single Insert

```
address = bytes(32)         # 32 zero bytes
key     = get_tree_key_for_basic_data(address)
value   = encode_basic_data(version=0, balance=1000, nonce=1, code_size=0)
root    = insert(EmptyNode(), key, value)
# The root MUST be a StemNode, not an InternalNode.
assert isinstance(root, StemNode)
assert root.values[BASIC_DATA_LEAF_KEY] == value
```

### Locality Invariant

```
addr  = bytes(32)
root  = EmptyNode()
for slot in range(STORAGE_CHUNKS_IN_HEADER):
    key  = get_tree_key_for_storage_slot(addr, slot)
    root = insert(root, key, slot.to_bytes(32, "big"))
# All four slots share the header stem: the root MUST still be a StemNode.
assert isinstance(root, StemNode)
```

### Proof Round-Trip

```
root  = <tree with at least two stems>
key   = <any key present in the tree>
proof = get_proof(root, key)
assert verify_proof(root_hash(root), proof) is True
# Tamper with the value.
tampered = MerkleProof(**{**proof.__dict__, "value": bytes(32)})
assert verify_proof(root_hash(root), tampered) is False
```

Full test vector files (including migration vectors from MPT state) MUST be published in the EIP's `assets/` directory before this EIP moves to Final status.

---

## Reference Implementation

A reference implementation in Python is maintained at [`pbt/`](./pbt/) in this repository. It includes:

| Module | Contents |
|---|---|
| `pbt/constants.py` | all protocol constants with invariant assertions |
| `pbt/hash.py` | hash-function abstraction and built-in variants |
| `pbt/nodes.py` | `EmptyNode`, `InternalNode`, `StemNode` |
| `pbt/tree.py` | `insert`, `delete`, `get`, `root_hash`, `get_proof`, `verify_proof` |
| `pbt/embedding.py` | Ethereum-specific key derivation and leaf encoding |
| `tests/` | property-based and unit tests covering all test cases above |

The reference implementation is normative for tie-breaking in cases where this document is ambiguous. It MUST stay within the phone-grade resource budgets defined in the Broader Protocol Requirements section.

---

## Open Questions

- Final hash function choice (BLAKE3, Keccak-256, or Poseidon2) and the process for finalising it.
- Whether metadata bits live in reserved leaf indices or a dedicated `storage_type` range.
- Canonical proof language selection for the formal verification requirement.
- Precise definition and tooling for the verifiability budget.
- Exact resource-budget figures for the phone-grade full verifier as device capabilities evolve.
- Multi-key witness format and its interaction with the single-key proof defined above.
- Snap-sync protocol adaptation for PBT stem structure.
- Mechanism for triggering the sequencer decentralisation requirement at the protocol level vs. ecosystem level.

---

## Copyright

Copyright and related rights waived via [CC0](https://creativecommons.org/publicdomain/zero/1.0/).
