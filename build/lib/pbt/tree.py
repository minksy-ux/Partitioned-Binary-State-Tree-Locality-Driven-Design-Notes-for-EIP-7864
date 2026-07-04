"""
Core Partitioned Binary Tree operations.

All functions are pure with respect to the logical tree state:
  - insert / delete return a (possibly new) root Node
  - get returns the 32-byte value or EMPTY_VALUE
  - root_hash returns the 32-byte Merkle root
  - get_proof / verify_proof implement the single-key proof API

The insertion and deletion algorithms are normative per the EIP.
"""

from __future__ import annotations

from dataclasses import dataclass

from .constants import EMPTY_VALUE, STEM_SUBTREE_WIDTH
from .hash import tree_hash
from .nodes import STEM_HASH_DOMAIN, EmptyNode, InternalNode, Node, StemNode

# ---------------------------------------------------------------------------
# Bit helpers
# ---------------------------------------------------------------------------

def _bit_at(data: bytes, position: int) -> int:
    """Return the bit at `position` (big-endian, MSB-first) of `data`."""
    byte_index, bit_index = divmod(position, 8)
    if byte_index < len(data):
        return (data[byte_index] >> (7 - bit_index)) & 1
    return 0


def _path_bit_at(data: bytes, position: int) -> int:
    """Bit accessor used for tree paths.

    Uses an implicit terminator bit after the payload bits so finite prefixes
    are uniquely decodable and split recursion always terminates.
    """
    byte_index, bit_index = divmod(position, 8)
    if byte_index < len(data):
        return (data[byte_index] >> (7 - bit_index)) & 1
    if byte_index == len(data) and bit_index == 0:
        return 1
    return 0


def _common_prefix_len(a: bytes, b: bytes) -> int:
    """Return the number of leading bits shared by `a` and `b`."""
    length = min(len(a), len(b)) * 8
    for i in range(length):
        if _bit_at(a, i) != _bit_at(b, i):
            return i
    return length


# ---------------------------------------------------------------------------
# Key splitting
# ---------------------------------------------------------------------------

def split_key(key: bytes) -> tuple[bytes, int]:
    """
    Split a PBT key into (stem_prefix, subindex).

    stem_prefix = key[:-1]
    subindex    = key[-1]
    """
    if len(key) < 2:
        raise ValueError(f"Key too short: {key!r}")
    return key[:-1], key[-1]


# ---------------------------------------------------------------------------
# Insert
# ---------------------------------------------------------------------------

def insert(root: Node, key: bytes, value: bytes) -> Node:
    """
    Insert (key, value) into the tree rooted at `root`.

    Returns the new root.  The input root is not modified in-place for
    InternalNode/EmptyNode cases; StemNode values are updated in-place
    when the stem already exists.

    value MUST be exactly 32 bytes.
    """
    if len(value) != 32:
        raise ValueError("value must be exactly 32 bytes")
    stem_prefix, subindex = split_key(key)
    return _insert(root, stem_prefix, subindex, value, depth=0)


def _insert(node: Node, stem_prefix: bytes, subindex: int,
            value: bytes, depth: int) -> Node:
    if isinstance(node, EmptyNode):
        stem = StemNode(
            stem_prefix=stem_prefix,
            values=[EMPTY_VALUE] * STEM_SUBTREE_WIDTH,
        )
        stem.values[subindex] = value
        return stem

    if isinstance(node, StemNode):
        if node.stem_prefix == stem_prefix:
            node.values[subindex] = value
            node.invalidate()
            return node
        return _split_stems(node, stem_prefix, subindex, value, depth)

    # InternalNode: descend by the bit at `depth`.
    assert isinstance(node, InternalNode)
    bit = _path_bit_at(stem_prefix, depth)
    if bit == 0:
        node.left = _insert(node.left, stem_prefix, subindex, value, depth + 1)
    else:
        node.right = _insert(node.right, stem_prefix, subindex, value, depth + 1)
    node.invalidate()
    return node


def _split_stems(existing: StemNode, new_prefix: bytes, subindex: int,
                 value: bytes, depth: int) -> Node:
    """
    Introduce the minimum number of InternalNodes to separate two stems
    whose prefixes first diverge at or after bit `depth`.
    """
    bit_existing = _path_bit_at(existing.stem_prefix, depth)
    bit_new = _path_bit_at(new_prefix, depth)

    if bit_existing == bit_new:
        # Bits still agree; descend one more level.
        child = _split_stems(existing, new_prefix, subindex, value, depth + 1)
        node = InternalNode()
        if bit_existing == 0:
            node.left = child
        else:
            node.right = child
        return node

    # Bits differ here; place each stem on its own side.
    new_stem = StemNode(
        stem_prefix=new_prefix,
        values=[EMPTY_VALUE] * STEM_SUBTREE_WIDTH,
    )
    new_stem.values[subindex] = value

    node = InternalNode()
    if bit_new == 0:
        node.left, node.right = new_stem, existing
    else:
        node.left, node.right = existing, new_stem
    return node


# ---------------------------------------------------------------------------
# Get
# ---------------------------------------------------------------------------

def get(root: Node, key: bytes) -> bytes:
    """
    Return the 32-byte value stored at `key`, or EMPTY_VALUE if absent.
    """
    stem_prefix, subindex = split_key(key)
    return _get(root, stem_prefix, subindex, depth=0)


def _get(node: Node, stem_prefix: bytes, subindex: int, depth: int) -> bytes:
    if isinstance(node, EmptyNode):
        return EMPTY_VALUE

    if isinstance(node, StemNode):
        if node.stem_prefix == stem_prefix:
            return node.values[subindex]
        return EMPTY_VALUE

    assert isinstance(node, InternalNode)
    bit = _path_bit_at(stem_prefix, depth)
    if bit == 0:
        return _get(node.left, stem_prefix, subindex, depth + 1)
    return _get(node.right, stem_prefix, subindex, depth + 1)


# ---------------------------------------------------------------------------
# Delete
# ---------------------------------------------------------------------------

def delete(root: Node, key: bytes) -> Node:
    """
    Delete the leaf at `key`.

    Setting a leaf to EMPTY_VALUE is equivalent to deletion.
    After deletion, collapsed StemNodes and InternalNodes are removed to
    maintain canonical minimal structure.

    Returns the new root.
    """
    stem_prefix, subindex = split_key(key)
    return _delete(root, stem_prefix, subindex, depth=0)


def _delete(node: Node, stem_prefix: bytes, subindex: int, depth: int) -> Node:
    if isinstance(node, EmptyNode):
        return node

    if isinstance(node, StemNode):
        if node.stem_prefix != stem_prefix:
            return node
        node.values[subindex] = EMPTY_VALUE
        node.invalidate()
        if node.is_empty():
            return EmptyNode()
        return node

    assert isinstance(node, InternalNode)
    bit = _path_bit_at(stem_prefix, depth)
    if bit == 0:
        node.left = _delete(node.left, stem_prefix, subindex, depth + 1)
    else:
        node.right = _delete(node.right, stem_prefix, subindex, depth + 1)
    node.invalidate()

    # Canonical collapse:
    # - both empty => EmptyNode
    # - one empty and one StemNode => surviving StemNode
    # - one empty and one InternalNode => keep this InternalNode
    #   (depth semantics would be invalid if we bypassed to the child).
    left_empty = isinstance(node.left, EmptyNode)
    right_empty = isinstance(node.right, EmptyNode)

    if left_empty and right_empty:
        return EmptyNode()
    if left_empty and isinstance(node.right, StemNode):
        return node.right
    if right_empty and isinstance(node.left, StemNode):
        return node.left
    return node


# ---------------------------------------------------------------------------
# Root hash
# ---------------------------------------------------------------------------

def root_hash(root: Node) -> bytes:
    """Return the 32-byte Merkle root of the tree."""
    return root.node_hash()


# ---------------------------------------------------------------------------
# Proof generation and verification
# ---------------------------------------------------------------------------

@dataclass
class MerkleProof:
    """
    Single-key Merkle proof.

    path_siblings: sibling hashes from root downward.
    path_bits:     0 = we went left at this level, 1 = we went right.
    stem_values:   all 256 leaf values of the matched (or absent) stem.
    key:           the queried key.
    value:         the 32-byte value (EMPTY_VALUE if the key is absent).
    """
    key: bytes
    value: bytes
    stem_values: list[bytes]
    path_siblings: list[bytes]
    path_bits: list[int]


@dataclass
class BatchMerkleProof:
    """Canonical multi-key proof bundle.

    keys are stored in lexicographic order and map 1:1 to proofs.
    deduplicated_siblings are sorted lexicographically to provide a
    deterministic shared-sibling commitment surface for batch transports.
    """

    keys: list[bytes]
    values: list[bytes]
    proofs: list[MerkleProof]
    deduplicated_siblings: list[bytes]
    key_to_proof_index: list[int]


def get_proof(root: Node, key: bytes) -> MerkleProof:
    """
    Generate a Merkle proof for `key` in the tree rooted at `root`.

    The proof is self-contained: verify_proof(root_hash(root), proof)
    returns True for the returned proof.
    """
    stem_prefix, subindex = split_key(key)
    siblings: list[bytes] = []
    bits: list[int] = []

    node = root
    depth = 0
    while isinstance(node, InternalNode):
        bit = _path_bit_at(stem_prefix, depth)
        bits.append(bit)
        if bit == 0:
            siblings.append(node.right.node_hash())
            node = node.left
        else:
            siblings.append(node.left.node_hash())
            node = node.right
        depth += 1

    if isinstance(node, StemNode) and node.stem_prefix == stem_prefix:
        value = node.values[subindex]
        stem_values = list(node.values)
    else:
        value = EMPTY_VALUE
        stem_values = [EMPTY_VALUE] * STEM_SUBTREE_WIDTH

    return MerkleProof(
        key=key,
        value=value,
        stem_values=stem_values,
        path_siblings=siblings,
        path_bits=bits,
    )


def _hash_stem(stem_prefix: bytes, values: list[bytes]) -> bytes:
    """
    Compute the hash of a StemNode deterministically.

    This function is the canonical commitment to the stem's contents and
    MUST be used both in node_hash() and in proof verification.
    """
    payload = STEM_HASH_DOMAIN + stem_prefix + b"".join(values)
    return tree_hash(payload)


def verify_proof(rh: bytes, proof: MerkleProof) -> bool:
    """
    Verify a MerkleProof against a known root hash.

    Returns True iff the proof is valid and proof.value is the correct
    value for proof.key in the tree whose root hash is `rh`.
    """
    stem_prefix, subindex = split_key(proof.key)

    # The claimed value must match the stem values array.
    if len(proof.stem_values) != STEM_SUBTREE_WIDTH:
        return False
    if proof.stem_values[subindex] != proof.value:
        return False

    # Recompute the stem hash.
    current = _hash_stem(stem_prefix, proof.stem_values)

    # Walk back up the path using sibling hashes.
    if len(proof.path_siblings) != len(proof.path_bits):
        return False

    for sibling, bit in zip(reversed(proof.path_siblings), reversed(proof.path_bits)):
        if bit == 0:
            # We went left, so sibling is on the right.
            current = tree_hash(current + sibling)
        else:
            # We went right, so sibling is on the left.
            current = tree_hash(sibling + current)

    return current == rh


def get_multi_proof(root: Node, keys: list[bytes]) -> BatchMerkleProof:
    """Build a canonical batch proof for multiple keys.

    Keys are deduplicated then sorted lexicographically to ensure deterministic
    output across implementations.
    """
    ordered_keys = sorted(set(keys))
    proofs: list[MerkleProof] = []
    values: list[bytes] = []
    sibling_set: set[bytes] = set()

    for key in ordered_keys:
        proof = get_proof(root, key)
        proofs.append(proof)
        values.append(proof.value)
        sibling_set.update(proof.path_siblings)

    return BatchMerkleProof(
        keys=ordered_keys,
        values=values,
        proofs=proofs,
        deduplicated_siblings=sorted(sibling_set),
        key_to_proof_index=list(range(len(ordered_keys))),
    )


def verify_multi_proof(rh: bytes, batch_proof: BatchMerkleProof) -> bool:
    """Verify a canonical batch proof.

    Validation rules:
    - key ordering must be canonical (lexicographic ascending, unique),
    - vectors must have aligned lengths,
    - each constituent MerkleProof must verify against the same root.
    """
    if batch_proof.keys != sorted(set(batch_proof.keys)):
        return False
    n = len(batch_proof.keys)
    if len(batch_proof.values) != n:
        return False
    if len(batch_proof.proofs) != n:
        return False
    if len(batch_proof.key_to_proof_index) != n:
        return False
    if batch_proof.key_to_proof_index != list(range(n)):
        return False
    if batch_proof.deduplicated_siblings != sorted(batch_proof.deduplicated_siblings):
        return False

    for i in range(n):
        proof = batch_proof.proofs[i]
        if proof.key != batch_proof.keys[i]:
            return False
        if proof.value != batch_proof.values[i]:
            return False
        if not verify_proof(rh, proof):
            return False
    return True
