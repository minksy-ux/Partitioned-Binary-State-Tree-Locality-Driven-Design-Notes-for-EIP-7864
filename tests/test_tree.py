"""
Tests for the core PBT tree operations.

Covers:
  - empty tree invariant
  - single insert / get round-trip
  - multi-insert with stem sharing
  - stem splitting into InternalNodes
  - canonical collapse on delete
  - proof generation and verification
  - tampered-proof rejection
  - root hash determinism
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
from pbt.constants import EMPTY_VALUE, STEM_SUBTREE_WIDTH
from pbt.nodes import EmptyNode, InternalNode, StemNode
from pbt.tree import (
    insert,
    get,
    delete,
    root_hash,
    get_proof,
    verify_proof,
    get_multi_proof,
    verify_multi_proof,
    BatchMerkleProof,
    split_key,
    _bit_at,
    MerkleProof,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _val(n: int) -> bytes:
    """Make a deterministic 32-byte value from an integer."""
    return n.to_bytes(32, "big")


def _key(storage_type: int, position: bytes, subindex: int) -> bytes:
    return bytes([storage_type]) + position + bytes([subindex])


ZERO_ADDR = bytes(32)
ADDR_A = bytes([0xAA] * 32)
ADDR_B = bytes([0xBB] * 32)


# ---------------------------------------------------------------------------
# Bit helper
# ---------------------------------------------------------------------------

def test_bit_at_basic():
    data = bytes([0b10110000])
    assert _bit_at(data, 0) == 1
    assert _bit_at(data, 1) == 0
    assert _bit_at(data, 2) == 1
    assert _bit_at(data, 3) == 1
    assert _bit_at(data, 4) == 0


def test_bit_at_out_of_range():
    assert _bit_at(b"\xff", 8) == 0
    assert _bit_at(b"", 0) == 0


# ---------------------------------------------------------------------------
# Empty tree
# ---------------------------------------------------------------------------

def test_empty_tree_hash_is_deterministic():
    h1 = root_hash(EmptyNode())
    h2 = root_hash(EmptyNode())
    assert h1 == h2
    assert len(h1) == 32


def test_get_from_empty_tree():
    key = _key(0, ZERO_ADDR, 0)
    assert get(EmptyNode(), key) == EMPTY_VALUE


# ---------------------------------------------------------------------------
# Single insert / get
# ---------------------------------------------------------------------------

def test_single_insert_returns_stem_node():
    key = _key(0, ZERO_ADDR, 0)
    value = _val(42)
    root = insert(EmptyNode(), key, value)
    assert isinstance(root, StemNode)
    assert root.values[0] == value


def test_single_insert_get_round_trip():
    key = _key(0, ZERO_ADDR, 7)
    value = _val(99)
    root = insert(EmptyNode(), key, value)
    assert get(root, key) == value


def test_get_absent_key_returns_empty():
    key = _key(0, ZERO_ADDR, 0)
    absent = _key(0, ZERO_ADDR, 1)
    root = insert(EmptyNode(), key, _val(1))
    assert get(root, absent) == EMPTY_VALUE


def test_insert_rejects_wrong_value_length():
    key = _key(0, ZERO_ADDR, 0)
    with pytest.raises(ValueError):
        insert(EmptyNode(), key, b"short")


# ---------------------------------------------------------------------------
# Same-stem multi-leaf insert (locality invariant)
# ---------------------------------------------------------------------------

def test_same_stem_stays_one_stem_node():
    """All leaves sharing the same (storage_type, tree_position) stay in one StemNode."""
    root = EmptyNode()
    position = ZERO_ADDR
    for subindex in range(4):
        key = _key(0, position, subindex)
        root = insert(root, key, _val(subindex))
    # Root must still be a single StemNode, not an InternalNode.
    assert isinstance(root, StemNode)
    for subindex in range(4):
        assert get(root, _key(0, position, subindex)) == _val(subindex)


def test_all_256_subindices():
    root = EmptyNode()
    position = ZERO_ADDR
    for i in range(STEM_SUBTREE_WIDTH):
        root = insert(root, _key(0, position, i), _val(i))
    assert isinstance(root, StemNode)
    for i in range(STEM_SUBTREE_WIDTH):
        assert get(root, _key(0, position, i)) == _val(i)


# ---------------------------------------------------------------------------
# Stem splitting
# ---------------------------------------------------------------------------

def test_two_different_stems_produce_internal_node():
    key_a = _key(0, ADDR_A, 0)
    key_b = _key(0, ADDR_B, 0)
    root = EmptyNode()
    root = insert(root, key_a, _val(1))
    root = insert(root, key_b, _val(2))
    assert isinstance(root, InternalNode)
    assert get(root, key_a) == _val(1)
    assert get(root, key_b) == _val(2)


def test_different_storage_types_split():
    pos = ZERO_ADDR
    key_hdr = _key(0, pos, 0)   # HEADER_SUBTREE
    key_code = _key(1, pos, 0)  # CODE_SUBTREE
    root = EmptyNode()
    root = insert(root, key_hdr, _val(10))
    root = insert(root, key_code, _val(20))
    assert isinstance(root, InternalNode)
    assert get(root, key_hdr) == _val(10)
    assert get(root, key_code) == _val(20)


def test_update_existing_leaf():
    key = _key(0, ZERO_ADDR, 5)
    root = insert(EmptyNode(), key, _val(1))
    root = insert(root, key, _val(2))
    assert get(root, key) == _val(2)


# ---------------------------------------------------------------------------
# Delete
# ---------------------------------------------------------------------------

def test_delete_single_leaf_collapses_to_empty():
    key = _key(0, ZERO_ADDR, 0)
    root = insert(EmptyNode(), key, _val(1))
    root = delete(root, key)
    assert isinstance(root, EmptyNode)


def test_delete_one_of_two_leaves_in_same_stem():
    root = EmptyNode()
    key0 = _key(0, ZERO_ADDR, 0)
    key1 = _key(0, ZERO_ADDR, 1)
    root = insert(root, key0, _val(10))
    root = insert(root, key1, _val(20))
    root = delete(root, key0)
    assert isinstance(root, StemNode)
    assert get(root, key0) == EMPTY_VALUE
    assert get(root, key1) == _val(20)


def test_delete_collapses_internal_node():
    """After deleting one of two stems, the InternalNode must be collapsed."""
    key_a = _key(0, ADDR_A, 0)
    key_b = _key(0, ADDR_B, 0)
    root = EmptyNode()
    root = insert(root, key_a, _val(1))
    root = insert(root, key_b, _val(2))
    assert isinstance(root, InternalNode)
    root = delete(root, key_a)
    # Must collapse to the surviving StemNode, not remain an InternalNode.
    assert isinstance(root, StemNode)
    assert get(root, key_b) == _val(2)


def test_delete_absent_key_is_noop():
    key = _key(0, ZERO_ADDR, 0)
    absent = _key(0, ADDR_A, 0)
    root = insert(EmptyNode(), key, _val(1))
    root2 = delete(root, absent)
    assert root_hash(root) == root_hash(root2)


# ---------------------------------------------------------------------------
# Root hash determinism
# ---------------------------------------------------------------------------

def test_root_hash_order_independent():
    """Inserting the same keys in different orders must give the same root hash."""
    keys_values = [
        (_key(0, ADDR_A, i), _val(i)) for i in range(8)
    ] + [
        (_key(0, ADDR_B, i), _val(i + 100)) for i in range(8)
    ]

    root1 = EmptyNode()
    for k, v in keys_values:
        root1 = insert(root1, k, v)

    root2 = EmptyNode()
    for k, v in reversed(keys_values):
        root2 = insert(root2, k, v)

    assert root_hash(root1) == root_hash(root2)


def test_root_hash_changes_after_insert():
    key = _key(0, ZERO_ADDR, 0)
    root = EmptyNode()
    h0 = root_hash(root)
    root = insert(root, key, _val(1))
    assert root_hash(root) != h0


def test_root_hash_changes_after_delete():
    key = _key(0, ZERO_ADDR, 0)
    root = insert(EmptyNode(), key, _val(1))
    h1 = root_hash(root)
    root = delete(root, key)
    assert root_hash(root) != h1


# ---------------------------------------------------------------------------
# Proof generation and verification
# ---------------------------------------------------------------------------

def _build_tree() -> tuple[StemNode | InternalNode, list[tuple[bytes, bytes]]]:
    kvs = [
        (_key(0, ADDR_A, i), _val(i)) for i in range(4)
    ] + [
        (_key(0, ADDR_B, i), _val(i + 50)) for i in range(4)
    ] + [
        (_key(1, ZERO_ADDR, i), _val(i + 100)) for i in range(4)
    ]
    root = EmptyNode()
    for k, v in kvs:
        root = insert(root, k, v)
    return root, kvs


def test_proof_verifies_present_key():
    root, kvs = _build_tree()
    rh = root_hash(root)
    for key, value in kvs:
        proof = get_proof(root, key)
        assert proof.value == value
        assert verify_proof(rh, proof)


def test_proof_verifies_absent_key():
    root, _ = _build_tree()
    rh = root_hash(root)
    # Use a subindex that was never inserted but whose stem_prefix exists in the tree.
    # ADDR_A was inserted for subindices 0-3; subindex 100 is absent.
    absent_key = _key(0, ADDR_A, 100)
    proof = get_proof(root, absent_key)
    assert proof.value == EMPTY_VALUE
    assert verify_proof(rh, proof)


def test_tampered_value_fails_verification():
    root, kvs = _build_tree()
    rh = root_hash(root)
    key, _ = kvs[0]
    proof = get_proof(root, key)
    tampered = MerkleProof(
        key=proof.key,
        value=_val(9999),
        stem_values=proof.stem_values,
        path_siblings=proof.path_siblings,
        path_bits=proof.path_bits,
    )
    assert not verify_proof(rh, tampered)


def test_tampered_sibling_fails_verification():
    root, kvs = _build_tree()
    rh = root_hash(root)
    key, _ = kvs[0]
    proof = get_proof(root, key)
    if not proof.path_siblings:
        pytest.skip("single-stem tree has no siblings to tamper")
    bad_siblings = [bytes(32)] + list(proof.path_siblings[1:])
    tampered = MerkleProof(
        key=proof.key,
        value=proof.value,
        stem_values=proof.stem_values,
        path_siblings=bad_siblings,
        path_bits=proof.path_bits,
    )
    assert not verify_proof(rh, tampered)


def test_multi_proof_round_trip_for_mixed_keys():
    root, kvs = _build_tree()
    rh = root_hash(root)
    keys = [kvs[0][0], kvs[3][0], kvs[-1][0], _key(0, ADDR_A, 99)]
    batch = get_multi_proof(root, keys)

    assert verify_multi_proof(rh, batch)
    assert batch.keys == sorted(set(keys))


def test_multi_proof_rejects_non_canonical_ordering():
    root, kvs = _build_tree()
    rh = root_hash(root)
    keys = [kvs[0][0], kvs[1][0], kvs[2][0]]
    batch = get_multi_proof(root, keys)

    bad = BatchMerkleProof(
        keys=list(reversed(batch.keys)),
        values=list(reversed(batch.values)),
        proofs=list(reversed(batch.proofs)),
        deduplicated_siblings=batch.deduplicated_siblings,
        key_to_proof_index=batch.key_to_proof_index,
    )
    assert not verify_multi_proof(rh, bad)


def test_multi_proof_rejects_tampered_value_alignment():
    root, kvs = _build_tree()
    rh = root_hash(root)
    keys = [kvs[0][0], kvs[1][0]]
    batch = get_multi_proof(root, keys)

    tampered_values = list(batch.values)
    tampered_values[0] = _val(123456)
    bad = BatchMerkleProof(
        keys=batch.keys,
        values=tampered_values,
        proofs=batch.proofs,
        deduplicated_siblings=batch.deduplicated_siblings,
        key_to_proof_index=batch.key_to_proof_index,
    )
    assert not verify_multi_proof(rh, bad)


def test_wrong_root_fails_verification():
    root, kvs = _build_tree()
    key, _ = kvs[0]
    proof = get_proof(root, key)
    wrong_root = bytes(32)
    assert not verify_proof(wrong_root, proof)


# ---------------------------------------------------------------------------
# Canonicality: no redundant InternalNodes
# ---------------------------------------------------------------------------

def _count_internal(node: object) -> int:
    if isinstance(node, InternalNode):
        return 1 + _count_internal(node.left) + _count_internal(node.right)
    return 0


def test_no_redundant_internal_nodes_after_delete():
    """After deleting all stems but one, the tree must collapse to a StemNode."""
    root = EmptyNode()
    keys = [_key(0, bytes([i] * 32), 0) for i in range(4)]
    for k in keys:
        root = insert(root, k, _val(1))
    assert isinstance(root, InternalNode)
    # Delete ALL keys.
    for k in keys:
        root = delete(root, k)
    # The root must collapse to EmptyNode after all stems are removed.
    assert isinstance(root, EmptyNode)
