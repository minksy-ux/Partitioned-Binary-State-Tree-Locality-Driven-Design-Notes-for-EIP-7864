"""
Property-based tests for the PBT core using Hypothesis.

Properties verified:
  - Insert-then-get identity for arbitrary keys and values
  - Root hash is independent of insertion order
  - Delete undoes insert for a single key
  - Proof verification holds for all inserted keys
  - No InternalNode with two EmptyNode children in any valid tree
  - Prefix-free key sets never collide in the tree
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
from hypothesis import given, assume, settings
from hypothesis import strategies as st

from pbt.constants import EMPTY_VALUE, STEM_SUBTREE_WIDTH
from pbt.nodes import EmptyNode, InternalNode, StemNode, Node
from pbt.tree import (
    insert,
    get,
    delete,
    root_hash,
    get_proof,
    verify_proof,
    split_key,
)


# ---------------------------------------------------------------------------
# Strategies
# ---------------------------------------------------------------------------

@st.composite
def pbt_key(draw) -> bytes:
    """
    Draw a valid PBT key: at least 2 bytes so split_key has a stem and subindex.
    Use small stems (1-4 bytes) to get interesting tree shapes quickly.
    """
    storage_type = draw(st.integers(min_value=0, max_value=2))
    position_len = draw(st.integers(min_value=1, max_value=4))
    position = draw(st.binary(min_size=position_len, max_size=position_len))
    subindex = draw(st.integers(min_value=0, max_value=255))
    return bytes([storage_type]) + position + bytes([subindex])


@st.composite
def pbt_value(draw) -> bytes:
    """Draw a 32-byte value that is never EMPTY_VALUE."""
    v = draw(st.binary(min_size=32, max_size=32))
    assume(v != EMPTY_VALUE)
    return v


@st.composite
def key_value_list(draw, min_size=1, max_size=12):
    """Draw a list of (key, value) pairs with distinct keys."""
    keys = draw(
        st.lists(pbt_key(), min_size=min_size, max_size=max_size, unique=True)
    )
    values = draw(st.lists(pbt_value(), min_size=len(keys), max_size=len(keys)))
    return list(zip(keys, values))


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def build_tree(kvs):
    root = EmptyNode()
    for k, v in kvs:
        root = insert(root, k, v)
    return root


def _assert_canonical(node: Node) -> None:
    """Recursively assert that no InternalNode has two EmptyNode children."""
    if isinstance(node, InternalNode):
        assert not (
            isinstance(node.left, EmptyNode) and isinstance(node.right, EmptyNode)
        ), "InternalNode with two EmptyNode children found (non-canonical tree)"
        _assert_canonical(node.left)
        _assert_canonical(node.right)


# ---------------------------------------------------------------------------
# Properties
# ---------------------------------------------------------------------------

@given(kvs=key_value_list())
def test_insert_get_identity(kvs):
    """Every inserted key-value must be retrievable from the tree."""
    root = build_tree(kvs)
    for k, v in kvs:
        assert get(root, k) == v, f"get({k.hex()}) returned wrong value"


@given(kvs=key_value_list(min_size=2, max_size=10))
def test_root_hash_order_independent(kvs):
    """Inserting the same keys in reverse order must give the same root hash."""
    root_forward = build_tree(kvs)
    root_backward = build_tree(list(reversed(kvs)))
    assert root_hash(root_forward) == root_hash(root_backward)


@given(kvs=key_value_list(), extra=pbt_key().flatmap(lambda k: st.tuples(st.just(k), pbt_value())))
def test_absent_key_returns_empty(kvs, extra):
    """A key not in the tree must return EMPTY_VALUE."""
    extra_key, _ = extra
    # Only test if extra_key is not already in kvs.
    assume(extra_key not in [k for k, _ in kvs])
    root = build_tree(kvs)
    assert get(root, extra_key) == EMPTY_VALUE


@given(kvs=key_value_list(min_size=2))
def test_delete_one_key_leaves_others_intact(kvs):
    """Deleting the first key must not affect any other key."""
    root = build_tree(kvs)
    key_to_delete, _ = kvs[0]
    root = delete(root, key_to_delete)
    assert get(root, key_to_delete) == EMPTY_VALUE
    for k, v in kvs[1:]:
        assert get(root, k) == v, f"Deleting {key_to_delete.hex()} broke {k.hex()}"


@given(k=pbt_key(), v=pbt_value())
def test_delete_single_insert(k, v):
    """Inserting then deleting a single key should return an EmptyNode."""
    root = insert(EmptyNode(), k, v)
    root = delete(root, k)
    assert isinstance(root, EmptyNode)


@given(kvs=key_value_list())
def test_proof_verifies_for_all_inserted_keys(kvs):
    """get_proof / verify_proof must succeed for every inserted key."""
    root = build_tree(kvs)
    rh = root_hash(root)
    for k, v in kvs:
        proof = get_proof(root, k)
        assert proof.value == v
        assert verify_proof(rh, proof), f"Proof failed for key {k.hex()}"


@given(kvs=key_value_list())
def test_tree_is_always_canonical(kvs):
    """After any sequence of inserts the tree must be canonical."""
    root = build_tree(kvs)
    _assert_canonical(root)


@given(kvs=key_value_list(min_size=2))
def test_tree_canonical_after_deletes(kvs):
    """After deleting half the keys the tree must still be canonical."""
    root = build_tree(kvs)
    for k, _ in kvs[: len(kvs) // 2]:
        root = delete(root, k)
    _assert_canonical(root)


@given(kvs=key_value_list())
def test_root_hash_changes_on_every_new_insert(kvs):
    """Each new key inserted must change the root hash."""
    root = EmptyNode()
    seen_hashes = {root_hash(root)}
    for k, v in kvs:
        root = insert(root, k, v)
        h = root_hash(root)
        assert h not in seen_hashes, (
            f"Root hash collision after inserting {k.hex()}"
        )
        seen_hashes.add(h)


@given(kvs=key_value_list(min_size=1))
def test_update_changes_root_hash(kvs):
    """Updating an existing leaf must change the root hash."""
    root = build_tree(kvs)
    k, old_v = kvs[0]
    new_v = bytes(b ^ 0xFF for b in old_v)  # flip all bits
    h_before = root_hash(root)
    root = insert(root, k, new_v)
    h_after = root_hash(root)
    assert h_before != h_after
    assert get(root, k) == new_v


@given(kvs=key_value_list())
def test_proof_for_absent_key_verifies(kvs):
    """Absence proofs must also verify correctly."""
    root = build_tree(kvs)
    rh = root_hash(root)
    # Construct an absent key by flipping the last byte of the first key.
    first_key = kvs[0][0]
    absent_key = first_key[:-1] + bytes([(first_key[-1] + 1) % 256])
    if absent_key in [k for k, _ in kvs]:
        return  # skip if by chance it's present
    proof = get_proof(root, absent_key)
    assert proof.value == EMPTY_VALUE
    assert verify_proof(rh, proof)
