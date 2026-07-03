"""Tests for hash-function registry and hash-ID based switching."""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest

from pbt.hash import (
    available_hash_function_ids,
    get_hash_function_id,
    register_hash_function,
    set_hash_function,
    set_hash_function_by_id,
    tree_hash,
)
from pbt.nodes import EmptyNode
from pbt.tree import get_proof, insert, root_hash, verify_proof


def test_hash_registry_contains_expected_builtin_ids():
    ids = set(available_hash_function_ids())
    assert "blake3" in ids
    assert "keccak256" in ids
    assert "poseidon2" in ids


def test_switch_hash_by_id_changes_active_identifier():
    original = get_hash_function_id()
    set_hash_function_by_id("keccak256")
    assert get_hash_function_id() == "keccak256"

    set_hash_function_by_id("blake3")
    assert get_hash_function_id() == "blake3"

    # Restore caller-visible state if this test ever starts under a custom id.
    if original not in ("blake3", "keccak256"):
        set_hash_function_by_id("blake3")


def test_unknown_hash_id_rejected():
    with pytest.raises(ValueError):
        set_hash_function_by_id("does-not-exist")


def test_tree_root_and_proof_verify_under_blake3_and_keccak_modes():
    key = bytes([0]) + bytes([0x22] * 32) + bytes([7])
    value = (777).to_bytes(32, "big")

    set_hash_function_by_id("blake3")
    root_blake3 = insert(EmptyNode(), key, value)
    rh_blake3 = root_hash(root_blake3)
    proof_blake3 = get_proof(root_blake3, key)
    assert verify_proof(rh_blake3, proof_blake3)

    set_hash_function_by_id("keccak256")
    root_keccak = insert(EmptyNode(), key, value)
    rh_keccak = root_hash(root_keccak)
    proof_keccak = get_proof(root_keccak, key)
    assert verify_proof(rh_keccak, proof_keccak)

    # Same state can have different roots across hash functions.
    assert rh_blake3 != rh_keccak

    # Restore default for other tests.
    set_hash_function_by_id("blake3")


def test_poseidon2_mode_reports_missing_backend_or_returns_32_bytes():
    try:
        set_hash_function_by_id("poseidon2")
    except RuntimeError as exc:
        assert "poseidon2 hash backend not available" in str(exc)
    else:
        digest = tree_hash(b"poseidon2-probe")
        assert isinstance(digest, bytes)
        assert len(digest) == 32
    finally:
        set_hash_function_by_id("blake3")


def test_register_custom_hash_id_and_switch():
    def dummy_hash(data: bytes) -> bytes:
        # Deterministic 32-byte digest for API behavior testing.
        return b"\x5a" * 32

    register_hash_function("dummy32", dummy_hash)
    set_hash_function_by_id("dummy32")

    assert get_hash_function_id() == "dummy32"
    assert tree_hash(b"any-input") == b"\x5a" * 32

    # Restore default for other tests.
    set_hash_function_by_id("blake3")


def test_set_hash_function_marks_identifier_as_custom():
    def all_ones_hash(data: bytes) -> bytes:
        return b"\xff" * 32

    set_hash_function(all_ones_hash)
    assert get_hash_function_id() == "custom"
    assert tree_hash(b"probe") == b"\xff" * 32

    # Restore default for other tests.
    set_hash_function_by_id("blake3")
