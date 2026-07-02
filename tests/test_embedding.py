"""
Tests for the Ethereum-specific embedding layer (pbt/embedding.py).

Covers:
  - key derivation for header, code, and storage
  - BASIC_DATA encode/decode round-trip
  - code-chunk encoding and PUSH-data boundary tracking
  - locality invariants (same-stem for hot state)
  - anti-DoS property (different contracts → different tree_positions)
  - page index helpers
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest

from pbt.constants import (
    HEADER_SUBTREE,
    CODE_SUBTREE,
    STORAGE_SUBTREE,
    BASIC_DATA_LEAF_KEY,
    CODE_HASH_LEAF_KEY,
    CODE_OFFSET,
    HEADER_STORAGE_OFFSET,
    CODE_CHUNKS_IN_HEADER,
    STORAGE_CHUNKS_IN_HEADER,
    STEM_SUBTREE_WIDTH,
    EMPTY_VALUE,
)
from pbt.embedding import (
    get_tree_key,
    get_tree_key_for_basic_data,
    get_tree_key_for_code_hash,
    get_tree_key_for_code_chunk,
    get_tree_key_for_storage_slot,
    encode_basic_data,
    decode_basic_data,
    encode_code_chunk,
    chunk_code,
    page_index_for_code,
    page_index_for_storage,
    int_to_bytes32,
)
from pbt.nodes import EmptyNode, StemNode, InternalNode
from pbt.tree import insert, get

ADDR_A = bytes([0xAA] * 32)
ADDR_B = bytes([0xBB] * 32)
ZERO_ADDR = bytes(32)

# ---------------------------------------------------------------------------
# get_tree_key validation
# ---------------------------------------------------------------------------

def test_get_tree_key_structure():
    storage_type = 0
    position = b"\x01" * 32
    subindex = 5
    key = get_tree_key(storage_type, position, subindex)
    assert key[0] == storage_type
    assert key[1:-1] == position
    assert key[-1] == subindex


def test_get_tree_key_rejects_invalid_storage_type():
    with pytest.raises(ValueError):
        get_tree_key(256, b"\x00" * 32, 0)
    with pytest.raises(ValueError):
        get_tree_key(-1, b"\x00" * 32, 0)


def test_get_tree_key_rejects_invalid_subindex():
    with pytest.raises(ValueError):
        get_tree_key(0, b"\x00" * 32, 256)
    with pytest.raises(ValueError):
        get_tree_key(0, b"\x00" * 32, -1)


# ---------------------------------------------------------------------------
# Account header keys
# ---------------------------------------------------------------------------

def test_basic_data_key_uses_header_subtree():
    key = get_tree_key_for_basic_data(ADDR_A)
    assert key[0] == HEADER_SUBTREE
    assert key[-1] == BASIC_DATA_LEAF_KEY


def test_code_hash_key_uses_header_subtree():
    key = get_tree_key_for_code_hash(ADDR_A)
    assert key[0] == HEADER_SUBTREE
    assert key[-1] == CODE_HASH_LEAF_KEY


def test_basic_data_and_code_hash_share_stem():
    """Both header keys must have the same (storage_type, tree_position)."""
    key_bd = get_tree_key_for_basic_data(ADDR_A)
    key_ch = get_tree_key_for_code_hash(ADDR_A)
    assert key_bd[:-1] == key_ch[:-1]  # same stem prefix


def test_different_addresses_different_stems():
    key_a = get_tree_key_for_basic_data(ADDR_A)
    key_b = get_tree_key_for_basic_data(ADDR_B)
    assert key_a[:-1] != key_b[:-1]


# ---------------------------------------------------------------------------
# Code chunk keys
# ---------------------------------------------------------------------------

def test_first_code_chunks_in_header_stem():
    for chunk_id in range(CODE_CHUNKS_IN_HEADER):
        key = get_tree_key_for_code_chunk(ADDR_A, chunk_id)
        assert key[0] == HEADER_SUBTREE
        assert key[-1] == CODE_OFFSET + chunk_id


def test_first_code_chunk_shares_header_stem():
    key_bd = get_tree_key_for_basic_data(ADDR_A)
    key_c0 = get_tree_key_for_code_chunk(ADDR_A, 0)
    assert key_bd[:-1] == key_c0[:-1]


def test_overflow_code_chunk_uses_code_subtree():
    key = get_tree_key_for_code_chunk(ADDR_A, CODE_CHUNKS_IN_HEADER)
    assert key[0] == CODE_SUBTREE


def test_code_chunk_page_boundary():
    """Chunk at index CODE_CHUNKS_IN_HEADER + STEM_SUBTREE_WIDTH starts a new page."""
    key0 = get_tree_key_for_code_chunk(ADDR_A, CODE_CHUNKS_IN_HEADER)
    key1 = get_tree_key_for_code_chunk(ADDR_A, CODE_CHUNKS_IN_HEADER + STEM_SUBTREE_WIDTH)
    # Different stems (tree_position differs).
    assert key0[:-1] != key1[:-1]


def test_code_chunks_within_same_overflow_page_share_stem():
    base = CODE_CHUNKS_IN_HEADER
    key0 = get_tree_key_for_code_chunk(ADDR_A, base)
    key1 = get_tree_key_for_code_chunk(ADDR_A, base + STEM_SUBTREE_WIDTH - 1)
    assert key0[:-1] == key1[:-1]


# ---------------------------------------------------------------------------
# Storage slot keys
# ---------------------------------------------------------------------------

def test_first_storage_slots_in_header_stem():
    for slot in range(STORAGE_CHUNKS_IN_HEADER):
        key = get_tree_key_for_storage_slot(ADDR_A, slot)
        assert key[0] == HEADER_SUBTREE
        assert key[-1] == HEADER_STORAGE_OFFSET + slot


def test_first_storage_slot_shares_header_stem():
    key_bd = get_tree_key_for_basic_data(ADDR_A)
    key_s0 = get_tree_key_for_storage_slot(ADDR_A, 0)
    assert key_bd[:-1] == key_s0[:-1]


def test_overflow_storage_uses_storage_subtree():
    key = get_tree_key_for_storage_slot(ADDR_A, STORAGE_CHUNKS_IN_HEADER)
    assert key[0] == STORAGE_SUBTREE


def test_overflow_storage_slots_within_same_page_share_stem():
    base = STORAGE_CHUNKS_IN_HEADER
    key0 = get_tree_key_for_storage_slot(ADDR_A, base)
    key1 = get_tree_key_for_storage_slot(ADDR_A, base + STEM_SUBTREE_WIDTH - 1)
    assert key0[:-1] == key1[:-1]


def test_anti_dos_different_contracts_different_storage_tree_position():
    """Two contracts must NOT share a storage tree_position for the same slot."""
    key_a = get_tree_key_for_storage_slot(ADDR_A, STORAGE_CHUNKS_IN_HEADER)
    key_b = get_tree_key_for_storage_slot(ADDR_B, STORAGE_CHUNKS_IN_HEADER)
    # tree_position = key[1:-1]
    assert key_a[1:-1] != key_b[1:-1]


# ---------------------------------------------------------------------------
# BASIC_DATA encode / decode
# ---------------------------------------------------------------------------

def test_encode_basic_data_length():
    buf = encode_basic_data(0, 1000, 5, 256)
    assert len(buf) == 32


def test_encode_decode_round_trip():
    version = 1
    balance = 10**18
    nonce = 42
    code_size = 24576
    buf = encode_basic_data(version, balance, nonce, code_size)
    decoded = decode_basic_data(buf)
    assert decoded.version == version
    assert decoded.balance == balance
    assert decoded.nonce == nonce
    assert decoded.code_size == code_size


def test_encode_zero_values():
    buf = encode_basic_data(0, 0, 0, 0)
    assert buf == bytes(32)


def test_encode_rejects_out_of_range():
    with pytest.raises(ValueError):
        encode_basic_data(2**32, 0, 0, 0)
    with pytest.raises(ValueError):
        encode_basic_data(0, 2**64, 0, 0)
    with pytest.raises(ValueError):
        encode_basic_data(0, 0, 2**64, 0)


# ---------------------------------------------------------------------------
# Code chunk encoding
# ---------------------------------------------------------------------------

def test_encode_code_chunk_length():
    chunk = encode_code_chunk(0, b"\x60\x01" * 15 + b"\x00")
    assert len(chunk) == 32


def test_encode_code_chunk_padding():
    raw = b"\xab\xcd"
    chunk = encode_code_chunk(0, raw)
    assert len(chunk) == 32
    assert chunk[0] == 0
    assert chunk[1:3] == raw
    assert chunk[3:] == bytes(29)


def test_encode_code_chunk_rejects_too_long():
    with pytest.raises(ValueError):
        encode_code_chunk(0, b"\x00" * 32)


def test_encode_code_chunk_rejects_bad_offset():
    with pytest.raises(ValueError):
        encode_code_chunk(32, b"\x00")


# ---------------------------------------------------------------------------
# chunk_code PUSH-data tracking
# ---------------------------------------------------------------------------

def test_chunk_code_empty():
    assert chunk_code(b"") == []


def test_chunk_code_short_code():
    code = b"\x60\x01\x60\x02\x01"  # PUSH1 1 PUSH1 2 ADD
    chunks = chunk_code(code)
    assert len(chunks) == 1
    assert chunks[0][0] == 0  # no pushdata overflow from previous chunk
    assert chunks[0][1: 1 + len(code)] == code


def test_chunk_code_push_spans_boundary():
    """A PUSH32 that starts near the end of chunk 0 should set pushdata_offset in chunk 1."""
    # Place a PUSH32 (0x7f) 2 bytes before the end of the first 31-byte chunk.
    prefix = b"\x00" * 29  # 29 bytes of NOPs
    push32 = bytes([0x7F]) + b"\xaa" * 32  # PUSH32 with 32 bytes of data
    code = prefix + push32
    chunks = chunk_code(code)
    assert len(chunks) >= 2
    # The first chunk ends with 0x7F and the first byte of operand.
    # pushdata_offset of chunk 1 should indicate the remaining operand bytes
    # that spill into chunk 1.
    assert chunks[1][0] > 0


def test_chunk_code_roundtrip_length():
    """Total bytes across all chunks reconstructs the original bytecode length."""
    code = bytes(range(256))
    chunks = chunk_code(code)
    # Each chunk holds up to 31 bytes of code (bytes 1-31 of the 32-byte leaf).
    total = sum(
        min(31, len(code) - i * 31)
        for i in range(len(chunks))
    )
    assert total == len(code)


# ---------------------------------------------------------------------------
# Page index helpers
# ---------------------------------------------------------------------------

def test_page_index_for_code_header():
    for i in range(CODE_CHUNKS_IN_HEADER):
        assert page_index_for_code(i) == 0


def test_page_index_for_code_overflow():
    assert page_index_for_code(CODE_CHUNKS_IN_HEADER) == 1
    assert page_index_for_code(CODE_CHUNKS_IN_HEADER + STEM_SUBTREE_WIDTH - 1) == 1
    assert page_index_for_code(CODE_CHUNKS_IN_HEADER + STEM_SUBTREE_WIDTH) == 2


def test_page_index_for_storage_header():
    for i in range(STORAGE_CHUNKS_IN_HEADER):
        assert page_index_for_storage(i) == 0


def test_page_index_for_storage_overflow():
    assert page_index_for_storage(STORAGE_CHUNKS_IN_HEADER) == 1
    assert page_index_for_storage(STORAGE_CHUNKS_IN_HEADER + STEM_SUBTREE_WIDTH - 1) == 1
    assert page_index_for_storage(STORAGE_CHUNKS_IN_HEADER + STEM_SUBTREE_WIDTH) == 2


# ---------------------------------------------------------------------------
# Locality integration: small contract fits in one stem
# ---------------------------------------------------------------------------

def test_small_contract_all_in_header_stem():
    """
    A contract with 16 code chunks and 4 storage slots should have
    all keys in the same header stem.
    """
    addr = ADDR_A
    stem_prefix = get_tree_key_for_basic_data(addr)[:-1]

    keys = (
        [get_tree_key_for_basic_data(addr)]
        + [get_tree_key_for_code_hash(addr)]
        + [get_tree_key_for_code_chunk(addr, i) for i in range(CODE_CHUNKS_IN_HEADER)]
        + [get_tree_key_for_storage_slot(addr, i) for i in range(STORAGE_CHUNKS_IN_HEADER)]
    )

    for key in keys:
        assert key[:-1] == stem_prefix, (
            f"Key {key.hex()} stem {key[:-1].hex()} != expected {stem_prefix.hex()}"
        )

    # Insert them all and verify a single StemNode is sufficient.
    root = EmptyNode()
    for i, key in enumerate(keys):
        root = insert(root, key, (i + 1).to_bytes(32, "big"))

    assert isinstance(root, StemNode), (
        "Small contract hot state must fit in one StemNode"
    )
