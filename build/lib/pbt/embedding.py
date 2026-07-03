"""
Ethereum-specific key derivation and leaf encoding for the PBT.

This module is the only place that knows about Ethereum account structure.
The core tree (pbt/tree.py) is Ethereum-agnostic.

Key derivation functions match the EIP specification exactly.
"""

from __future__ import annotations

import hashlib
import struct
from typing import NamedTuple

from .constants import (
    HEADER_SUBTREE,
    CODE_SUBTREE,
    STORAGE_SUBTREE,
    BASIC_DATA_LEAF_KEY,
    CODE_HASH_LEAF_KEY,
    HEADER_STORAGE_OFFSET,
    CODE_OFFSET,
    CODE_CHUNKS_IN_HEADER,
    STORAGE_CHUNKS_IN_HEADER,
    STEM_SUBTREE_WIDTH,
    EMPTY_VALUE,
)
from .hash import tree_hash

# An Ethereum address in 32-byte (zero-padded) form.
Address32 = bytes


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _h(data: bytes) -> bytes:
    """Hash `data` to 32 bytes using the active tree hash function."""
    return tree_hash(data)


def int_to_bytes32(n: int) -> bytes:
    """Encode a non-negative integer as a 32-byte big-endian byte string."""
    if n < 0:
        raise ValueError(f"int_to_bytes32 requires a non-negative integer, got {n}")
    return n.to_bytes(32, "big")


# ---------------------------------------------------------------------------
# Primitive key constructor (normative)
# ---------------------------------------------------------------------------

def get_tree_key(storage_type: int, tree_position: bytes, subindex: int) -> bytes:
    """
    Construct a PBT key from its three components.

    storage_type  : 0–255, identifies the partition
    tree_position : prefix-free byte string identifying account or page
    subindex      : 0–255, selects a leaf within the stem
    """
    if not (0 <= storage_type <= 255):
        raise ValueError(f"storage_type must be 0–255, got {storage_type}")
    if not (0 <= subindex < STEM_SUBTREE_WIDTH):
        raise ValueError(f"subindex must be 0–{STEM_SUBTREE_WIDTH - 1}, got {subindex}")
    return bytes([storage_type]) + tree_position + bytes([subindex])


# ---------------------------------------------------------------------------
# Account header keys
# ---------------------------------------------------------------------------

def get_tree_key_for_basic_data(address: Address32) -> bytes:
    """Key for the BASIC_DATA leaf (version, balance, nonce, code_size)."""
    return get_tree_key(HEADER_SUBTREE, _h(address), BASIC_DATA_LEAF_KEY)


def get_tree_key_for_code_hash(address: Address32) -> bytes:
    """Key for the CODE_HASH leaf."""
    return get_tree_key(HEADER_SUBTREE, _h(address), CODE_HASH_LEAF_KEY)


# ---------------------------------------------------------------------------
# Code keys
# ---------------------------------------------------------------------------

def get_tree_key_for_code_chunk(address: Address32, chunk_id: int) -> bytes:
    """
    Key for code chunk `chunk_id` of the contract at `address`.

    The first CODE_CHUNKS_IN_HEADER chunks are co-located in the header stem.
    Later chunks are stored in the CODE_SUBTREE, one stem per 256 chunks.
    """
    if chunk_id < 0:
        raise ValueError(f"chunk_id must be non-negative, got {chunk_id}")
    if chunk_id < CODE_CHUNKS_IN_HEADER:
        return get_tree_key(HEADER_SUBTREE, _h(address), CODE_OFFSET + chunk_id)
    overflow = chunk_id - CODE_CHUNKS_IN_HEADER
    high = overflow // STEM_SUBTREE_WIDTH
    low = overflow % STEM_SUBTREE_WIDTH
    return get_tree_key(CODE_SUBTREE, _h(address + int_to_bytes32(high)), low)


def page_index_for_code(chunk_id: int) -> int:
    """
    Return the stem page index for `chunk_id`.

    Page 0 is the header stem; pages 1+ are overflow code stems.
    """
    if chunk_id < 0:
        raise ValueError(f"chunk_id must be non-negative, got {chunk_id}")
    if chunk_id < CODE_CHUNKS_IN_HEADER:
        return 0
    return 1 + (chunk_id - CODE_CHUNKS_IN_HEADER) // STEM_SUBTREE_WIDTH


# ---------------------------------------------------------------------------
# Storage keys
# ---------------------------------------------------------------------------

def get_tree_key_for_storage_slot(address: Address32, storage_key: int) -> bytes:
    """
    Key for storage slot `storage_key` of the contract at `address`.

    The first STORAGE_CHUNKS_IN_HEADER slots are co-located in the header stem.
    Later slots are stored in the STORAGE_SUBTREE using the double-hash
    construction to prevent adversarial alignment.
    """
    if storage_key < 0:
        raise ValueError(f"storage_key must be non-negative, got {storage_key}")
    if storage_key < STORAGE_CHUNKS_IN_HEADER:
        return get_tree_key(
            HEADER_SUBTREE, _h(address), HEADER_STORAGE_OFFSET + storage_key
        )
    overflow = storage_key - STORAGE_CHUNKS_IN_HEADER
    high = overflow // STEM_SUBTREE_WIDTH
    low = overflow % STEM_SUBTREE_WIDTH
    tree_position = _h(address) + _h(address + int_to_bytes32(high))
    return get_tree_key(STORAGE_SUBTREE, tree_position, low)


def page_index_for_storage(storage_key: int) -> int:
    """
    Return the stem page index for `storage_key`.

    Page 0 is the header stem; pages 1+ are overflow storage stems.
    """
    if storage_key < 0:
        raise ValueError(f"storage_key must be non-negative, got {storage_key}")
    if storage_key < STORAGE_CHUNKS_IN_HEADER:
        return 0
    return 1 + (storage_key - STORAGE_CHUNKS_IN_HEADER) // STEM_SUBTREE_WIDTH


# ---------------------------------------------------------------------------
# Leaf value encodings
# ---------------------------------------------------------------------------

def encode_basic_data(
    version: int,
    balance: int,
    nonce: int,
    code_size: int,
) -> bytes:
    """
    Encode the BASIC_DATA leaf value as exactly 32 bytes, big-endian:

      bytes  0– 3 : version   (uint32)
      bytes  4–11 : balance   (uint64)
      bytes 12–19 : nonce     (uint64)
      bytes 20–31 : code_size (uint96)
    """
    if not (0 <= version < 2**32):
        raise ValueError(f"version out of range: {version}")
    if not (0 <= balance < 2**64):
        raise ValueError(f"balance out of range: {balance}")
    if not (0 <= nonce < 2**64):
        raise ValueError(f"nonce out of range: {nonce}")
    if not (0 <= code_size < 2**96):
        raise ValueError(f"code_size out of range: {code_size}")
    buf = (
        version.to_bytes(4, "big")
        + balance.to_bytes(8, "big")
        + nonce.to_bytes(8, "big")
        + code_size.to_bytes(12, "big")
    )
    assert len(buf) == 32
    return buf


class BasicData(NamedTuple):
    version: int
    balance: int
    nonce: int
    code_size: int


def decode_basic_data(leaf: bytes) -> BasicData:
    """Decode a BASIC_DATA leaf value into its constituent fields."""
    if len(leaf) != 32:
        raise ValueError(f"BASIC_DATA leaf must be 32 bytes, got {len(leaf)}")
    version = int.from_bytes(leaf[0:4], "big")
    balance = int.from_bytes(leaf[4:12], "big")
    nonce = int.from_bytes(leaf[12:20], "big")
    code_size = int.from_bytes(leaf[20:32], "big")
    return BasicData(version=version, balance=balance, nonce=nonce, code_size=code_size)


def encode_code_chunk(pushdata_offset: int, code_slice: bytes) -> bytes:
    """
    Encode one 31-byte code chunk as a 32-byte leaf value:

      byte   0     : pushdata_offset (0–31)
      bytes  1–31  : code_slice (zero-padded to 31 bytes)
    """
    if not (0 <= pushdata_offset <= 31):
        raise ValueError(f"pushdata_offset must be 0–31, got {pushdata_offset}")
    if len(code_slice) > 31:
        raise ValueError(f"code_slice must be at most 31 bytes, got {len(code_slice)}")
    padded = code_slice.ljust(31, b"\x00")
    return bytes([pushdata_offset]) + padded


def chunk_code(bytecode: bytes) -> list[bytes]:
    """
    Split `bytecode` into 32-byte leaf values ready for tree insertion.

    Correctly tracks PUSH data boundaries so that `pushdata_offset` in each
    chunk records how many leading bytes of that chunk are PUSH operand data
    carried over from the previous chunk.
    """
    CHUNK_SIZE = 31
    chunks: list[bytes] = []

    # EVM PUSH opcodes: PUSH1 = 0x60 … PUSH32 = 0x7f
    PUSH1 = 0x60
    PUSH32 = 0x7f

    i = 0
    pushdata_remaining = 0  # bytes of current PUSH operand not yet consumed

    # We need to track pushdata_offset per chunk, so iterate over chunks.
    for chunk_start in range(0, len(bytecode), CHUNK_SIZE):
        raw = bytecode[chunk_start: chunk_start + CHUNK_SIZE]

        # pushdata_offset for this chunk = how many of its leading bytes
        # are operand data from a PUSH that started in a previous chunk.
        pushdata_offset = min(pushdata_remaining, len(raw))

        # Advance through the chunk, updating pushdata_remaining.
        for j, byte in enumerate(raw):
            if pushdata_remaining > 0:
                pushdata_remaining -= 1
            elif PUSH1 <= byte <= PUSH32:
                pushdata_remaining = byte - PUSH1 + 1

        chunks.append(encode_code_chunk(pushdata_offset, raw))

    return chunks
