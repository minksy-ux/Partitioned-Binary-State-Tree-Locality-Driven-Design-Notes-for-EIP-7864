"""
Hash function abstraction for the Partitioned Binary Tree.

The tree is hash-agnostic: any 32-byte-output, collision-resistant hash can
be plugged in.  BLAKE3 is used as the default for implementation convenience.
Keccak-256 and Poseidon2 remain candidates for the final EIP.

Usage:
    from pbt.hash import tree_hash, set_hash_function
    set_hash_function(keccak_hash)   # switch to Keccak-256
"""

from __future__ import annotations

import hashlib
from typing import Callable, Optional

# Type alias: a hash function takes bytes and returns exactly 32 bytes.
HashFunction = Callable[[bytes], bytes]


def _blake3_hash(data: bytes) -> bytes:
    try:
        import blake3  # type: ignore
        return blake3.blake3(data).digest()
    except ImportError:
        # Fall back to SHA-256 if blake3 is not installed so the module
        # remains importable in environments without the native extension.
        return hashlib.sha256(data).digest()


def _keccak_hash(data: bytes) -> bytes:
    from hashlib import sha3_256
    # hashlib ships sha3_256 which is Keccak-derived; for exact Ethereum
    # Keccak-256 install pysha3 and use sha3.keccak_256 instead.
    return hashlib.sha3_256(data).digest()


# Module-level active hash function.  Defaults to BLAKE3.
_active_hash: HashFunction = _blake3_hash


def set_hash_function(fn: HashFunction) -> None:
    """Replace the active hash function used by the tree."""
    global _active_hash
    # Sanity check: the function must return exactly 32 bytes.
    probe = fn(b"probe")
    if len(probe) != 32:
        raise ValueError(f"Hash function must return 32 bytes, got {len(probe)}")
    _active_hash = fn


def tree_hash(data: bytes) -> bytes:
    """Hash data using the currently active hash function."""
    result = _active_hash(data)
    assert len(result) == 32
    return result


# Expose the built-in variants so callers can switch to them by name.
blake3_hash = _blake3_hash
keccak_hash = _keccak_hash
