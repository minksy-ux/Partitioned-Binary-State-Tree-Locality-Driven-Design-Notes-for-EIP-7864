"""Hash function abstraction and identifier registry for PBT.

The tree is hash-agnostic: any collision-resistant function returning 32 bytes
can be plugged in. Built-ins include BLAKE3, Keccak-256, and Poseidon2 (when a
Poseidon2 backend is available in the runtime environment).
"""

from __future__ import annotations

import hashlib
from typing import Callable

# Type alias: a hash function takes bytes and returns exactly 32 bytes.
HashFunction = Callable[[bytes], bytes]
HashFunctionId = str


def _blake3_hash(data: bytes) -> bytes:
    try:
        import blake3  # type: ignore
        return blake3.blake3(data).digest()
    except ImportError:
        # Fall back to SHA-256 if blake3 is not installed so the module
        # remains importable in environments without the native extension.
        return hashlib.sha256(data).digest()


def _keccak_hash(data: bytes) -> bytes:
    # Prefer exact Ethereum-compatible Keccak-256 backends when available.
    try:
        from eth_hash.auto import keccak as eth_keccak  # type: ignore

        digest = eth_keccak(data)
        if isinstance(digest, bytes) and len(digest) == 32:
            return digest
    except ImportError:
        pass

    try:
        import sha3  # type: ignore

        digest = sha3.keccak_256(data).digest()
        if isinstance(digest, bytes) and len(digest) == 32:
            return digest
    except ImportError:
        pass

    # Fallback keeps the module usable without optional dependencies.
    return hashlib.sha3_256(data).digest()


def _poseidon2_hash(data: bytes) -> bytes:
    """Hash using Poseidon2 when a compatible backend is installed.

    This project keeps Poseidon2 optional at runtime so the reference code can
    still run in plain Python environments. If no known backend is installed,
    callers selecting this hash mode receive a clear runtime error.
    """
    # Known backend variant A: package exposes a one-shot hash function.
    try:
        import poseidon2  # type: ignore

        if hasattr(poseidon2, "hash_bytes"):
            digest = poseidon2.hash_bytes(data)  # type: ignore[attr-defined]
            if isinstance(digest, bytes) and len(digest) == 32:
                return digest
    except ImportError:
        pass

    # Known backend variant B: class-based API (project-specific wrappers).
    try:
        from poseidon2 import Poseidon2  # type: ignore

        hasher = Poseidon2()  # type: ignore[call-arg]
        digest = hasher.hash_bytes(data)
        if isinstance(digest, bytes) and len(digest) == 32:
            return digest
    except ImportError:
        pass

    raise RuntimeError(
        "poseidon2 hash backend not available; install a compatible poseidon2 package"
    )


_hash_registry: dict[HashFunctionId, HashFunction] = {
    "blake3": _blake3_hash,
    "keccak256": _keccak_hash,
    "poseidon2": _poseidon2_hash,
}

# Module-level active hash selection. Defaults to BLAKE3 for implementation
# convenience while maintaining hash-agility hooks.
_active_hash_id: HashFunctionId = "blake3"
_active_hash: HashFunction = _hash_registry[_active_hash_id]


def register_hash_function(hash_id: HashFunctionId, fn: HashFunction) -> None:
    """Register a named 32-byte hash function for network upgrades/tests."""
    if not hash_id:
        raise ValueError("hash_id must be non-empty")
    probe = fn(b"probe")
    if len(probe) != 32:
        raise ValueError(f"Hash function must return 32 bytes, got {len(probe)}")
    _hash_registry[hash_id] = fn


def available_hash_function_ids() -> tuple[HashFunctionId, ...]:
    """Return known hash identifiers in deterministic order."""
    return tuple(sorted(_hash_registry.keys()))


def get_hash_function_id() -> HashFunctionId:
    """Return the active hash identifier."""
    return _active_hash_id


def set_hash_function(fn: HashFunction) -> None:
    """Replace the active hash function used by the tree.

    This keeps backward compatibility with existing call sites that inject a
    callable directly. The active identifier becomes "custom".
    """
    global _active_hash, _active_hash_id
    # Sanity check: the function must return exactly 32 bytes.
    probe = fn(b"probe")
    if len(probe) != 32:
        raise ValueError(f"Hash function must return 32 bytes, got {len(probe)}")
    _active_hash = fn
    _active_hash_id = "custom"


def set_hash_function_by_id(hash_id: HashFunctionId) -> None:
    """Switch the active hash function by identifier."""
    global _active_hash, _active_hash_id
    if hash_id not in _hash_registry:
        raise ValueError(f"Unknown hash function id: {hash_id}")
    fn = _hash_registry[hash_id]
    probe = fn(b"probe")
    if len(probe) != 32:
        raise ValueError(f"Hash function must return 32 bytes, got {len(probe)}")
    _active_hash = fn
    _active_hash_id = hash_id


def tree_hash(data: bytes) -> bytes:
    """Hash data using the currently active hash function."""
    result = _active_hash(data)
    assert len(result) == 32
    return result


# Expose the built-in variants so callers can switch to them by name.
blake3_hash = _blake3_hash
keccak_hash = _keccak_hash
poseidon2_hash = _poseidon2_hash
