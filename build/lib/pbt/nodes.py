"""
Node types for the Partitioned Binary Tree.

Three types exist and no others:
  EmptyNode    — explicit sentinel for an absent subtree
  InternalNode — binary branch; caches its subtree hash
  StemNode     — holds stem_prefix and values[STEM_SUBTREE_WIDTH]
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Optional

from .constants import EMPTY_VALUE, STEM_SUBTREE_WIDTH

if TYPE_CHECKING:
    pass

STEM_HASH_DOMAIN = b"PBT:STEM:v1"

# Sentinel bytes used as the hash of an EmptyNode.
# Defined as tree_hash(b"") but imported lazily to avoid circular imports.
_EMPTY_HASH_CACHE: Optional[bytes] = None


def _empty_hash() -> bytes:
    global _EMPTY_HASH_CACHE
    if _EMPTY_HASH_CACHE is None:
        from .hash import tree_hash
        _EMPTY_HASH_CACHE = tree_hash(b"")
    return _EMPTY_HASH_CACHE


class Node:
    """Abstract base for all PBT node types."""

    def node_hash(self) -> bytes:
        raise NotImplementedError


@dataclass
class EmptyNode(Node):
    """
    Explicit sentinel for an absent subtree.

    MUST NOT be replaced by None anywhere in the implementation.
    """

    def node_hash(self) -> bytes:
        return _empty_hash()

    def __repr__(self) -> str:
        return "EmptyNode()"


@dataclass
class InternalNode(Node):
    """
    Binary branch node.

    Carries a cached subtree hash that is invalidated on every structural
    change.  Callers MUST call invalidate() after modifying children and
    recompute the hash before publishing the root.
    """

    left: Node = field(default_factory=EmptyNode)
    right: Node = field(default_factory=EmptyNode)
    _hash_cache: Optional[bytes] = field(default=None, repr=False, compare=False)

    def invalidate(self) -> None:
        self._hash_cache = None

    def node_hash(self) -> bytes:
        if self._hash_cache is None:
            from .hash import tree_hash
            self._hash_cache = tree_hash(
                self.left.node_hash() + self.right.node_hash()
            )
        return self._hash_cache

    def __repr__(self) -> str:
        return f"InternalNode(left={self.left!r}, right={self.right!r})"


@dataclass
class StemNode(Node):
    """
    Holds a stem_prefix and exactly STEM_SUBTREE_WIDTH (256) leaf values.

    stem_prefix is bytes([storage_type]) + tree_position.
    values[i] is a 32-byte leaf; unset slots contain EMPTY_VALUE.
    """

    stem_prefix: bytes = b""
    values: list[bytes] = field(default_factory=lambda: [EMPTY_VALUE] * STEM_SUBTREE_WIDTH)
    _hash_cache: Optional[bytes] = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        if len(self.values) != STEM_SUBTREE_WIDTH:
            raise ValueError(
                f"StemNode.values must have exactly {STEM_SUBTREE_WIDTH} entries, "
                f"got {len(self.values)}"
            )
        for v in self.values:
            if len(v) != 32:
                raise ValueError("Every leaf value must be exactly 32 bytes")

    def invalidate(self) -> None:
        self._hash_cache = None

    def node_hash(self) -> bytes:
        if self._hash_cache is None:
            from .hash import tree_hash
            payload = STEM_HASH_DOMAIN + self.stem_prefix + b"".join(self.values)
            self._hash_cache = tree_hash(payload)
        return self._hash_cache

    def is_empty(self) -> bool:
        return all(v == EMPTY_VALUE for v in self.values)

    def __repr__(self) -> str:
        non_empty = sum(1 for v in self.values if v != EMPTY_VALUE)
        return (
            f"StemNode(prefix={self.stem_prefix.hex()}, "
            f"non_empty_leaves={non_empty})"
        )
