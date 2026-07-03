"""Metadata reservation hooks for state-expiry and lifecycle classification.

This module makes the reserved metadata space explicit and machine-checkable.
It defines fixed metadata slots in the header stem and an optional dedicated
metadata partition identifier for future expansion without proof-format changes.
"""

from __future__ import annotations

from dataclasses import dataclass

from .constants import (
    HEADER_SUBTREE,
    METADATA_SUBTREE,
    METADATA_EXPIRY_EPOCH_SUBINDEX,
    METADATA_HOT_COLD_SUBINDEX,
    METADATA_ARCHIVAL_TIER_SUBINDEX,
    METADATA_FLAGS_SUBINDEX,
    STEM_SUBTREE_WIDTH,
    CODE_OFFSET,
    CODE_CHUNKS_IN_HEADER,
    HEADER_STORAGE_OFFSET,
    STORAGE_CHUNKS_IN_HEADER,
)
from .embedding import get_tree_key
from .hash import tree_hash


@dataclass(frozen=True)
class MetadataLayout:
    """Reserved metadata slot mapping for header stems."""

    expiry_epoch_subindex: int = METADATA_EXPIRY_EPOCH_SUBINDEX
    hot_cold_subindex: int = METADATA_HOT_COLD_SUBINDEX
    archival_tier_subindex: int = METADATA_ARCHIVAL_TIER_SUBINDEX
    flags_subindex: int = METADATA_FLAGS_SUBINDEX

    def all_subindices(self) -> tuple[int, int, int, int]:
        return (
            self.expiry_epoch_subindex,
            self.hot_cold_subindex,
            self.archival_tier_subindex,
            self.flags_subindex,
        )


def _occupied_header_subindices() -> set[int]:
    occupied: set[int] = {0, 1, 2, 3}
    occupied.update(range(CODE_OFFSET, CODE_OFFSET + CODE_CHUNKS_IN_HEADER))
    occupied.update(
        range(HEADER_STORAGE_OFFSET, HEADER_STORAGE_OFFSET + STORAGE_CHUNKS_IN_HEADER)
    )
    return occupied


def validate_metadata_layout(layout: MetadataLayout = MetadataLayout()) -> None:
    """Ensure metadata slots are unique, in-range, and do not overlap active ranges."""
    subindices = layout.all_subindices()
    if len(set(subindices)) != len(subindices):
        raise ValueError("metadata subindices must be unique")
    for idx in subindices:
        if not (0 <= idx < STEM_SUBTREE_WIDTH):
            raise ValueError(f"metadata subindex out of range: {idx}")

    occupied = _occupied_header_subindices()
    conflicts = [idx for idx in subindices if idx in occupied]
    if conflicts:
        raise ValueError(f"metadata subindices overlap active header ranges: {conflicts}")


@dataclass(frozen=True)
class MetadataRecord:
    """Packed metadata fields stored in reserved metadata leaves."""

    expiry_epoch: int
    is_hot: bool
    archival_tier: int
    flags: int = 0


def encode_expiry_epoch(epoch: int) -> bytes:
    if not (0 <= epoch < 2**64):
        raise ValueError(f"expiry epoch out of range: {epoch}")
    return epoch.to_bytes(32, "big")


def decode_expiry_epoch(value: bytes) -> int:
    if len(value) != 32:
        raise ValueError("expiry metadata leaf must be 32 bytes")
    return int.from_bytes(value, "big")


def encode_hot_cold(is_hot: bool) -> bytes:
    return (b"\x01" if is_hot else b"\x00") + bytes(31)


def decode_hot_cold(value: bytes) -> bool:
    if len(value) != 32:
        raise ValueError("hot/cold metadata leaf must be 32 bytes")
    return value[0] != 0


def encode_archival_tier(tier: int) -> bytes:
    if not (0 <= tier <= 255):
        raise ValueError(f"archival tier out of range: {tier}")
    return bytes([tier]) + bytes(31)


def decode_archival_tier(value: bytes) -> int:
    if len(value) != 32:
        raise ValueError("archival-tier metadata leaf must be 32 bytes")
    return value[0]


def encode_flags(flags: int) -> bytes:
    if not (0 <= flags < 2**256):
        raise ValueError("flags out of range for 32-byte value")
    return flags.to_bytes(32, "big")


def decode_flags(value: bytes) -> int:
    if len(value) != 32:
        raise ValueError("flags metadata leaf must be 32 bytes")
    return int.from_bytes(value, "big")


def metadata_keys_for_address(
    address: bytes,
    layout: MetadataLayout = MetadataLayout(),
) -> dict[str, bytes]:
    """Return canonical metadata keys in the account header stem."""
    validate_metadata_layout(layout)
    stem_position = tree_hash(address)
    return {
        "expiry_epoch": get_tree_key(HEADER_SUBTREE, stem_position, layout.expiry_epoch_subindex),
        "hot_cold": get_tree_key(HEADER_SUBTREE, stem_position, layout.hot_cold_subindex),
        "archival_tier": get_tree_key(HEADER_SUBTREE, stem_position, layout.archival_tier_subindex),
        "flags": get_tree_key(HEADER_SUBTREE, stem_position, layout.flags_subindex),
    }


def metadata_partition_key(tree_position: bytes, subindex: int) -> bytes:
    """Construct a key in the reserved metadata partition for future expansion."""
    return get_tree_key(METADATA_SUBTREE, tree_position, subindex)
