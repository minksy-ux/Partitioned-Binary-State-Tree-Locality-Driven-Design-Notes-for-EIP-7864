"""Tests for metadata reservation hooks and encoding helpers."""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest

from pbt.constants import (
    CODE_OFFSET,
    HEADER_SUBTREE,
    METADATA_SUBTREE,
    METADATA_EXPIRY_EPOCH_SUBINDEX,
)
from pbt.metadata import (
    MetadataLayout,
    validate_metadata_layout,
    metadata_keys_for_address,
    metadata_partition_key,
    encode_expiry_epoch,
    decode_expiry_epoch,
    encode_hot_cold,
    decode_hot_cold,
    encode_archival_tier,
    decode_archival_tier,
    encode_flags,
    decode_flags,
)


def test_default_metadata_layout_is_valid():
    validate_metadata_layout()


def test_metadata_layout_rejects_overlap_with_active_header_ranges():
    layout = MetadataLayout(expiry_epoch_subindex=CODE_OFFSET)
    with pytest.raises(ValueError):
        validate_metadata_layout(layout)


def test_metadata_keys_share_header_stem_prefix():
    addr = bytes([0xAB] * 32)
    keys = metadata_keys_for_address(addr)

    stem_prefixes = {k[:-1] for k in keys.values()}
    assert len(stem_prefixes) == 1
    for key in keys.values():
        assert key[0] == HEADER_SUBTREE


def test_metadata_partition_key_uses_reserved_partition():
    key = metadata_partition_key(b"\x01" * 32, 7)
    assert key[0] == METADATA_SUBTREE
    assert key[-1] == 7


def test_expiry_epoch_encode_decode_round_trip():
    epoch = 123456789
    assert decode_expiry_epoch(encode_expiry_epoch(epoch)) == epoch


def test_hot_cold_encode_decode_round_trip():
    assert decode_hot_cold(encode_hot_cold(True)) is True
    assert decode_hot_cold(encode_hot_cold(False)) is False


def test_archival_tier_encode_decode_round_trip():
    for tier in (0, 1, 7, 255):
        assert decode_archival_tier(encode_archival_tier(tier)) == tier


def test_flags_encode_decode_round_trip():
    flags = (1 << METADATA_EXPIRY_EPOCH_SUBINDEX) | 0x55
    assert decode_flags(encode_flags(flags)) == flags
