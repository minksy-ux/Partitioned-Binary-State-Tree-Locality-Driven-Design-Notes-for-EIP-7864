"""Canonical witness compression wrapper helpers.

This module provides an optional transport wrapper for canonical witness bytes.
Compression does not change verification semantics: callers must verify the
underlying canonical witness after decompression.
"""

from __future__ import annotations

from dataclasses import dataclass
import zlib

from .hash import tree_hash


MAX_CANONICAL_WITNESS_BYTES = 16 * 1024 * 1024


@dataclass(frozen=True)
class CompressedWitnessEnvelope:
    """Compression envelope with commitment to original canonical payload."""

    system_id: str
    version: int
    uncompressed_length: int
    uncompressed_commitment: bytes
    compressed_payload: bytes


def compress_canonical_witness(
    payload: bytes,
    system_id: str = "zlib-stark-wrapper",
    version: int = 1,
    level: int = 9,
    max_uncompressed_length: int = MAX_CANONICAL_WITNESS_BYTES,
) -> CompressedWitnessEnvelope:
    """Compress canonical witness bytes into a commitment-carrying envelope."""
    if not isinstance(payload, (bytes, bytearray)):
        raise ValueError("payload must be bytes-like")
    if not system_id:
        raise ValueError("system_id must be non-empty")
    if version <= 0:
        raise ValueError("version must be positive")
    if level < 0 or level > 9:
        raise ValueError("level must be between 0 and 9")
    if max_uncompressed_length <= 0:
        raise ValueError("max_uncompressed_length must be positive")

    canonical = bytes(payload)
    if len(canonical) > max_uncompressed_length:
        raise ValueError("payload exceeds max_uncompressed_length")
    return CompressedWitnessEnvelope(
        system_id=system_id,
        version=version,
        uncompressed_length=len(canonical),
        uncompressed_commitment=tree_hash(canonical),
        compressed_payload=zlib.compress(canonical, level),
    )


def decompress_canonical_witness(
    envelope: CompressedWitnessEnvelope,
    max_uncompressed_length: int = MAX_CANONICAL_WITNESS_BYTES,
) -> bytes:
    """Decompress and integrity-check canonical witness bytes from envelope."""
    if envelope.uncompressed_length < 0:
        raise ValueError("uncompressed_length must be non-negative")
    if max_uncompressed_length <= 0:
        raise ValueError("max_uncompressed_length must be positive")
    if envelope.uncompressed_length > max_uncompressed_length:
        raise ValueError("uncompressed_length exceeds max_uncompressed_length")

    decompressor = zlib.decompressobj()
    decompressed = decompressor.decompress(
        envelope.compressed_payload,
        max_uncompressed_length + 1,
    )
    if len(decompressed) > max_uncompressed_length:
        raise ValueError("decompressed payload exceeds max_uncompressed_length")
    if decompressor.unconsumed_tail or not decompressor.eof:
        raise ValueError("compressed payload exceeds safety limit or is incomplete")

    tail = decompressor.flush(max_uncompressed_length + 1 - len(decompressed))
    decompressed += tail
    if len(decompressed) > max_uncompressed_length:
        raise ValueError("decompressed payload exceeds max_uncompressed_length")
    if decompressor.unused_data:
        raise ValueError("compressed payload contains trailing bytes")

    if len(decompressed) != envelope.uncompressed_length:
        raise ValueError("decompressed length mismatch")
    if tree_hash(decompressed) != envelope.uncompressed_commitment:
        raise ValueError("uncompressed commitment mismatch")
    return decompressed


def envelope_to_dict(envelope: CompressedWitnessEnvelope) -> dict[str, object]:
    """Serialize envelope for RPC transport."""
    return {
        "systemId": envelope.system_id,
        "version": envelope.version,
        "uncompressedLength": envelope.uncompressed_length,
        "uncompressedCommitment": "0x" + envelope.uncompressed_commitment.hex(),
        "compressedPayload": "0x" + envelope.compressed_payload.hex(),
    }


def envelope_from_dict(data: dict[str, object]) -> CompressedWitnessEnvelope:
    """Parse envelope from RPC transport structure."""
    if not isinstance(data, dict):
        raise ValueError("envelope must be an object")

    system_id = data.get("systemId")
    version = data.get("version")
    uncompressed_length = data.get("uncompressedLength")
    commitment_hex = data.get("uncompressedCommitment")
    payload_hex = data.get("compressedPayload")

    if not isinstance(system_id, str) or not system_id:
        raise ValueError("systemId must be a non-empty string")
    if not isinstance(version, int) or version <= 0:
        raise ValueError("version must be a positive integer")
    if not isinstance(uncompressed_length, int) or uncompressed_length < 0:
        raise ValueError("uncompressedLength must be a non-negative integer")
    if not isinstance(commitment_hex, str) or not commitment_hex.startswith("0x"):
        raise ValueError("uncompressedCommitment must be 0x-prefixed hex")
    if not isinstance(payload_hex, str) or not payload_hex.startswith("0x"):
        raise ValueError("compressedPayload must be 0x-prefixed hex")

    commitment = bytes.fromhex(commitment_hex[2:])
    payload = bytes.fromhex(payload_hex[2:])
    if len(commitment) != 32:
        raise ValueError("uncompressedCommitment must be 32 bytes")

    return CompressedWitnessEnvelope(
        system_id=system_id,
        version=version,
        uncompressed_length=uncompressed_length,
        uncompressed_commitment=commitment,
        compressed_payload=payload,
    )
