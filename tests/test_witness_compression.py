"""Tests for optional witness compression wrapper helpers."""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from pbt.witness_compression import (
    MAX_CANONICAL_WITNESS_BYTES,
    compress_canonical_witness,
    decompress_canonical_witness,
    envelope_to_dict,
    envelope_from_dict,
)


def test_compress_decompress_round_trip():
    payload = b"canonical-witness:" + bytes(range(64)) * 8
    envelope = compress_canonical_witness(payload)
    recovered = decompress_canonical_witness(envelope)
    assert recovered == payload


def test_envelope_dict_round_trip():
    payload = b"abc" * 100
    envelope = compress_canonical_witness(payload, system_id="test")
    encoded = envelope_to_dict(envelope)
    parsed = envelope_from_dict(encoded)
    recovered = decompress_canonical_witness(parsed)
    assert recovered == payload


def test_tampered_payload_fails_commitment_check():
    payload = b"payload" * 50
    envelope = compress_canonical_witness(payload)
    bad = envelope_to_dict(envelope)
    wire = bad["compressedPayload"]
    bad["compressedPayload"] = wire[:-1] + ("0" if wire[-1] != "0" else "1")
    parsed = envelope_from_dict(bad)

    failed = False
    try:
        _ = decompress_canonical_witness(parsed)
    except Exception:
        failed = True
    assert failed


def test_rejects_oversized_payload_on_compress():
    payload = b"x" * (MAX_CANONICAL_WITNESS_BYTES + 1)

    failed = False
    try:
        _ = compress_canonical_witness(payload)
    except ValueError:
        failed = True
    assert failed


def test_rejects_trailing_bytes_in_compressed_payload():
    payload = b"payload" * 40
    envelope = compress_canonical_witness(payload)

    bad = envelope_to_dict(envelope)
    bad["compressedPayload"] = bad["compressedPayload"] + "00"
    parsed = envelope_from_dict(bad)

    failed = False
    try:
        _ = decompress_canonical_witness(parsed)
    except ValueError:
        failed = True
    assert failed
