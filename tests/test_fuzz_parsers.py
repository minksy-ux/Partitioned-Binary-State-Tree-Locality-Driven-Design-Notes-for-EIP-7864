"""Property/fuzz stress tests for parser and decoder hardening surfaces."""

from __future__ import annotations

import os
import sys

from hypothesis import given
from hypothesis import strategies as st

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from pbt.stem_subscription import decode_stem_witness_packet_v1
from pbt.verified_rpc import parse_eth_getVerifiedProof_result
from pbt.witness_compression import envelope_from_dict


@given(blob=st.binary(min_size=0, max_size=4096))
def test_decode_stem_witness_packet_fuzz_never_crashes(blob: bytes):
    try:
        decode_stem_witness_packet_v1(blob)
    except ValueError:
        pass


@given(
    key_hex=st.text(min_size=0, max_size=128),
    value_hex=st.text(min_size=0, max_size=128),
    provider=st.text(min_size=0, max_size=64),
    method=st.text(min_size=0, max_size=64),
)
def test_verified_rpc_parser_fuzz_rejects_malformed_payloads(
    key_hex: str,
    value_hex: str,
    provider: str,
    method: str,
):
    payload = {
        "version": "pbt-verified-rpc-v1",
        "method": method,
        "provider": provider,
        "block": {
            "number": "0x1",
            "hash": "0x" + key_hex,
            "stateRoot": "0x" + value_hex,
        },
        "state": {
            "key": "0x" + key_hex,
            "value": "0x" + value_hex,
        },
        "proof": {
            "key": "0x" + key_hex,
            "value": "0x" + value_hex,
            "stemValues": [],
            "pathSiblings": [],
            "pathBits": [],
        },
    }
    try:
        parse_eth_getVerifiedProof_result(payload)
    except ValueError:
        pass


@given(
    system_id=st.text(min_size=0, max_size=32),
    version=st.integers(min_value=-5, max_value=5),
    length=st.integers(min_value=-10, max_value=1000),
    commitment=st.binary(min_size=0, max_size=64),
    payload=st.binary(min_size=0, max_size=1024),
)
def test_witness_compression_envelope_parser_fuzz(
    system_id: str,
    version: int,
    length: int,
    commitment: bytes,
    payload: bytes,
):
    obj = {
        "systemId": system_id,
        "version": version,
        "uncompressedLength": length,
        "uncompressedCommitment": "0x" + commitment.hex(),
        "compressedPayload": "0x" + payload.hex(),
    }
    try:
        envelope_from_dict(obj)
    except ValueError:
        pass
