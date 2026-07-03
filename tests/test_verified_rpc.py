"""Tests for minimal proof-carrying verified RPC helpers."""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from pbt.nodes import EmptyNode
from pbt.tree import get_proof, insert, root_hash
from pbt.stem_subscription import StemWitnessPacket
from pbt.verified_rpc import (
    ERR_INVALID_PARAMS,
    make_eth_getStemWitness_result,
    make_eth_getStemWitness_request,
    make_eth_getStemProof_request,
    make_eth_getVerifiedState_request,
    make_eth_getStemProof_result,
    make_eth_getVerifiedState_result,
    make_eth_getStemWitness_response,
    make_eth_getVerifiedProof_result,
    make_eth_getVerifiedProof_request,
    make_eth_getVerifiedProof_response,
    parse_eth_getStemProof_result,
    parse_eth_getVerifiedState_result,
    make_jsonrpc_error_response,
    parse_eth_getStemWitness_result,
    parse_eth_getVerifiedProof_result,
    verify_eth_getStemProof_result,
    verify_eth_getVerifiedState_result,
    verify_eth_getStemWitness_result,
    verify_eth_getVerifiedProof_result,
)


def _build_tree_fixture():
    key = bytes([0]) + bytes([0xAA] * 32) + bytes([7])
    value = (777).to_bytes(32, "big")
    root = insert(EmptyNode(), key, value)
    rh = root_hash(root)
    proof = get_proof(root, key)
    return key, value, rh, proof


def _build_packet_fixture() -> StemWitnessPacket:
    key, value, rh, proof = _build_tree_fixture()
    return StemWitnessPacket(
        epoch=1,
        block_number=100,
        block_root=rh,
        stem_prefix=key[:-1],
        key=key,
        value=value,
        proof=proof,
        bucket_id=3,
    )


def test_verified_proof_payload_round_trip_and_local_verification():
    key, value, rh, proof = _build_tree_fixture()
    payload = make_eth_getVerifiedProof_result(
        provider="provider-a",
        block_number=123,
        block_hash=b"h" * 32,
        state_root=rh,
        key=key,
        value=value,
        proof=proof,
    )

    parsed = parse_eth_getVerifiedProof_result(payload)
    assert parsed.key == key
    assert parsed.value == value
    assert parsed.state_root == rh

    ok = verify_eth_getVerifiedProof_result(payload, expected_state_root=rh)
    assert ok.accepted


def test_verified_proof_rejects_untrusted_state_root():
    key, value, rh, proof = _build_tree_fixture()
    payload = make_eth_getVerifiedProof_result(
        provider="provider-a",
        block_number=123,
        block_hash=b"h" * 32,
        state_root=rh,
        key=key,
        value=value,
        proof=proof,
    )

    bad = verify_eth_getVerifiedProof_result(payload, expected_state_root=b"z" * 32)
    assert not bad.accepted
    assert "not locally trusted" in bad.reason


def test_verified_proof_rejects_malformed_hex_payload():
    key, value, rh, proof = _build_tree_fixture()
    payload = make_eth_getVerifiedProof_result(
        provider="provider-a",
        block_number=123,
        block_hash=b"h" * 32,
        state_root=rh,
        key=key,
        value=value,
        proof=proof,
    )

    payload["state"]["value"] = "0xxyz"
    bad = verify_eth_getVerifiedProof_result(payload)
    assert not bad.accepted
    assert "malformed" in bad.reason


def test_verified_proof_rejects_non_32byte_stem_value():
    key, value, rh, proof = _build_tree_fixture()
    payload = make_eth_getVerifiedProof_result(
        provider="provider-a",
        block_number=123,
        block_hash=b"h" * 32,
        state_root=rh,
        key=key,
        value=value,
        proof=proof,
    )

    payload["proof"]["stemValues"][0] = "0x01"
    bad = verify_eth_getVerifiedProof_result(payload)
    assert not bad.accepted
    assert "malformed" in bad.reason


def test_verified_proof_rejects_non_32byte_sibling():
    key, value, rh, proof = _build_tree_fixture()
    if not proof.path_siblings:
        other_key = bytes([1]) + bytes([0xAA] * 32) + bytes([7])
        other_value = (123).to_bytes(32, "big")
        root = insert(EmptyNode(), key, value)
        root = insert(root, other_key, other_value)
        rh = root_hash(root)
        proof = get_proof(root, key)
    payload = make_eth_getVerifiedProof_result(
        provider="provider-a",
        block_number=123,
        block_hash=b"h" * 32,
        state_root=rh,
        key=key,
        value=value,
        proof=proof,
    )

    payload["proof"]["pathSiblings"][0] = "0x01"
    bad = verify_eth_getVerifiedProof_result(payload)
    assert not bad.accepted
    assert "malformed" in bad.reason


def test_verified_proof_rejects_boolean_path_bit():
    key, value, rh, proof = _build_tree_fixture()
    if not proof.path_bits:
        other_key = bytes([1]) + bytes([0xAA] * 32) + bytes([7])
        other_value = (123).to_bytes(32, "big")
        root = insert(EmptyNode(), key, value)
        root = insert(root, other_key, other_value)
        rh = root_hash(root)
        proof = get_proof(root, key)
    payload = make_eth_getVerifiedProof_result(
        provider="provider-a",
        block_number=123,
        block_hash=b"h" * 32,
        state_root=rh,
        key=key,
        value=value,
        proof=proof,
    )

    payload["proof"]["pathBits"][0] = True
    bad = verify_eth_getVerifiedProof_result(payload)
    assert not bad.accepted
    assert "malformed" in bad.reason


def test_verified_proof_rejects_wrong_stem_values_count():
    key, value, rh, proof = _build_tree_fixture()
    payload = make_eth_getVerifiedProof_result(
        provider="provider-a",
        block_number=123,
        block_hash=b"h" * 32,
        state_root=rh,
        key=key,
        value=value,
        proof=proof,
    )

    payload["proof"]["stemValues"] = payload["proof"]["stemValues"][:-1]
    bad = verify_eth_getVerifiedProof_result(payload)
    assert not bad.accepted
    assert "malformed" in bad.reason


def test_verified_proof_rejects_mismatched_path_lengths():
    key, value, rh, proof = _build_tree_fixture()
    if not proof.path_bits:
        other_key = bytes([1]) + bytes([0xAA] * 32) + bytes([7])
        other_value = (123).to_bytes(32, "big")
        root = insert(EmptyNode(), key, value)
        root = insert(root, other_key, other_value)
        rh = root_hash(root)
        proof = get_proof(root, key)

    payload = make_eth_getVerifiedProof_result(
        provider="provider-a",
        block_number=123,
        block_hash=b"h" * 32,
        state_root=rh,
        key=key,
        value=value,
        proof=proof,
    )

    payload["proof"]["pathBits"] = payload["proof"]["pathBits"][:-1]
    bad = verify_eth_getVerifiedProof_result(payload)
    assert not bad.accepted
    assert "malformed" in bad.reason


def test_stem_witness_payload_round_trip_and_local_verification():
    packet = _build_packet_fixture()
    payload = make_eth_getStemWitness_result(
        provider="provider-a",
        block_hash=b"b" * 32,
        packet=packet,
    )

    parsed = parse_eth_getStemWitness_result(payload)
    assert parsed.packet.key == packet.key
    assert parsed.packet.value == packet.value

    ok = verify_eth_getStemWitness_result(payload, expected_state_root=packet.block_root)
    assert ok.accepted


def test_stem_witness_rejects_untrusted_state_root():
    packet = _build_packet_fixture()
    payload = make_eth_getStemWitness_result(
        provider="provider-a",
        block_hash=b"b" * 32,
        packet=packet,
    )

    bad = verify_eth_getStemWitness_result(payload, expected_state_root=b"z" * 32)
    assert not bad.accepted
    assert "not locally trusted" in bad.reason


def test_stem_witness_rejects_tampered_packet_wire():
    packet = _build_packet_fixture()
    payload = make_eth_getStemWitness_result(
        provider="provider-a",
        block_hash=b"b" * 32,
        packet=packet,
    )

    wire = payload["stemWitness"]["packetWire"]
    # Flip the final nibble to invalidate packet commitment.
    tampered_wire = wire[:-1] + ("0" if wire[-1] != "0" else "1")
    payload["stemWitness"]["packetWire"] = tampered_wire

    bad = verify_eth_getStemWitness_result(payload)
    assert not bad.accepted
    assert "malformed" in bad.reason


def test_verified_proof_jsonrpc_request_and_response_round_trip():
    key, value, rh, proof = _build_tree_fixture()
    request = make_eth_getVerifiedProof_request(key=key, block_tag="latest", request_id=7)
    assert request["jsonrpc"] == "2.0"
    assert request["id"] == 7
    assert request["method"] == "eth_getVerifiedProof"
    assert request["params"]["key"].startswith("0x")

    response = make_eth_getVerifiedProof_response(
        request_id=7,
        provider="provider-a",
        block_number=123,
        block_hash=b"h" * 32,
        state_root=rh,
        key=key,
        value=value,
        proof=proof,
    )
    parsed = parse_eth_getVerifiedProof_result(response)
    assert parsed.key == key
    assert parsed.value == value


def test_stem_witness_jsonrpc_request_and_response_round_trip():
    packet = _build_packet_fixture()
    request = make_eth_getStemWitness_request(
        stem_prefix=packet.stem_prefix,
        block_tag="finalized",
        request_id="abc-1",
    )
    assert request["jsonrpc"] == "2.0"
    assert request["id"] == "abc-1"
    assert request["method"] == "eth_getStemWitness"
    assert request["params"]["stemPrefix"].startswith("0x")

    response = make_eth_getStemWitness_response(
        request_id="abc-1",
        provider="provider-a",
        block_hash=b"b" * 32,
        packet=packet,
    )
    parsed = parse_eth_getStemWitness_result(response)
    assert parsed.packet.key == packet.key
    assert parsed.packet.value == packet.value


def test_verified_rpc_parse_rejects_jsonrpc_error_envelope():
    error_payload = make_jsonrpc_error_response(
        code=ERR_INVALID_PARAMS,
        message="invalid params",
        request_id=9,
    )

    bad1 = verify_eth_getVerifiedProof_result(error_payload)
    assert not bad1.accepted
    assert "rpc error" in bad1.reason

    bad2 = verify_eth_getStemWitness_result(error_payload)
    assert not bad2.accepted
    assert "rpc error" in bad2.reason


def test_verified_state_alias_round_trip_and_verify():
    key, value, rh, proof = _build_tree_fixture()
    request = make_eth_getVerifiedState_request(key=key, request_id=8)
    assert request["method"] == "eth_getVerifiedState"

    result = make_eth_getVerifiedState_result(
        provider="provider-a",
        block_number=12,
        block_hash=b"h" * 32,
        state_root=rh,
        key=key,
        value=value,
        proof=proof,
    )
    parsed = parse_eth_getVerifiedState_result(result)
    assert parsed.key == key
    assert parsed.value == value

    verified = verify_eth_getVerifiedState_result(result, expected_state_root=rh)
    assert verified.accepted


def test_stem_proof_alias_round_trip_and_verify():
    packet = _build_packet_fixture()
    request = make_eth_getStemProof_request(stem_prefix=packet.stem_prefix, request_id=11)
    assert request["method"] == "eth_getStemProof"

    result = make_eth_getStemProof_result(
        provider="provider-a",
        block_hash=b"b" * 32,
        packet=packet,
    )
    parsed = parse_eth_getStemProof_result(result)
    assert parsed.packet.key == packet.key

    verified = verify_eth_getStemProof_result(result, expected_state_root=packet.block_root)
    assert verified.accepted


def test_verified_proof_rejects_block_number_over_u64_range():
    key, value, rh, proof = _build_tree_fixture()
    payload = make_eth_getVerifiedProof_result(
        provider="provider-a",
        block_number=123,
        block_hash=b"h" * 32,
        state_root=rh,
        key=key,
        value=value,
        proof=proof,
    )
    payload["block"]["number"] = "0x10000000000000000"

    bad = verify_eth_getVerifiedProof_result(payload)
    assert not bad.accepted
    assert "malformed" in bad.reason


def test_stem_witness_rejects_oversized_packet_wire_hex():
    packet = _build_packet_fixture()
    payload = make_eth_getStemWitness_result(
        provider="provider-a",
        block_hash=b"b" * 32,
        packet=packet,
    )

    payload["stemWitness"]["packetWire"] = "0x" + ("ab" * 262145)
    bad = verify_eth_getStemWitness_result(payload)
    assert not bad.accepted
    assert "malformed" in bad.reason
