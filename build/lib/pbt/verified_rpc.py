"""Minimal proof-carrying verified RPC helpers.

This module provides a compact companion interface for the EIP's optional
verified-RPC direction. It treats RPC responses as untrusted witness payloads
and enforces strict local validation before data is considered verified.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .constants import STEM_SUBTREE_WIDTH
from .stem_subscription import (
    LocalVerificationResult,
    StemWitnessPacket,
    decode_stem_witness_packet_v1,
    encode_stem_witness_packet_v1,
    verify_witness_packet,
)
from .tree import MerkleProof, verify_proof

METHOD_GET_VERIFIED_PROOF = "eth_getVerifiedProof"
METHOD_GET_STEM_WITNESS = "eth_getStemWitness"
METHOD_GET_STEM_PROOF = "eth_getStemProof"
METHOD_GET_VERIFIED_STATE = "eth_getVerifiedState"
WIRE_VERSION = "pbt-verified-rpc-v1"
JSONRPC_VERSION = "2.0"
MAX_PROOF_PATH_LENGTH = 4096
MAX_PACKET_WIRE_BYTES = 262144
MAX_U64 = (1 << 64) - 1

# Minimal protocol-level JSON-RPC error codes used by this companion layer.
ERR_INVALID_REQUEST = -32600
ERR_METHOD_NOT_FOUND = -32601
ERR_INVALID_PARAMS = -32602
ERR_INTERNAL = -32603
ERR_UNSUPPORTED_WIRE_VERSION = -32010
ERR_UNTRUSTED_STATE_ROOT = -32011
ERR_VERIFICATION_FAILED = -32012


def _bytes_to_hex(data: bytes) -> str:
    return "0x" + data.hex()


def _validate_jsonrpc_id(request_id: int | str | None, field_name: str = "id") -> None:
    if request_id is None:
        return
    if isinstance(request_id, bool):
        raise ValueError(f"{field_name} must be string, integer, or null")
    if not isinstance(request_id, (int, str)):
        raise ValueError(f"{field_name} must be string, integer, or null")


def _hex_to_bytes(value: str, field_name: str, max_bytes: int | None = None) -> bytes:
    if not isinstance(value, str):
        raise ValueError(f"{field_name} must be a hex string")
    if not value.startswith("0x"):
        raise ValueError(f"{field_name} must start with 0x")
    body = value[2:]
    if len(body) % 2 != 0:
        raise ValueError(f"{field_name} has odd-length hex body")
    if max_bytes is not None and (len(body) // 2) > max_bytes:
        raise ValueError(f"{field_name} exceeds maximum supported byte length")
    try:
        return bytes.fromhex(body)
    except ValueError as exc:
        raise ValueError(f"{field_name} is not valid hex") from exc


def _require_len(value: bytes, expected: int, field_name: str) -> None:
    if len(value) != expected:
        raise ValueError(f"{field_name} must be {expected} bytes, got {len(value)}")


def _u64_hex(value: int) -> str:
    if value < 0 or value > MAX_U64:
        raise ValueError("numeric field must fit in u64")
    return hex(value)


def _parse_u64_hex(value: str, field_name: str) -> int:
    if not isinstance(value, str):
        raise ValueError(f"{field_name} must be a hex string")
    if not value.startswith("0x"):
        raise ValueError(f"{field_name} must start with 0x")
    try:
        parsed = int(value, 16)
    except ValueError as exc:
        raise ValueError(f"{field_name} must be a valid hex integer") from exc
    if parsed < 0:
        raise ValueError(f"{field_name} must be non-negative")
    if parsed > MAX_U64:
        raise ValueError(f"{field_name} exceeds u64 range")
    return parsed


def _extract_result_object(payload: dict[str, Any], expected_method: str) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise ValueError("payload must be an object")

    # JSON-RPC 2.0 envelope path.
    if "jsonrpc" in payload or "id" in payload or "result" in payload or "error" in payload:
        if payload.get("jsonrpc") != JSONRPC_VERSION:
            raise ValueError("jsonrpc must be '2.0'")
        if "id" in payload:
            _validate_jsonrpc_id(payload.get("id"), "id")
        if "error" in payload:
            error = payload.get("error")
            if not isinstance(error, dict):
                raise ValueError("error must be an object")
            code = error.get("code")
            message = error.get("message")
            if not isinstance(code, int):
                raise ValueError("error.code must be an integer")
            if not isinstance(message, str) or not message:
                raise ValueError("error.message must be a non-empty string")
            raise ValueError(f"rpc error {code}: {message}")
        if "result" not in payload:
            raise ValueError("result must be present")
        result = payload.get("result")
    else:
        # Backward-compatible path for raw result object payloads.
        result = payload.get("result", payload)

    if not isinstance(result, dict):
        raise ValueError("result must be an object")
    if result.get("method") != expected_method:
        raise ValueError("unexpected method")
    return result


def make_jsonrpc_request(
    method: str,
    params: dict[str, Any],
    request_id: int | str | None = 1,
) -> dict[str, Any]:
    if not isinstance(method, str) or not method:
        raise ValueError("method must be a non-empty string")
    if not isinstance(params, dict):
        raise ValueError("params must be an object")
    _validate_jsonrpc_id(request_id)
    return {
        "jsonrpc": JSONRPC_VERSION,
        "id": request_id,
        "method": method,
        "params": params,
    }


def make_jsonrpc_success_response(
    result: dict[str, Any],
    request_id: int | str | None,
) -> dict[str, Any]:
    if not isinstance(result, dict):
        raise ValueError("result must be an object")
    _validate_jsonrpc_id(request_id)
    return {
        "jsonrpc": JSONRPC_VERSION,
        "id": request_id,
        "result": result,
    }


def make_jsonrpc_error_response(
    code: int,
    message: str,
    request_id: int | str | None,
    data: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if not isinstance(code, int):
        raise ValueError("code must be an integer")
    if not isinstance(message, str) or not message:
        raise ValueError("message must be a non-empty string")
    if data is not None and not isinstance(data, dict):
        raise ValueError("data must be an object when provided")
    _validate_jsonrpc_id(request_id)
    error_obj: dict[str, Any] = {"code": code, "message": message}
    if data is not None:
        error_obj["data"] = data
    return {
        "jsonrpc": JSONRPC_VERSION,
        "id": request_id,
        "error": error_obj,
    }


def make_eth_getVerifiedProof_request(
    key: bytes,
    block_tag: str = "latest",
    request_id: int | str | None = 1,
) -> dict[str, Any]:
    if not isinstance(block_tag, str) or not block_tag:
        raise ValueError("block_tag must be a non-empty string")
    return make_jsonrpc_request(
        METHOD_GET_VERIFIED_PROOF,
        params={"key": _bytes_to_hex(key), "blockTag": block_tag},
        request_id=request_id,
    )


def make_eth_getStemWitness_request(
    stem_prefix: bytes,
    block_tag: str = "latest",
    request_id: int | str | None = 1,
) -> dict[str, Any]:
    if not isinstance(block_tag, str) or not block_tag:
        raise ValueError("block_tag must be a non-empty string")
    return make_jsonrpc_request(
        METHOD_GET_STEM_WITNESS,
        params={"stemPrefix": _bytes_to_hex(stem_prefix), "blockTag": block_tag},
        request_id=request_id,
    )


def make_eth_getStemProof_request(
    stem_prefix: bytes,
    block_tag: str = "latest",
    request_id: int | str | None = 1,
) -> dict[str, Any]:
    """Alias for app-facing stem proof request naming."""
    request = make_eth_getStemWitness_request(
        stem_prefix=stem_prefix,
        block_tag=block_tag,
        request_id=request_id,
    )
    request["method"] = METHOD_GET_STEM_PROOF
    return request


def make_eth_getVerifiedState_request(
    key: bytes,
    block_tag: str = "latest",
    request_id: int | str | None = 1,
) -> dict[str, Any]:
    """Alias for app-facing verified state request naming."""
    request = make_eth_getVerifiedProof_request(
        key=key,
        block_tag=block_tag,
        request_id=request_id,
    )
    request["method"] = METHOD_GET_VERIFIED_STATE
    return request


def _proof_to_json_dict(proof: MerkleProof) -> dict[str, Any]:
    return {
        "key": _bytes_to_hex(proof.key),
        "value": _bytes_to_hex(proof.value),
        "stemValues": [_bytes_to_hex(value) for value in proof.stem_values],
        "pathSiblings": [_bytes_to_hex(sibling) for sibling in proof.path_siblings],
        "pathBits": list(proof.path_bits),
    }


def _proof_from_json_dict(data: dict[str, Any]) -> MerkleProof:
    if not isinstance(data, dict):
        raise ValueError("proof must be an object")

    key = _hex_to_bytes(data.get("key"), "proof.key")
    value = _hex_to_bytes(data.get("value"), "proof.value")
    _require_len(value, 32, "proof.value")

    stem_values_raw = data.get("stemValues")
    if not isinstance(stem_values_raw, list):
        raise ValueError("proof.stemValues must be a list")
    if len(stem_values_raw) != STEM_SUBTREE_WIDTH:
        raise ValueError(f"proof.stemValues must contain {STEM_SUBTREE_WIDTH} entries")
    stem_values = [_hex_to_bytes(item, "proof.stemValues[]") for item in stem_values_raw]
    for stem_value in stem_values:
        _require_len(stem_value, 32, "proof.stemValues[]")

    path_siblings_raw = data.get("pathSiblings")
    if not isinstance(path_siblings_raw, list):
        raise ValueError("proof.pathSiblings must be a list")
    if len(path_siblings_raw) > MAX_PROOF_PATH_LENGTH:
        raise ValueError("proof.pathSiblings exceeds maximum supported path length")
    path_siblings = [_hex_to_bytes(item, "proof.pathSiblings[]") for item in path_siblings_raw]
    for sibling in path_siblings:
        _require_len(sibling, 32, "proof.pathSiblings[]")

    path_bits_raw = data.get("pathBits")
    if not isinstance(path_bits_raw, list):
        raise ValueError("proof.pathBits must be a list")
    if len(path_bits_raw) > MAX_PROOF_PATH_LENGTH:
        raise ValueError("proof.pathBits exceeds maximum supported path length")
    if len(path_bits_raw) != len(path_siblings_raw):
        raise ValueError("proof.pathBits length must match proof.pathSiblings length")
    if any(not isinstance(bit, int) or isinstance(bit, bool) for bit in path_bits_raw):
        raise ValueError("proof.pathBits entries must be integers")
    if any(bit not in (0, 1) for bit in path_bits_raw):
        raise ValueError("proof.pathBits entries must be 0 or 1")

    return MerkleProof(
        key=key,
        value=value,
        stem_values=stem_values,
        path_siblings=path_siblings,
        path_bits=[int(bit) for bit in path_bits_raw],
    )


@dataclass(frozen=True)
class VerifiedProofRpcResult:
    provider: str
    block_number: int
    block_hash: bytes
    state_root: bytes
    key: bytes
    value: bytes
    proof: MerkleProof


@dataclass(frozen=True)
class StemWitnessRpcResult:
    provider: str
    block_number: int
    block_hash: bytes
    state_root: bytes
    packet: StemWitnessPacket


def make_eth_getVerifiedProof_result(
    provider: str,
    block_number: int,
    block_hash: bytes,
    state_root: bytes,
    key: bytes,
    value: bytes,
    proof: MerkleProof,
) -> dict[str, Any]:
    """Create a canonical result payload for `eth_getVerifiedProof`."""
    if not isinstance(provider, str) or not provider:
        raise ValueError("provider must be a non-empty string")
    _require_len(block_hash, 32, "block_hash")
    _require_len(state_root, 32, "state_root")
    _require_len(value, 32, "value")

    return {
        "version": WIRE_VERSION,
        "method": METHOD_GET_VERIFIED_PROOF,
        "provider": provider,
        "block": {
            "number": _u64_hex(block_number),
            "hash": _bytes_to_hex(block_hash),
            "stateRoot": _bytes_to_hex(state_root),
        },
        "state": {
            "key": _bytes_to_hex(key),
            "value": _bytes_to_hex(value),
        },
        "proof": _proof_to_json_dict(proof),
    }


def make_eth_getVerifiedState_result(
    provider: str,
    block_number: int,
    block_hash: bytes,
    state_root: bytes,
    key: bytes,
    value: bytes,
    proof: MerkleProof,
) -> dict[str, Any]:
    """Alias result for app-facing verified state method."""
    result = make_eth_getVerifiedProof_result(
        provider=provider,
        block_number=block_number,
        block_hash=block_hash,
        state_root=state_root,
        key=key,
        value=value,
        proof=proof,
    )
    result["method"] = METHOD_GET_VERIFIED_STATE
    return result


def parse_eth_getVerifiedProof_result(payload: dict[str, Any]) -> VerifiedProofRpcResult:
    """Parse and validate an `eth_getVerifiedProof` payload."""
    result = _extract_result_object(payload, METHOD_GET_VERIFIED_PROOF)

    if result.get("version") != WIRE_VERSION:
        raise ValueError("unsupported version")

    provider = result.get("provider")
    if not isinstance(provider, str) or not provider:
        raise ValueError("provider must be a non-empty string")

    block = result.get("block")
    state = result.get("state")
    if not isinstance(block, dict):
        raise ValueError("block must be an object")
    if not isinstance(state, dict):
        raise ValueError("state must be an object")

    block_number = _parse_u64_hex(block.get("number"), "block.number")
    block_hash = _hex_to_bytes(block.get("hash"), "block.hash")
    state_root = _hex_to_bytes(block.get("stateRoot"), "block.stateRoot")
    key = _hex_to_bytes(state.get("key"), "state.key")
    value = _hex_to_bytes(state.get("value"), "state.value")

    _require_len(block_hash, 32, "block.hash")
    _require_len(state_root, 32, "block.stateRoot")
    _require_len(value, 32, "state.value")

    proof = _proof_from_json_dict(result.get("proof"))
    if proof.key != key:
        raise ValueError("proof.key != state.key")
    if proof.value != value:
        raise ValueError("proof.value != state.value")

    return VerifiedProofRpcResult(
        provider=provider,
        block_number=block_number,
        block_hash=block_hash,
        state_root=state_root,
        key=key,
        value=value,
        proof=proof,
    )


def verify_eth_getVerifiedProof_result(
    payload: dict[str, Any],
    expected_state_root: bytes | None = None,
) -> LocalVerificationResult:
    """Verify an `eth_getVerifiedProof` response locally."""
    try:
        parsed = parse_eth_getVerifiedProof_result(payload)
    except ValueError as exc:
        return LocalVerificationResult(False, f"malformed verified proof payload: {exc}")

    if expected_state_root is not None and parsed.state_root != expected_state_root:
        return LocalVerificationResult(False, "state root is not locally trusted")

    if not verify_proof(parsed.state_root, parsed.proof):
        return LocalVerificationResult(False, "proof verification failed")
    return LocalVerificationResult(True, "verified proof locally accepted")


def parse_eth_getVerifiedState_result(payload: dict[str, Any]) -> VerifiedProofRpcResult:
    """Parse alias payload for eth_getVerifiedState."""
    copied = dict(payload)
    result_obj = copied.get("result", copied)
    if isinstance(result_obj, dict):
        copied_result = dict(result_obj)
        copied_result["method"] = METHOD_GET_VERIFIED_PROOF
        if "result" in copied:
            copied["result"] = copied_result
        else:
            copied = copied_result
    return parse_eth_getVerifiedProof_result(copied)


def verify_eth_getVerifiedState_result(
    payload: dict[str, Any],
    expected_state_root: bytes | None = None,
) -> LocalVerificationResult:
    """Verify alias response for eth_getVerifiedState."""
    copied = dict(payload)
    result_obj = copied.get("result", copied)
    if isinstance(result_obj, dict):
        copied_result = dict(result_obj)
        copied_result["method"] = METHOD_GET_VERIFIED_PROOF
        if "result" in copied:
            copied["result"] = copied_result
        else:
            copied = copied_result
    return verify_eth_getVerifiedProof_result(copied, expected_state_root=expected_state_root)


def make_eth_getStemWitness_result(
    provider: str,
    block_hash: bytes,
    packet: StemWitnessPacket,
) -> dict[str, Any]:
    """Create a canonical result payload for `eth_getStemWitness`."""
    if not isinstance(provider, str) or not provider:
        raise ValueError("provider must be a non-empty string")
    _require_len(block_hash, 32, "block_hash")
    packet_wire = encode_stem_witness_packet_v1(packet)
    if len(packet_wire) > MAX_PACKET_WIRE_BYTES:
        raise ValueError("packet wire exceeds maximum supported byte length")

    return {
        "version": WIRE_VERSION,
        "method": METHOD_GET_STEM_WITNESS,
        "provider": provider,
        "block": {
            "number": _u64_hex(packet.block_number),
            "hash": _bytes_to_hex(block_hash),
            "stateRoot": _bytes_to_hex(packet.block_root),
        },
        "stemWitness": {
            "packetWire": _bytes_to_hex(packet_wire),
        },
    }


def make_eth_getStemProof_result(
    provider: str,
    block_hash: bytes,
    packet: StemWitnessPacket,
) -> dict[str, Any]:
    """Alias result for app-facing stem proof method."""
    result = make_eth_getStemWitness_result(
        provider=provider,
        block_hash=block_hash,
        packet=packet,
    )
    result["method"] = METHOD_GET_STEM_PROOF
    return result


def make_eth_getVerifiedProof_response(
    request_id: int | str | None,
    provider: str,
    block_number: int,
    block_hash: bytes,
    state_root: bytes,
    key: bytes,
    value: bytes,
    proof: MerkleProof,
) -> dict[str, Any]:
    result = make_eth_getVerifiedProof_result(
        provider=provider,
        block_number=block_number,
        block_hash=block_hash,
        state_root=state_root,
        key=key,
        value=value,
        proof=proof,
    )
    return make_jsonrpc_success_response(result=result, request_id=request_id)


def make_eth_getStemWitness_response(
    request_id: int | str | None,
    provider: str,
    block_hash: bytes,
    packet: StemWitnessPacket,
) -> dict[str, Any]:
    result = make_eth_getStemWitness_result(
        provider=provider,
        block_hash=block_hash,
        packet=packet,
    )
    return make_jsonrpc_success_response(result=result, request_id=request_id)


def parse_eth_getStemWitness_result(payload: dict[str, Any]) -> StemWitnessRpcResult:
    """Parse and validate an `eth_getStemWitness` payload."""
    result = _extract_result_object(payload, METHOD_GET_STEM_WITNESS)

    if result.get("version") != WIRE_VERSION:
        raise ValueError("unsupported version")

    provider = result.get("provider")
    if not isinstance(provider, str) or not provider:
        raise ValueError("provider must be a non-empty string")

    block = result.get("block")
    stem_witness = result.get("stemWitness")
    if not isinstance(block, dict):
        raise ValueError("block must be an object")
    if not isinstance(stem_witness, dict):
        raise ValueError("stemWitness must be an object")

    block_number = _parse_u64_hex(block.get("number"), "block.number")
    block_hash = _hex_to_bytes(block.get("hash"), "block.hash")
    state_root = _hex_to_bytes(block.get("stateRoot"), "block.stateRoot")
    packet_wire = _hex_to_bytes(
        stem_witness.get("packetWire"),
        "stemWitness.packetWire",
        max_bytes=MAX_PACKET_WIRE_BYTES,
    )

    _require_len(block_hash, 32, "block.hash")
    _require_len(state_root, 32, "block.stateRoot")

    packet = decode_stem_witness_packet_v1(packet_wire)
    if packet.block_number != block_number:
        raise ValueError("packet.block_number != block.number")
    if packet.block_root != state_root:
        raise ValueError("packet.block_root != block.stateRoot")

    return StemWitnessRpcResult(
        provider=provider,
        block_number=block_number,
        block_hash=block_hash,
        state_root=state_root,
        packet=packet,
    )


def verify_eth_getStemWitness_result(
    payload: dict[str, Any],
    expected_state_root: bytes | None = None,
) -> LocalVerificationResult:
    """Verify an `eth_getStemWitness` response locally."""
    try:
        parsed = parse_eth_getStemWitness_result(payload)
    except ValueError as exc:
        return LocalVerificationResult(False, f"malformed stem witness payload: {exc}")

    if expected_state_root is not None and parsed.state_root != expected_state_root:
        return LocalVerificationResult(False, "state root is not locally trusted")

    if not verify_witness_packet(parsed.packet):
        return LocalVerificationResult(False, "stem witness verification failed")
    return LocalVerificationResult(True, "stem witness locally accepted")


def parse_eth_getStemProof_result(payload: dict[str, Any]) -> StemWitnessRpcResult:
    """Parse alias payload for eth_getStemProof."""
    copied = dict(payload)
    result_obj = copied.get("result", copied)
    if isinstance(result_obj, dict):
        copied_result = dict(result_obj)
        copied_result["method"] = METHOD_GET_STEM_WITNESS
        if "result" in copied:
            copied["result"] = copied_result
        else:
            copied = copied_result
    return parse_eth_getStemWitness_result(copied)


def verify_eth_getStemProof_result(
    payload: dict[str, Any],
    expected_state_root: bytes | None = None,
) -> LocalVerificationResult:
    """Verify alias response for eth_getStemProof."""
    copied = dict(payload)
    result_obj = copied.get("result", copied)
    if isinstance(result_obj, dict):
        copied_result = dict(result_obj)
        copied_result["method"] = METHOD_GET_STEM_WITNESS
        if "result" in copied:
            copied["result"] = copied_result
        else:
            copied = copied_result
    return verify_eth_getStemWitness_result(copied, expected_state_root=expected_state_root)
