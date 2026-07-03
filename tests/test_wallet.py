"""Tests for local verification policy, privacy query baseline, and smart-account defaults."""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest

from pbt.nodes import EmptyNode
from pbt.tree import insert, get_proof, root_hash
from pbt.wallet import (
    VerificationStatus,
    UIMode,
    RpcStateResponse,
    LocalVerificationPolicy,
    UnverifiedResponseError,
    RedundantQueryEngine,
    PrivacyQueryService,
    PrivacyMode,
    SmartAccount,
)


class MockProvider:
    def __init__(self, name: str, response: RpcStateResponse):
        self.name = name
        self._response = response

    def query(self, key: bytes) -> RpcStateResponse:
        assert key == self._response.key
        return self._response


def _build_verified_response(provider: str = "p1") -> tuple[bytes, bytes, bytes, RpcStateResponse]:
    key = bytes([0]) + bytes([0xCC] * 32) + bytes([7])
    value = (777).to_bytes(32, "big")
    root = insert(EmptyNode(), key, value)
    proof = get_proof(root, key)
    return key, value, root_hash(root), RpcStateResponse(provider=provider, key=key, value=value, proof=proof)


def test_local_verification_policy_marks_verified_response():
    key, value, rh, response = _build_verified_response()
    policy = LocalVerificationPolicy(rh)
    view = policy.classify(response)

    assert view.status == VerificationStatus.VERIFIED
    assert view.ui_mode == UIMode.NORMAL
    assert view.value == value


def test_local_verification_policy_marks_unverified_mode_for_missing_proof():
    key, value, rh, _ = _build_verified_response()
    policy = LocalVerificationPolicy(rh)
    unverified = RpcStateResponse(provider="p1", key=key, value=value, proof=None)

    view = policy.classify(unverified)
    assert view.status == VerificationStatus.UNVERIFIED
    assert view.ui_mode == UIMode.UNVERIFIED
    with pytest.raises(UnverifiedResponseError):
        policy.require_verified(unverified)


def test_redundant_query_engine_requires_multi_provider_agreement():
    key, value, rh, verified_response = _build_verified_response(provider="a")
    policy = LocalVerificationPolicy(rh)

    provider_a = MockProvider("a", verified_response)
    provider_b = MockProvider("b", RpcStateResponse(provider="b", key=key, value=value, proof=verified_response.proof))
    provider_c = MockProvider(
        "c",
        RpcStateResponse(provider="c", key=key, value=(1).to_bytes(32, "big"), proof=None),
    )

    engine = RedundantQueryEngine([provider_a, provider_b, provider_c], min_agreement=2)
    result = engine.query_verified_value(key, policy)

    assert result.value == value
    assert result.agreed_providers == ("a", "b")
    assert result.checked_providers == ("a", "b", "c")


def test_redundant_query_engine_rejects_without_verified_agreement():
    key, value, rh, _ = _build_verified_response(provider="a")
    policy = LocalVerificationPolicy(rh)

    p1 = MockProvider("a", RpcStateResponse(provider="a", key=key, value=value, proof=None))
    p2 = MockProvider("b", RpcStateResponse(provider="b", key=key, value=value, proof=None))

    engine = RedundantQueryEngine([p1, p2], min_agreement=2)
    with pytest.raises(UnverifiedResponseError):
        engine.query_verified_value(key, policy)


def test_privacy_service_redundant_mode_uses_multi_provider_result():
    key, value, rh, verified_response = _build_verified_response(provider="a")
    policy = LocalVerificationPolicy(rh)
    engine = RedundantQueryEngine(
        [
            MockProvider("a", verified_response),
            MockProvider("b", RpcStateResponse(provider="b", key=key, value=value, proof=verified_response.proof)),
        ],
        min_agreement=2,
    )
    service = PrivacyQueryService(engine, policy, mode=PrivacyMode.REDUNDANT)
    assert service.query_state_key(key).value == value


def test_smart_account_timelock_and_guardian_cancel_flow():
    account = SmartAccount(
        owner="owner",
        guardians={"g1", "g2", "g3"},
        large_transfer_threshold=100,
        timelock_seconds=24 * 60 * 60,
    )

    transfer = account.schedule_transfer(to=b"dest", amount=150, now=0)
    with pytest.raises(ValueError):
        account.execute_transfer(transfer.transfer_id, now=60)

    account.cancel_transfer(transfer.transfer_id, actor="g1")
    with pytest.raises(ValueError):
        account.execute_transfer(transfer.transfer_id, now=10**6)


def test_smart_account_recovery_requires_quorum():
    account = SmartAccount(
        owner="owner",
        guardians={"g1", "g2", "g3"},
        large_transfer_threshold=100,
    )

    with pytest.raises(PermissionError):
        account.recover_owner("new_owner", approvals={"g1"})

    account.recover_owner("new_owner", approvals={"g1", "g2"})
    assert account.owner == "new_owner"
