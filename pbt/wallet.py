"""Wallet/client-side policy primitives for local verification and privacy.

These classes encode default behaviors required by the spec notes:
- local proof verification before trusted use
- explicit unverified mode for unchecked responses
- redundant multi-provider query baseline
- account-abstraction style social recovery and transfer time-lock defaults
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Protocol

from .tree import MerkleProof, verify_proof


class VerificationStatus(str, Enum):
    VERIFIED = "verified"
    UNVERIFIED = "unverified"


class UIMode(str, Enum):
    NORMAL = "normal"
    UNVERIFIED = "unverified"


@dataclass(frozen=True)
class RpcStateResponse:
    provider: str
    key: bytes
    value: bytes
    proof: MerkleProof | None


@dataclass(frozen=True)
class VerifiedStateView:
    provider: str
    key: bytes
    value: bytes
    status: VerificationStatus
    ui_mode: UIMode


class UnverifiedResponseError(RuntimeError):
    pass


class LocalVerificationPolicy:
    """Policy gate that forces local proof verification for trusted use."""

    def __init__(self, root_hash: bytes):
        self.root_hash = root_hash

    def classify(self, response: RpcStateResponse) -> VerifiedStateView:
        is_verified = response.proof is not None and verify_proof(self.root_hash, response.proof)
        status = VerificationStatus.VERIFIED if is_verified else VerificationStatus.UNVERIFIED
        ui_mode = UIMode.NORMAL if is_verified else UIMode.UNVERIFIED
        return VerifiedStateView(
            provider=response.provider,
            key=response.key,
            value=response.value,
            status=status,
            ui_mode=ui_mode,
        )

    def require_verified(self, response: RpcStateResponse) -> VerifiedStateView:
        view = self.classify(response)
        if view.status != VerificationStatus.VERIFIED:
            raise UnverifiedResponseError(
                "response is unverified; wallet/client must remain in explicit unverified mode"
            )
        return view


class QueryProvider(Protocol):
    name: str

    def query(self, key: bytes) -> RpcStateResponse:
        """Return provider response for the requested key."""


@dataclass(frozen=True)
class RedundantQueryResult:
    value: bytes
    agreed_providers: tuple[str, ...]
    checked_providers: tuple[str, ...]


class RedundantQueryEngine:
    """Redundant multi-provider query baseline: no single provider is trusted."""

    def __init__(self, providers: list[QueryProvider], min_agreement: int = 2):
        if len(providers) < 2:
            raise ValueError("at least two providers are required for redundant querying")
        if min_agreement < 2:
            raise ValueError("min_agreement must be >= 2")
        self.providers = providers
        self.min_agreement = min_agreement

    def query_verified_value(self, key: bytes, policy: LocalVerificationPolicy) -> RedundantQueryResult:
        buckets: dict[bytes, list[str]] = {}
        checked: list[str] = []

        for provider in self.providers:
            response = provider.query(key)
            checked.append(provider.name)
            view = policy.classify(response)
            if view.status == VerificationStatus.VERIFIED:
                buckets.setdefault(view.value, []).append(provider.name)

        if not buckets:
            raise UnverifiedResponseError("no provider returned a locally verified response")

        winner_value, winner_providers = max(buckets.items(), key=lambda pair: len(pair[1]))
        if len(winner_providers) < self.min_agreement:
            raise UnverifiedResponseError(
                "insufficient cross-provider agreement among locally verified responses"
            )

        return RedundantQueryResult(
            value=winner_value,
            agreed_providers=tuple(sorted(winner_providers)),
            checked_providers=tuple(sorted(checked)),
        )


class PrivateQueryBackend(Protocol):
    def query_balance(self, address: bytes) -> bytes:
        ...

    def query_history(self, address: bytes) -> list[bytes]:
        ...


class PrivacyMode(str, Enum):
    REDUNDANT = "redundant"
    PIR = "pir"
    ORAM = "oram"


class PrivacyQueryService:
    """Selects redundant baseline and optional PIR/ORAM backends."""

    def __init__(
        self,
        redundant_engine: RedundantQueryEngine,
        policy: LocalVerificationPolicy,
        mode: PrivacyMode = PrivacyMode.REDUNDANT,
        backend: PrivateQueryBackend | None = None,
    ):
        self.redundant_engine = redundant_engine
        self.policy = policy
        self.mode = mode
        self.backend = backend

    def _require_backend(self) -> PrivateQueryBackend:
        if self.backend is None:
            raise ValueError("selected privacy mode requires a backend")
        return self.backend

    def query_state_key(self, key: bytes) -> RedundantQueryResult:
        return self.redundant_engine.query_verified_value(key, self.policy)

    def query_balance(self, address: bytes, key: bytes) -> bytes:
        if self.mode == PrivacyMode.REDUNDANT:
            return self.query_state_key(key).value
        return self._require_backend().query_balance(address)

    def query_history(self, address: bytes, key: bytes) -> list[bytes]:
        if self.mode == PrivacyMode.REDUNDANT:
            return [self.query_state_key(key).value]
        return self._require_backend().query_history(address)


@dataclass
class PendingTransfer:
    transfer_id: int
    to: bytes
    amount: int
    created_at: int
    execute_after: int
    canceled: bool = False
    executed: bool = False


class SmartAccount:
    """Account-abstraction style defaults: guardians + timelock for large sends."""

    def __init__(
        self,
        owner: str,
        guardians: set[str],
        large_transfer_threshold: int,
        timelock_seconds: int = 24 * 60 * 60,
        recovery_quorum: int | None = None,
    ):
        if not guardians:
            raise ValueError("guardians are required")
        if owner in guardians:
            raise ValueError("owner cannot be a guardian")
        if large_transfer_threshold <= 0:
            raise ValueError("large_transfer_threshold must be positive")
        if timelock_seconds < 24 * 60 * 60:
            raise ValueError("timelock_seconds must be at least 24h")

        self.owner = owner
        self.guardians = set(guardians)
        self.large_transfer_threshold = large_transfer_threshold
        self.timelock_seconds = timelock_seconds
        self.recovery_quorum = recovery_quorum or max(1, len(guardians) // 2 + 1)
        self.pending_transfers: dict[int, PendingTransfer] = {}
        self._next_transfer_id = 1

    def schedule_transfer(self, to: bytes, amount: int, now: int) -> PendingTransfer:
        if amount <= 0:
            raise ValueError("amount must be positive")
        delay = self.timelock_seconds if amount >= self.large_transfer_threshold else 0
        transfer = PendingTransfer(
            transfer_id=self._next_transfer_id,
            to=to,
            amount=amount,
            created_at=now,
            execute_after=now + delay,
        )
        self.pending_transfers[transfer.transfer_id] = transfer
        self._next_transfer_id += 1
        return transfer

    def cancel_transfer(self, transfer_id: int, actor: str) -> None:
        if actor != self.owner and actor not in self.guardians:
            raise PermissionError("only owner or guardian can cancel a transfer")
        transfer = self.pending_transfers[transfer_id]
        if transfer.executed:
            raise ValueError("cannot cancel an executed transfer")
        transfer.canceled = True

    def execute_transfer(self, transfer_id: int, now: int) -> PendingTransfer:
        transfer = self.pending_transfers[transfer_id]
        if transfer.canceled:
            raise ValueError("transfer was canceled")
        if transfer.executed:
            raise ValueError("transfer already executed")
        if now < transfer.execute_after:
            raise ValueError("timelock not yet expired")
        transfer.executed = True
        return transfer

    def recover_owner(self, new_owner: str, approvals: set[str]) -> None:
        if len(approvals & self.guardians) < self.recovery_quorum:
            raise PermissionError("insufficient guardian approvals for recovery")
        if new_owner in self.guardians:
            raise ValueError("new owner cannot be a guardian")
        self.owner = new_owner
