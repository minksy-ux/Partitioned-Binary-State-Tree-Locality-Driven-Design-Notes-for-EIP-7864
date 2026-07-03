"""Privacy-respecting stem subscription primitive for EIP-7864.

This module defines a light, verifiable, and privacy-preserving subscription
protocol for stem witness delivery:

- On-chain registration stores only a commitment and operational limits.
- Witnesses are distributed in epoch buckets rather than per-wallet channels.
- Wallets fetch target buckets plus cover buckets, avoiding stem disclosure.
- Every delivered packet is locally verifiable against a known block root.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Callable, Iterable

from .constants import (
    METADATA_ARCHIVAL_TIER_SUBINDEX,
    METADATA_EXPIRY_EPOCH_SUBINDEX,
    METADATA_FLAGS_SUBINDEX,
    METADATA_HOT_COLD_SUBINDEX,
)
from .hash import tree_hash
from .tree import MerkleProof, split_key, verify_proof


WIRE_VERSION_V1 = 1


@dataclass(frozen=True)
class SubscriptionRegistration:
    """On-chain registration payload with no explicit stem identifiers."""

    commitment: bytes
    window_start_epoch: int
    window_end_epoch: int
    max_buckets_per_epoch: int
    encryption_pubkey: bytes


@dataclass(frozen=True)
class InterestCommitment:
    """Short-lived non-interactive privacy-preserving interest commitment."""

    commitment: bytes
    scheme: str
    key_epoch: int
    valid_from_epoch: int
    valid_until_epoch: int


@dataclass
class EphemeralStateLens:
    """Short-lived private view over an exact stem subset.

    A lens is intended to support partial statelessness workflows where a
    wallet derives a tiny, temporary state view for only the stems needed for
    a near-term operation, then discards it.
    """

    stem_prefixes: tuple[bytes, ...]
    created_epoch: int
    expires_at_epoch: int
    lens_commitment: bytes
    remaining_uses: int | None = None
    disposed: bool = False

    def is_active(self, current_epoch: int) -> bool:
        if current_epoch < 0:
            raise ValueError("current_epoch must be non-negative")
        if self.disposed:
            return False
        if self.remaining_uses is not None and self.remaining_uses <= 0:
            return False
        return self.created_epoch <= current_epoch <= self.expires_at_epoch

    def consume(self, current_epoch: int, uses: int = 1) -> bool:
        """Consume lens usage quota and auto-discard when exhausted.

        Returns True if consumption was applied, otherwise False when lens is
        already inactive.
        """
        if uses <= 0:
            raise ValueError("uses must be positive")
        if not self.is_active(current_epoch):
            return False
        if self.remaining_uses is None:
            return True

        self.remaining_uses = max(0, self.remaining_uses - uses)
        if self.remaining_uses == 0:
            self.discard()
        return True

    def discard(self) -> None:
        self.stem_prefixes = ()
        self.disposed = True


@dataclass(frozen=True)
class WitnessBundle:
    """Encrypted per-block witness bundle posted by a provider."""

    epoch: int
    block_number: int
    block_root: bytes
    provider_id: bytes
    bundle_commitment: bytes
    encrypted_blob_hash: bytes
    packet_commitments: tuple[bytes, ...]
    storage_locator_hash: bytes = b""


@dataclass(frozen=True)
class ProviderSLA:
    """Provider signed service-level agreement for witness delivery."""

    provider_id: bytes
    valid_from_epoch: int
    valid_until_epoch: int
    max_latency_slots: int
    min_availability_bps: int
    signature: bytes


@dataclass
class BondPosition:
    """Optional bonded position for SLA-backed service guarantees."""

    wallet_id: bytes
    provider_id: bytes
    bond_amount: int
    slashable: int


@dataclass(frozen=True)
class LocalVerificationResult:
    """Decision returned by local verification clients."""

    accepted: bool
    reason: str


@dataclass(frozen=True)
class StemWitnessPacket:
    """Witness packet delivered by distributors for one key in a stem bucket."""

    epoch: int
    block_number: int
    block_root: bytes
    stem_prefix: bytes
    key: bytes
    value: bytes
    proof: MerkleProof
    bucket_id: int

    def commitment(self) -> bytes:
        return packet_commitment_v1(self)


@dataclass(frozen=True)
class BucketManifest:
    """Published commitment list for an epoch bucket."""

    epoch: int
    bucket_id: int
    packet_commitments: tuple[bytes, ...]
    packets_root: bytes


@dataclass(frozen=True)
class StemFetchPlan:
    """Concrete epoch-scoped fetch plan for a client session."""

    epoch: int
    target_buckets: tuple[int, ...]
    fetch_buckets: tuple[int, ...]
    provider_ids: tuple[bytes, ...]


@dataclass(frozen=True)
class StemFetchPolicy:
    """Operational policy for realistic private stem retrieval."""

    bucket_count: int = 64
    cover_count: int = 2
    required_provider_matches: int = 2
    provider_redundancy: int = 1
    max_epoch_lag: int = 2
    max_future_epoch_skew: int = 0

    def __post_init__(self):
        if self.bucket_count <= 0:
            raise ValueError("bucket_count must be positive")
        if self.cover_count < 0:
            raise ValueError("cover_count must be non-negative")
        if self.required_provider_matches <= 0:
            raise ValueError("required_provider_matches must be positive")
        if self.provider_redundancy < 0:
            raise ValueError("provider_redundancy must be non-negative")
        if self.max_epoch_lag < 0:
            raise ValueError("max_epoch_lag must be non-negative")
        if self.max_future_epoch_skew < 0:
            raise ValueError("max_future_epoch_skew must be non-negative")

    def plan_fetch(
        self,
        target_stems: list[bytes],
        epoch: int,
        secret_seed: bytes,
        global_salt: bytes,
        available_provider_ids: list[bytes],
    ) -> StemFetchPlan:
        """Build one fetch plan combining bucket privacy and provider diversity."""
        target_buckets = {
            bucket_for_stem(
                stem_prefix=stem,
                epoch=epoch,
                bucket_count=self.bucket_count,
                global_salt=global_salt,
            )
            for stem in target_stems
        }
        fetch_buckets = build_cover_bucket_set(
            target_buckets=target_buckets,
            cover_count=self.cover_count,
            epoch=epoch,
            secret_seed=secret_seed,
            bucket_count=self.bucket_count,
        )
        providers = select_redundant_providers(
            available_provider_ids=available_provider_ids,
            epoch=epoch,
            secret_seed=secret_seed,
            required_count=self.required_provider_matches,
            extra_count=self.provider_redundancy,
        )
        return StemFetchPlan(
            epoch=epoch,
            target_buckets=tuple(sorted(target_buckets)),
            fetch_buckets=tuple(fetch_buckets),
            provider_ids=tuple(providers),
        )

    def evaluate_response(
        self,
        packets: list[StemWitnessPacket],
        provider_ids: list[bytes],
        expected_block_root: bytes,
        current_epoch: int,
    ) -> LocalVerificationResult:
        """Evaluate a redundant response set under freshness + quorum constraints."""
        fresh_packets: list[StemWitnessPacket] = []
        fresh_provider_ids: list[bytes] = []
        for packet, provider_id in zip(packets, provider_ids):
            if verify_packet_freshness(
                packet,
                current_epoch=current_epoch,
                max_epoch_lag=self.max_epoch_lag,
                max_future_epoch_skew=self.max_future_epoch_skew,
            ):
                fresh_packets.append(packet)
                fresh_provider_ids.append(provider_id)

        if len(fresh_packets) < self.required_provider_matches:
            return LocalVerificationResult(False, "insufficient fresh packets for quorum")

        ok = verify_redundant_packet_set(
            packets=fresh_packets,
            provider_ids=fresh_provider_ids,
            required_matches=self.required_provider_matches,
            expected_block_root=expected_block_root,
        )
        if not ok:
            return LocalVerificationResult(False, "redundant provider agreement failed")
        return LocalVerificationResult(True, "fresh redundant quorum locally verified")


@dataclass(frozen=True)
class ProviderTelemetry:
    """Per-provider reliability counters used for adaptive fetch policy tuning."""

    attempts: int = 0
    successes: int = 0
    proof_failures: int = 0
    stale_failures: int = 0
    other_failures: int = 0
    consecutive_failures: int = 0

    @property
    def success_rate(self) -> float:
        if self.attempts == 0:
            return 1.0
        return self.successes / self.attempts


@dataclass(frozen=True)
class ProviderPrivacyMetric:
    """Session-level leakage metric over provider-observed query events."""

    total_queries: int
    unique_providers: int
    dominant_provider_id: bytes | None
    dominant_provider_share: float
    provider_hhi: float
    single_provider_full_interest: bool


def derive_ephemeral_state_lens(
    target_stems: Iterable[bytes],
    wallet_secret: bytes,
    current_epoch: int,
    ttl_epochs: int = 1,
    scope_tag: bytes = b"",
    max_uses: int | None = None,
) -> EphemeralStateLens:
    """Derive a short-lived private stem lens for local verification flows."""
    if current_epoch < 0:
        raise ValueError("current_epoch must be non-negative")
    if ttl_epochs <= 0:
        raise ValueError("ttl_epochs must be positive")
    if max_uses is not None and max_uses <= 0:
        raise ValueError("max_uses must be positive when provided")

    stems = tuple(sorted(set(target_stems)))
    expires_at_epoch = current_epoch + ttl_epochs - 1
    commitment = tree_hash(
        b"pbt-ephemeral-lens-v1"
        + wallet_secret
        + current_epoch.to_bytes(8, "big")
        + ttl_epochs.to_bytes(4, "big")
        + (max_uses or 0).to_bytes(4, "big")
        + scope_tag
        + b"".join(stems)
    )
    return EphemeralStateLens(
        stem_prefixes=stems,
        created_epoch=current_epoch,
        expires_at_epoch=expires_at_epoch,
        lens_commitment=commitment,
        remaining_uses=max_uses,
    )


def filter_packets_by_ephemeral_lens(
    lens: EphemeralStateLens,
    packets: Iterable[StemWitnessPacket],
    current_epoch: int,
) -> list[StemWitnessPacket]:
    """Select only packets that belong to an active lens stem subset."""
    if not lens.is_active(current_epoch):
        return []
    allowed = set(lens.stem_prefixes)
    return [packet for packet in packets if packet.stem_prefix in allowed]


class ProviderReliabilityTracker:
    """Tracks provider outcomes and exposes simple reliability views."""

    def __init__(self):
        self._stats: dict[bytes, ProviderTelemetry] = {}

    def _get(self, provider_id: bytes) -> ProviderTelemetry:
        return self._stats.get(provider_id, ProviderTelemetry())

    def record_result(self, provider_id: bytes, accepted: bool, reason: str = "") -> None:
        stats = self._get(provider_id)
        proof_failures = stats.proof_failures
        stale_failures = stats.stale_failures
        other_failures = stats.other_failures

        if accepted:
            updated = ProviderTelemetry(
                attempts=stats.attempts + 1,
                successes=stats.successes + 1,
                proof_failures=proof_failures,
                stale_failures=stale_failures,
                other_failures=other_failures,
                consecutive_failures=0,
            )
        else:
            if "proof" in reason:
                proof_failures += 1
            elif "fresh" in reason or "stale" in reason:
                stale_failures += 1
            else:
                other_failures += 1
            updated = ProviderTelemetry(
                attempts=stats.attempts + 1,
                successes=stats.successes,
                proof_failures=proof_failures,
                stale_failures=stale_failures,
                other_failures=other_failures,
                consecutive_failures=stats.consecutive_failures + 1,
            )
        self._stats[provider_id] = updated

    def snapshot(self) -> dict[bytes, ProviderTelemetry]:
        return dict(self._stats)

    def average_success_rate(self, provider_ids: Iterable[bytes]) -> float:
        ids = list(provider_ids)
        if not ids:
            return 1.0
        rates = [self._get(pid).success_rate for pid in ids]
        return sum(rates) / len(rates)

    def max_consecutive_failures(self, provider_ids: Iterable[bytes]) -> int:
        return max((self._get(pid).consecutive_failures for pid in provider_ids), default=0)


def measure_query_pattern_leakage(
    provider_observations: Iterable[bytes],
    full_interest_threshold: float = 0.8,
) -> ProviderPrivacyMetric:
    """Measure how concentrated query visibility is across providers.

    The metric is intended for policy checks such as:
    "common flows SHOULD NOT leak a full interest pattern to one provider".
    """
    if not (0.0 < full_interest_threshold <= 1.0):
        raise ValueError("full_interest_threshold must be in (0, 1]")

    counts: dict[bytes, int] = {}
    total = 0
    for provider_id in provider_observations:
        total += 1
        counts[provider_id] = counts.get(provider_id, 0) + 1

    if total == 0:
        return ProviderPrivacyMetric(
            total_queries=0,
            unique_providers=0,
            dominant_provider_id=None,
            dominant_provider_share=0.0,
            provider_hhi=0.0,
            single_provider_full_interest=False,
        )

    dominant_provider_id = max(counts, key=counts.get)
    dominant_count = counts[dominant_provider_id]
    dominant_share = dominant_count / total
    hhi = sum((count / total) ** 2 for count in counts.values())

    return ProviderPrivacyMetric(
        total_queries=total,
        unique_providers=len(counts),
        dominant_provider_id=dominant_provider_id,
        dominant_provider_share=dominant_share,
        provider_hhi=hhi,
        single_provider_full_interest=dominant_share >= full_interest_threshold,
    )


def tune_policy_from_reliability(
    base_policy: StemFetchPolicy,
    tracker: ProviderReliabilityTracker,
    provider_ids: Iterable[bytes],
    min_success_rate: float = 0.7,
    failure_streak_threshold: int = 2,
    max_extra_cover: int = 8,
    max_extra_redundancy: int = 8,
) -> StemFetchPolicy:
    """Adapt cover and redundancy based on provider reliability observations."""
    if not (0.0 < min_success_rate <= 1.0):
        raise ValueError("min_success_rate must be in (0, 1]")
    if failure_streak_threshold <= 0:
        raise ValueError("failure_streak_threshold must be positive")

    avg_rate = tracker.average_success_rate(provider_ids)
    max_streak = tracker.max_consecutive_failures(provider_ids)

    cover = base_policy.cover_count
    redundancy = base_policy.provider_redundancy

    if avg_rate < min_success_rate:
        cover += 1
        redundancy += 1
    if max_streak >= failure_streak_threshold:
        cover += 1
        redundancy += 1

    cover = min(cover, base_policy.cover_count + max_extra_cover)
    redundancy = min(redundancy, base_policy.provider_redundancy + max_extra_redundancy)

    return replace(
        base_policy,
        cover_count=cover,
        provider_redundancy=redundancy,
    )


def simulate_epoch_fetch_with_fallback(
    base_policy: StemFetchPolicy,
    target_stems: list[bytes],
    epoch: int,
    secret_seed: bytes,
    global_salt: bytes,
    available_provider_ids: list[bytes],
    expected_block_root: bytes,
    current_epoch: int,
    fetch_fn: Callable[[StemFetchPlan], tuple[list[StemWitnessPacket], list[bytes]]],
    max_attempts: int = 3,
    reliability_tracker: ProviderReliabilityTracker | None = None,
    adaptive_tuning: bool = True,
    tuning_min_success_rate: float = 0.7,
    tuning_failure_streak_threshold: int = 2,
) -> tuple[LocalVerificationResult, StemFetchPlan, int]:
    """Run one wallet epoch fetch with retry and adaptive fallback.

    If `adaptive_tuning` is enabled, retry policy widening is driven by live
    per-provider telemetry; otherwise fixed widening (+1 cover/+1 redundancy)
    is used for backward-compatible behavior.
    Returns (result, plan_used, attempts_taken).
    """
    if max_attempts <= 0:
        raise ValueError("max_attempts must be positive")

    policy = base_policy
    last_plan = policy.plan_fetch(
        target_stems=target_stems,
        epoch=epoch,
        secret_seed=secret_seed,
        global_salt=global_salt,
        available_provider_ids=available_provider_ids,
    )
    last_result = LocalVerificationResult(False, "no attempts executed")
    tracker = reliability_tracker if reliability_tracker is not None else ProviderReliabilityTracker()

    for attempt in range(1, max_attempts + 1):
        last_plan = policy.plan_fetch(
            target_stems=target_stems,
            epoch=epoch,
            secret_seed=secret_seed,
            global_salt=global_salt,
            available_provider_ids=available_provider_ids,
        )
        packets, provider_ids = fetch_fn(last_plan)
        last_result = policy.evaluate_response(
            packets=packets,
            provider_ids=provider_ids,
            expected_block_root=expected_block_root,
            current_epoch=current_epoch,
        )
        if last_result.accepted:
            return last_result, last_plan, attempt

        responding_providers = set(provider_ids)
        for packet, provider_id in zip(packets, provider_ids):
            if packet.block_root != expected_block_root:
                tracker.record_result(provider_id, accepted=False, reason="root mismatch")
                continue
            if not verify_packet_freshness(
                packet,
                current_epoch=current_epoch,
                max_epoch_lag=policy.max_epoch_lag,
                max_future_epoch_skew=policy.max_future_epoch_skew,
            ):
                tracker.record_result(provider_id, accepted=False, reason="stale response")
                continue
            if not verify_witness_packet(packet):
                tracker.record_result(provider_id, accepted=False, reason="proof verification failed")
                continue
            tracker.record_result(provider_id, accepted=True, reason="ok")

        for provider_id in last_plan.provider_ids:
            if provider_id not in responding_providers:
                tracker.record_result(provider_id, accepted=False, reason="missing response")

        if attempt == max_attempts:
            break

        if adaptive_tuning:
            policy = tune_policy_from_reliability(
                base_policy=policy,
                tracker=tracker,
                provider_ids=last_plan.provider_ids,
                min_success_rate=tuning_min_success_rate,
                failure_streak_threshold=tuning_failure_streak_threshold,
            )
        else:
            policy = replace(
                policy,
                cover_count=policy.cover_count + 1,
                provider_redundancy=policy.provider_redundancy + 1,
            )

    return last_result, last_plan, max_attempts


class StatelessStemClient:
    """Local-verification-first client for stateless stem access."""

    def __init__(self, verified_block_root: bytes):
        self.verified_block_root = verified_block_root

    def verify_packet(self, packet: StemWitnessPacket) -> LocalVerificationResult:
        if packet.block_root != self.verified_block_root:
            return LocalVerificationResult(False, "packet block root is not locally trusted")
        if not verify_witness_packet(packet):
            return LocalVerificationResult(False, "packet proof verification failed")
        return LocalVerificationResult(True, "packet locally verified")


class PartiallyStatelessStemClient(StatelessStemClient):
    """Local-verification-first client with a rolling hot-stem cache."""

    def __init__(self, verified_block_root: bytes):
        super().__init__(verified_block_root)
        self._stem_cache: dict[bytes, list[bytes]] = {}

    def verify_and_cache_packet(self, packet: StemWitnessPacket) -> LocalVerificationResult:
        result = self.verify_packet(packet)
        if not result.accepted:
            return result
        self._stem_cache[packet.stem_prefix] = list(packet.proof.stem_values)
        return LocalVerificationResult(True, "packet locally verified and cached")

    def cached_value(self, key: bytes) -> bytes | None:
        stem_prefix, subindex = split_key(key)
        values = self._stem_cache.get(stem_prefix)
        if values is None:
            return None
        return values[subindex]


def select_redundant_providers(
    available_provider_ids: list[bytes],
    epoch: int,
    secret_seed: bytes,
    required_count: int,
    extra_count: int = 0,
) -> list[bytes]:
    """Deterministically choose a diversified provider subset for one epoch."""
    if epoch < 0:
        raise ValueError("epoch must be non-negative")
    if required_count <= 0:
        raise ValueError("required_count must be positive")
    if extra_count < 0:
        raise ValueError("extra_count must be non-negative")

    deduped = sorted(set(available_provider_ids))
    if len(deduped) < required_count:
        raise ValueError("insufficient providers for required_count")

    scored: list[tuple[bytes, bytes]] = []
    for provider_id in deduped:
        score = tree_hash(
            b"pbt-provider-select-v1"
            + secret_seed
            + epoch.to_bytes(8, "big")
            + provider_id
        )
        scored.append((score, provider_id))

    scored.sort()
    take = min(len(scored), required_count + extra_count)
    return [provider_id for _, provider_id in scored[:take]]


def verify_packet_freshness(
    packet: StemWitnessPacket,
    current_epoch: int,
    max_epoch_lag: int = 2,
    max_future_epoch_skew: int = 0,
) -> bool:
    """Validate packet freshness bounds for replay/staleness resistance."""
    if current_epoch < 0:
        return False
    if max_epoch_lag < 0:
        return False
    if max_future_epoch_skew < 0:
        return False
    if packet.epoch > current_epoch + max_future_epoch_skew:
        return False
    if current_epoch - packet.epoch > max_epoch_lag:
        return False
    return True


def verify_redundant_packet_set(
    packets: list[StemWitnessPacket],
    provider_ids: list[bytes],
    required_matches: int,
    expected_block_root: bytes,
) -> bool:
    """Verify cross-provider agreement and local proof validity.

    A packet set is acceptable when at least `required_matches` distinct providers
    return locally valid packets that agree on key/value/block root.
    """
    if required_matches <= 0:
        raise ValueError("required_matches must be positive")
    if len(packets) != len(provider_ids):
        raise ValueError("packets/provider_ids length mismatch")

    agreeing: dict[tuple[bytes, bytes, bytes], set[bytes]] = {}
    for packet, provider_id in zip(packets, provider_ids):
        if packet.block_root != expected_block_root:
            continue
        if not verify_witness_packet(packet):
            continue

        fingerprint = (packet.key, packet.value, packet.block_root)
        providers = agreeing.setdefault(fingerprint, set())
        providers.add(provider_id)
        if len(providers) >= required_matches:
            return True
    return False


def _hash_concat(items: Iterable[bytes]) -> bytes:
    current = tree_hash(b"")
    for item in items:
        current = tree_hash(current + item)
    return current


def _pack_u16_len(data: bytes) -> bytes:
    if len(data) > 0xFFFF:
        raise ValueError("field too large for u16 length prefix")
    return len(data).to_bytes(2, "big") + data


def _pack_u32_len(data: bytes) -> bytes:
    if len(data) > 0xFFFFFFFF:
        raise ValueError("field too large for u32 length prefix")
    return len(data).to_bytes(4, "big") + data


def _read_exact(blob: bytes, offset: int, size: int) -> tuple[bytes, int]:
    if offset + size > len(blob):
        raise ValueError("truncated payload")
    return blob[offset : offset + size], offset + size


def _read_u16_len(blob: bytes, offset: int) -> tuple[bytes, int]:
    raw_len, offset = _read_exact(blob, offset, 2)
    size = int.from_bytes(raw_len, "big")
    return _read_exact(blob, offset, size)


def _read_u32_len(blob: bytes, offset: int) -> tuple[bytes, int]:
    raw_len, offset = _read_exact(blob, offset, 4)
    size = int.from_bytes(raw_len, "big")
    return _read_exact(blob, offset, size)


def _metadata_subindices() -> set[int]:
    return {
        METADATA_EXPIRY_EPOCH_SUBINDEX,
        METADATA_HOT_COLD_SUBINDEX,
        METADATA_ARCHIVAL_TIER_SUBINDEX,
        METADATA_FLAGS_SUBINDEX,
    }


def _encode_proof_blob(proof: MerkleProof) -> bytes:
    if len(proof.value) != 32:
        raise ValueError("proof value must be 32 bytes")
    if len(proof.stem_values) != 256:
        raise ValueError("stem_values_count must be 256")
    if len(proof.path_siblings) != len(proof.path_bits):
        raise ValueError("siblings_count must equal path_bits_count")
    if any(bit not in (0, 1) for bit in proof.path_bits):
        raise ValueError("path_bits entries must be 0 or 1")
    if any(len(v) != 32 for v in proof.stem_values):
        raise ValueError("all stem values must be 32 bytes")
    if any(len(s) != 32 for s in proof.path_siblings):
        raise ValueError("all sibling hashes must be 32 bytes")

    out = bytearray()
    out.extend(_pack_u16_len(proof.key))
    out.extend(proof.value)
    out.extend((256).to_bytes(2, "big"))
    for value in proof.stem_values:
        out.extend(value)
    out.extend(len(proof.path_siblings).to_bytes(2, "big"))
    for sibling in proof.path_siblings:
        out.extend(sibling)
    out.extend(len(proof.path_bits).to_bytes(2, "big"))
    for bit in proof.path_bits:
        out.append(bit)
    return bytes(out)


def _decode_proof_blob(blob: bytes) -> MerkleProof:
    offset = 0
    proof_key, offset = _read_u16_len(blob, offset)
    proof_value, offset = _read_exact(blob, offset, 32)

    stem_count_raw, offset = _read_exact(blob, offset, 2)
    stem_values_count = int.from_bytes(stem_count_raw, "big")
    if stem_values_count != 256:
        raise ValueError("stem_values_count must be 256")
    stem_values: list[bytes] = []
    for _ in range(stem_values_count):
        value, offset = _read_exact(blob, offset, 32)
        stem_values.append(value)

    siblings_count_raw, offset = _read_exact(blob, offset, 2)
    siblings_count = int.from_bytes(siblings_count_raw, "big")
    siblings: list[bytes] = []
    for _ in range(siblings_count):
        sibling, offset = _read_exact(blob, offset, 32)
        siblings.append(sibling)

    path_bits_count_raw, offset = _read_exact(blob, offset, 2)
    path_bits_count = int.from_bytes(path_bits_count_raw, "big")
    if siblings_count != path_bits_count:
        raise ValueError("siblings_count must equal path_bits_count")
    path_bits: list[int] = []
    for _ in range(path_bits_count):
        bit_raw, offset = _read_exact(blob, offset, 1)
        bit = bit_raw[0]
        if bit not in (0, 1):
            raise ValueError("path_bits entries must be 0 or 1")
        path_bits.append(bit)

    if offset != len(blob):
        raise ValueError("truncated payload")

    return MerkleProof(
        key=proof_key,
        value=proof_value,
        stem_values=stem_values,
        path_siblings=siblings,
        path_bits=path_bits,
    )


def _packet_payload_without_commitment(packet: StemWitnessPacket) -> bytes:
    if len(packet.block_root) != 32:
        raise ValueError("block_root must be 32 bytes")
    if len(packet.value) != 32:
        raise ValueError("value must be 32 bytes")
    if packet.epoch < 0 or packet.block_number < 0 or packet.bucket_id < 0:
        raise ValueError("numeric packet fields must be non-negative")

    proof_blob = _encode_proof_blob(packet.proof)
    return (
        bytes([WIRE_VERSION_V1])
        + packet.epoch.to_bytes(8, "big")
        + packet.block_number.to_bytes(8, "big")
        + packet.block_root
        + packet.bucket_id.to_bytes(4, "big")
        + _pack_u16_len(packet.stem_prefix)
        + _pack_u16_len(packet.key)
        + packet.value
        + _pack_u32_len(proof_blob)
    )


def packet_commitment_v1(packet: StemWitnessPacket) -> bytes:
    """Commit over every STEM_PKT_V1 field except packet_commitment."""
    return tree_hash(_packet_payload_without_commitment(packet))


def encode_subscription_registration_v1(registration: SubscriptionRegistration) -> bytes:
    """Encode SUB_REG_V1 record."""
    if len(registration.commitment) != 32:
        raise ValueError("commitment must be 32 bytes")
    if registration.window_end_epoch < registration.window_start_epoch:
        raise ValueError("window_end_epoch must be >= window_start_epoch")
    if not (0 <= registration.max_buckets_per_epoch <= 0xFFFFFFFF):
        raise ValueError("max_buckets_per_epoch out of range")

    return (
        bytes([WIRE_VERSION_V1])
        + registration.commitment
        + registration.window_start_epoch.to_bytes(8, "big")
        + registration.window_end_epoch.to_bytes(8, "big")
        + registration.max_buckets_per_epoch.to_bytes(4, "big")
        + _pack_u16_len(registration.encryption_pubkey)
    )


def decode_subscription_registration_v1(blob: bytes) -> SubscriptionRegistration:
    """Decode and validate SUB_REG_V1 record."""
    offset = 0
    version_raw, offset = _read_exact(blob, offset, 1)
    version = version_raw[0]
    if version != WIRE_VERSION_V1:
        raise ValueError("unknown version")

    commitment, offset = _read_exact(blob, offset, 32)
    window_start_raw, offset = _read_exact(blob, offset, 8)
    window_end_raw, offset = _read_exact(blob, offset, 8)
    max_buckets_raw, offset = _read_exact(blob, offset, 4)
    encryption_pubkey, offset = _read_u16_len(blob, offset)
    if offset != len(blob):
        raise ValueError("truncated payload")

    window_start_epoch = int.from_bytes(window_start_raw, "big")
    window_end_epoch = int.from_bytes(window_end_raw, "big")
    max_buckets_per_epoch = int.from_bytes(max_buckets_raw, "big")
    if window_end_epoch < window_start_epoch:
        raise ValueError("window_end_epoch must be >= window_start_epoch")

    return SubscriptionRegistration(
        commitment=commitment,
        window_start_epoch=window_start_epoch,
        window_end_epoch=window_end_epoch,
        max_buckets_per_epoch=max_buckets_per_epoch,
        encryption_pubkey=encryption_pubkey,
    )


def encode_stem_witness_packet_v1(packet: StemWitnessPacket) -> bytes:
    """Encode STEM_PKT_V1 record."""
    payload = _packet_payload_without_commitment(packet)
    return payload + packet_commitment_v1(packet)


def decode_stem_witness_packet_v1(blob: bytes) -> StemWitnessPacket:
    """Decode and validate STEM_PKT_V1 record."""
    offset = 0
    version_raw, offset = _read_exact(blob, offset, 1)
    version = version_raw[0]
    if version != WIRE_VERSION_V1:
        raise ValueError("unknown version")

    epoch_raw, offset = _read_exact(blob, offset, 8)
    block_number_raw, offset = _read_exact(blob, offset, 8)
    block_root, offset = _read_exact(blob, offset, 32)
    bucket_id_raw, offset = _read_exact(blob, offset, 4)
    stem_prefix, offset = _read_u16_len(blob, offset)
    key, offset = _read_u16_len(blob, offset)
    value, offset = _read_exact(blob, offset, 32)
    proof_blob, offset = _read_u32_len(blob, offset)
    packet_commitment, offset = _read_exact(blob, offset, 32)
    if offset != len(blob):
        raise ValueError("truncated payload")

    proof = _decode_proof_blob(proof_blob)
    if proof.key != key:
        raise ValueError("proof_key != key")
    if proof.value != value:
        raise ValueError("proof_value != value")

    packet = StemWitnessPacket(
        epoch=int.from_bytes(epoch_raw, "big"),
        block_number=int.from_bytes(block_number_raw, "big"),
        block_root=block_root,
        stem_prefix=stem_prefix,
        key=key,
        value=value,
        proof=proof,
        bucket_id=int.from_bytes(bucket_id_raw, "big"),
    )

    expected_commitment = packet_commitment_v1(packet)
    if expected_commitment != packet_commitment:
        raise ValueError("packet_commitment mismatch")
    return packet


def encode_bucket_manifest_v1(manifest: BucketManifest) -> bytes:
    """Encode BUCKET_MANIFEST_V1 record."""
    if manifest.epoch < 0 or manifest.bucket_id < 0:
        raise ValueError("manifest numeric fields must be non-negative")
    if len(manifest.packets_root) != 32:
        raise ValueError("packets_root must be 32 bytes")
    if any(len(commitment) != 32 for commitment in manifest.packet_commitments):
        raise ValueError("packet commitments must be 32 bytes")

    packet_count = len(manifest.packet_commitments)
    if packet_count > 0xFFFFFFFF:
        raise ValueError("packet_count out of range")

    out = bytearray()
    out.extend(bytes([WIRE_VERSION_V1]))
    out.extend(manifest.epoch.to_bytes(8, "big"))
    out.extend(manifest.bucket_id.to_bytes(4, "big"))
    out.extend(packet_count.to_bytes(4, "big"))
    for commitment in manifest.packet_commitments:
        out.extend(commitment)
    out.extend(manifest.packets_root)
    return bytes(out)


def decode_bucket_manifest_v1(blob: bytes) -> BucketManifest:
    """Decode and validate BUCKET_MANIFEST_V1 record."""
    offset = 0
    version_raw, offset = _read_exact(blob, offset, 1)
    version = version_raw[0]
    if version != WIRE_VERSION_V1:
        raise ValueError("unknown version")

    epoch_raw, offset = _read_exact(blob, offset, 8)
    bucket_id_raw, offset = _read_exact(blob, offset, 4)
    packet_count_raw, offset = _read_exact(blob, offset, 4)
    packet_count = int.from_bytes(packet_count_raw, "big")

    commitments: list[bytes] = []
    for _ in range(packet_count):
        commitment, offset = _read_exact(blob, offset, 32)
        commitments.append(commitment)

    packets_root, offset = _read_exact(blob, offset, 32)
    if offset != len(blob):
        raise ValueError("truncated payload")

    manifest = BucketManifest(
        epoch=int.from_bytes(epoch_raw, "big"),
        bucket_id=int.from_bytes(bucket_id_raw, "big"),
        packet_commitments=tuple(commitments),
        packets_root=packets_root,
    )
    if not verify_bucket_manifest(manifest):
        raise ValueError("packets_root mismatch")
    return manifest


def make_subscription_commitment(
    secret_seed: bytes,
    wallet_pubkey: bytes,
    window_start_epoch: int,
    window_end_epoch: int,
    max_buckets_per_epoch: int,
) -> bytes:
    """Create commitment for on-chain subscription registration.

    Commitment intentionally excludes stem identifiers to preserve interest privacy.
    """
    if window_end_epoch < window_start_epoch:
        raise ValueError("window_end_epoch must be >= window_start_epoch")
    if max_buckets_per_epoch <= 0:
        raise ValueError("max_buckets_per_epoch must be positive")

    payload = (
        b"pbt-sub-v1"
        + secret_seed
        + wallet_pubkey
        + window_start_epoch.to_bytes(8, "big")
        + window_end_epoch.to_bytes(8, "big")
        + max_buckets_per_epoch.to_bytes(4, "big")
    )
    return tree_hash(payload)


def rotate_ephemeral_key(seed: bytes, epoch: int) -> bytes:
    """Derive an epoch-scoped ephemeral key from a long-lived seed."""
    if epoch < 0:
        raise ValueError("epoch must be non-negative")
    return tree_hash(b"pbt-ephemeral-k-v1" + seed + epoch.to_bytes(8, "big"))


def make_keyed_bloom_interest_digest(
    stems: list[bytes],
    keyed_secret: bytes,
    m_bits: int = 2048,
    k_hashes: int = 5,
) -> bytes:
    """Build keyed Bloom-style interest digest over stem prefixes.

    The resulting digest can be committed on-chain without exposing stems.
    """
    if m_bits <= 0 or m_bits % 8 != 0:
        raise ValueError("m_bits must be a positive multiple of 8")
    if k_hashes <= 0:
        raise ValueError("k_hashes must be positive")
    bitset = bytearray(m_bits // 8)

    for stem in stems:
        for i in range(k_hashes):
            digest = tree_hash(
                b"pbt-interest-bloom-v1" + keyed_secret + i.to_bytes(2, "big") + stem
            )
            idx = int.from_bytes(digest[:8], "big") % m_bits
            bitset[idx // 8] |= 1 << (idx % 8)

    return tree_hash(bytes(bitset))


def make_accumulator_interest_digest(stems: list[bytes], keyed_secret: bytes) -> bytes:
    """Build keyed accumulator digest over stem prefixes."""
    entries = sorted(tree_hash(b"pbt-acc-entry-v1" + keyed_secret + stem) for stem in stems)
    return _hash_concat(entries)


def make_interest_commitment(
    keyed_interest_digest: bytes,
    ephemeral_pubkey: bytes,
    scheme: str,
    key_epoch: int,
    valid_from_epoch: int,
    valid_until_epoch: int,
) -> InterestCommitment:
    """Create short-lived on-chain interest commitment record."""
    if valid_until_epoch < valid_from_epoch:
        raise ValueError("valid_until_epoch must be >= valid_from_epoch")
    if not (1 <= (valid_until_epoch - valid_from_epoch + 1) <= 7):
        raise ValueError("commitment window must be 1-7 epochs")
    if key_epoch < 0:
        raise ValueError("key_epoch must be non-negative")
    if scheme not in {"keyed_bloom", "keyed_accumulator"}:
        raise ValueError("unsupported interest scheme")

    commitment = tree_hash(
        b"pbt-interest-commit-v1"
        + scheme.encode("ascii")
        + key_epoch.to_bytes(8, "big")
        + valid_from_epoch.to_bytes(8, "big")
        + valid_until_epoch.to_bytes(8, "big")
        + ephemeral_pubkey
        + keyed_interest_digest
    )
    return InterestCommitment(
        commitment=commitment,
        scheme=scheme,
        key_epoch=key_epoch,
        valid_from_epoch=valid_from_epoch,
        valid_until_epoch=valid_until_epoch,
    )


def derive_epoch_nullifier(secret_seed: bytes, epoch: int) -> bytes:
    """Derive unlinkable epoch nullifier for anti-replay/rate-limiting."""
    if epoch < 0:
        raise ValueError("epoch must be non-negative")
    return tree_hash(b"pbt-nullifier-v1" + secret_seed + epoch.to_bytes(8, "big"))


def bucket_for_stem(
    stem_prefix: bytes,
    epoch: int,
    bucket_count: int,
    global_salt: bytes,
) -> int:
    """Map stem to distribution bucket for a given epoch."""
    if bucket_count <= 0:
        raise ValueError("bucket_count must be positive")
    if epoch < 0:
        raise ValueError("epoch must be non-negative")
    digest = tree_hash(
        b"pbt-bucket-v1" + global_salt + epoch.to_bytes(8, "big") + stem_prefix
    )
    return int.from_bytes(digest[:8], "big") % bucket_count


def build_cover_bucket_set(
    target_buckets: set[int],
    cover_count: int,
    epoch: int,
    secret_seed: bytes,
    bucket_count: int,
) -> list[int]:
    """Select target + deterministic cover buckets for privacy-preserving fetches."""
    if cover_count < 0:
        raise ValueError("cover_count must be non-negative")
    if bucket_count <= 0:
        raise ValueError("bucket_count must be positive")
    if any(bucket < 0 or bucket >= bucket_count for bucket in target_buckets):
        raise ValueError("target bucket out of range")

    selected = set(target_buckets)
    nonce = 0
    while len(selected) < len(target_buckets) + cover_count:
        candidate_digest = tree_hash(
            b"pbt-cover-v1"
            + secret_seed
            + epoch.to_bytes(8, "big")
            + nonce.to_bytes(4, "big")
        )
        candidate = int.from_bytes(candidate_digest[:8], "big") % bucket_count
        selected.add(candidate)
        nonce += 1
        if len(selected) == bucket_count:
            break

    return sorted(selected)


def build_bucket_manifest(
    epoch: int,
    bucket_id: int,
    packets: list[StemWitnessPacket],
) -> BucketManifest:
    """Create manifest commitment for packets in one bucket."""
    for packet in packets:
        if packet.epoch != epoch:
            raise ValueError("packet epoch mismatch")
        if packet.bucket_id != bucket_id:
            raise ValueError("packet bucket mismatch")
    commitments = tuple(sorted(packet.commitment() for packet in packets))
    root = _hash_concat(commitments)
    return BucketManifest(
        epoch=epoch,
        bucket_id=bucket_id,
        packet_commitments=commitments,
        packets_root=root,
    )


def verify_bucket_manifest(manifest: BucketManifest) -> bool:
    """Verify manifest commitment integrity."""
    return _hash_concat(manifest.packet_commitments) == manifest.packets_root


def verify_witness_packet(packet: StemWitnessPacket) -> bool:
    """Verify packet proof and stem consistency against block root."""
    stem_prefix, _ = split_key(packet.key)
    if stem_prefix != packet.stem_prefix:
        return False
    if packet.proof.key != packet.key:
        return False
    if packet.proof.value != packet.value:
        return False
    return verify_proof(packet.block_root, packet.proof)


def is_reserved_metadata_packet(packet: StemWitnessPacket) -> bool:
    """Return True when a packet key targets a reserved metadata leaf."""
    _, subindex = split_key(packet.key)
    return subindex in _metadata_subindices()


def build_witness_bundle(
    epoch: int,
    block_number: int,
    block_root: bytes,
    provider_id: bytes,
    encrypted_blob_hash: bytes,
    packet_commitments: tuple[bytes, ...],
    storage_locator_hash: bytes = b"",
) -> WitnessBundle:
    """Build encrypted witness bundle commitment record."""
    commitments = tuple(sorted(packet_commitments))
    bundle_commitment = tree_hash(
        b"pbt-bundle-v1"
        + epoch.to_bytes(8, "big")
        + block_number.to_bytes(8, "big")
        + block_root
        + provider_id
        + encrypted_blob_hash
        + _hash_concat(commitments)
        + storage_locator_hash
    )
    return WitnessBundle(
        epoch=epoch,
        block_number=block_number,
        block_root=block_root,
        provider_id=provider_id,
        bundle_commitment=bundle_commitment,
        encrypted_blob_hash=encrypted_blob_hash,
        packet_commitments=commitments,
        storage_locator_hash=storage_locator_hash,
    )


def verify_witness_bundle(bundle: WitnessBundle) -> bool:
    """Verify bundle commitment integrity."""
    expected = build_witness_bundle(
        epoch=bundle.epoch,
        block_number=bundle.block_number,
        block_root=bundle.block_root,
        provider_id=bundle.provider_id,
        encrypted_blob_hash=bundle.encrypted_blob_hash,
        packet_commitments=bundle.packet_commitments,
        storage_locator_hash=bundle.storage_locator_hash,
    )
    return expected.bundle_commitment == bundle.bundle_commitment


def verify_provider_sla(sla: ProviderSLA, current_epoch: int) -> bool:
    """Basic SLA validation helper.

    Signature verification is left to chain/client-specific cryptography.
    """
    if sla.valid_until_epoch < sla.valid_from_epoch:
        return False
    if not (sla.valid_from_epoch <= current_epoch <= sla.valid_until_epoch):
        return False
    if sla.max_latency_slots <= 0:
        return False
    if not (0 <= sla.min_availability_bps <= 10000):
        return False
    if len(sla.signature) == 0:
        return False
    return True


class OptionalSLARegistry:
    """Minimal optional bond/slashing model for SLA-backed witness delivery."""

    def __init__(self):
        self._positions: dict[tuple[bytes, bytes], BondPosition] = {}

    def stake(self, wallet_id: bytes, provider_id: bytes, bond_amount: int) -> BondPosition:
        if bond_amount <= 0:
            raise ValueError("bond_amount must be positive")
        key = (wallet_id, provider_id)
        position = BondPosition(
            wallet_id=wallet_id,
            provider_id=provider_id,
            bond_amount=bond_amount,
            slashable=bond_amount,
        )
        self._positions[key] = position
        return position

    def slash_for_missed_delivery(
        self,
        wallet_id: bytes,
        provider_id: bytes,
        penalty: int,
    ) -> BondPosition:
        if penalty <= 0:
            raise ValueError("penalty must be positive")
        key = (wallet_id, provider_id)
        if key not in self._positions:
            raise KeyError("no bond position found")
        pos = self._positions[key]
        pos.slashable = max(0, pos.slashable - penalty)
        return pos

    def get_position(self, wallet_id: bytes, provider_id: bytes) -> BondPosition | None:
        return self._positions.get((wallet_id, provider_id))
