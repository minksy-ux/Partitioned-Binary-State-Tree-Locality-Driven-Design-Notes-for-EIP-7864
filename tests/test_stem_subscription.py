"""Tests for privacy-respecting stem subscription primitive."""

import sys
import os
import pytest
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from pbt.nodes import EmptyNode
from pbt.tree import get_proof, insert, root_hash
from pbt.stem_subscription import (
    InterestCommitment,
    EphemeralStateLens,
    StemWitnessPacket,
    ProviderSLA,
    SubscriptionRegistration,
    StemFetchPolicy,
    ProviderReliabilityTracker,
    ProviderPrivacyMetric,
    StatelessStemClient,
    PartiallyStatelessStemClient,
    OptionalSLARegistry,
    encode_subscription_registration_v1,
    decode_subscription_registration_v1,
    encode_stem_witness_packet_v1,
    decode_stem_witness_packet_v1,
    encode_bucket_manifest_v1,
    decode_bucket_manifest_v1,
    is_reserved_metadata_packet,
    select_redundant_providers,
    verify_packet_freshness,
    verify_redundant_packet_set,
    measure_query_pattern_leakage,
    tune_policy_from_reliability,
    simulate_epoch_fetch_with_fallback,
    make_subscription_commitment,
    derive_ephemeral_state_lens,
    filter_packets_by_ephemeral_lens,
    derive_epoch_nullifier,
    rotate_ephemeral_key,
    make_keyed_bloom_interest_digest,
    make_accumulator_interest_digest,
    make_interest_commitment,
    bucket_for_stem,
    build_cover_bucket_set,
    build_bucket_manifest,
    verify_bucket_manifest,
    verify_witness_packet,
    build_witness_bundle,
    verify_witness_bundle,
    verify_provider_sla,
)


def test_commitment_does_not_depend_on_stem_ids():
    seed = b"seed"
    pubkey = b"wallet-pk"
    c1 = make_subscription_commitment(seed, pubkey, 1, 10, 8)
    c2 = make_subscription_commitment(seed, pubkey, 1, 10, 8)
    assert c1 == c2


def test_epoch_nullifier_changes_per_epoch():
    seed = b"seed"
    n1 = derive_epoch_nullifier(seed, 1)
    n2 = derive_epoch_nullifier(seed, 2)
    assert n1 != n2


def test_ephemeral_key_rotation_changes_per_epoch():
    seed = b"seed"
    k1 = rotate_ephemeral_key(seed, 3)
    k2 = rotate_ephemeral_key(seed, 4)
    assert k1 != k2


def test_interest_commitment_window_is_short_lived():
    digest = make_keyed_bloom_interest_digest([b"\x00" + bytes(32)], b"k")
    c = make_interest_commitment(
        keyed_interest_digest=digest,
        ephemeral_pubkey=b"epk",
        scheme="keyed_bloom",
        key_epoch=11,
        valid_from_epoch=11,
        valid_until_epoch=13,
    )
    assert isinstance(c, InterestCommitment)


def test_ephemeral_state_lens_derivation_is_scoped_private_and_temporary():
    stems = [b"\x00" + bytes([0x10] * 32), b"\x00" + bytes([0x11] * 32)]
    lens1 = derive_ephemeral_state_lens(
        target_stems=stems,
        wallet_secret=b"wallet-secret",
        current_epoch=21,
        ttl_epochs=2,
        scope_tag=b"swap",
    )
    lens2 = derive_ephemeral_state_lens(
        target_stems=stems,
        wallet_secret=b"wallet-secret",
        current_epoch=22,
        ttl_epochs=2,
        scope_tag=b"swap",
    )

    assert isinstance(lens1, EphemeralStateLens)
    assert lens1.stem_prefixes == tuple(sorted(stems))
    assert lens1.is_active(21)
    assert lens1.is_active(22)
    assert not lens1.is_active(23)
    assert lens1.lens_commitment != lens2.lens_commitment


def test_ephemeral_state_lens_discard_clears_view():
    lens = derive_ephemeral_state_lens(
        target_stems=[b"\x00" + bytes([0x22] * 32)],
        wallet_secret=b"wallet-secret",
        current_epoch=5,
        ttl_epochs=3,
    )

    assert lens.is_active(5)
    lens.discard()
    assert lens.disposed
    assert lens.stem_prefixes == ()
    assert not lens.is_active(5)


def test_ephemeral_state_lens_one_time_burns_after_consume():
    lens = derive_ephemeral_state_lens(
        target_stems=[b"\x00" + bytes([0x33] * 32)],
        wallet_secret=b"wallet-secret",
        current_epoch=8,
        ttl_epochs=3,
        max_uses=1,
    )

    assert lens.is_active(8)
    assert lens.remaining_uses == 1
    assert lens.consume(current_epoch=8)
    assert lens.disposed
    assert lens.stem_prefixes == ()
    assert lens.remaining_uses == 0
    assert not lens.is_active(8)


def test_ephemeral_state_lens_bounded_use_counter_decrements():
    lens = derive_ephemeral_state_lens(
        target_stems=[b"\x00" + bytes([0x44] * 32)],
        wallet_secret=b"wallet-secret",
        current_epoch=14,
        ttl_epochs=3,
        max_uses=2,
    )

    assert lens.consume(current_epoch=14)
    assert lens.remaining_uses == 1
    assert lens.is_active(14)

    assert lens.consume(current_epoch=14)
    assert lens.remaining_uses == 0
    assert lens.disposed
    assert not lens.is_active(14)


def test_bucket_mapping_is_deterministic():
    stem = b"\x00" + bytes([0x11] * 32)
    b1 = bucket_for_stem(stem, epoch=5, bucket_count=64, global_salt=b"salt")
    b2 = bucket_for_stem(stem, epoch=5, bucket_count=64, global_salt=b"salt")
    assert b1 == b2


def test_cover_set_contains_targets_and_cover():
    targets = {1, 2}
    cover = build_cover_bucket_set(
        target_buckets=targets,
        cover_count=3,
        epoch=9,
        secret_seed=b"seed",
        bucket_count=32,
    )
    assert all(t in cover for t in targets)
    assert len(cover) >= len(targets)


def _build_packet() -> StemWitnessPacket:
    key = bytes([0]) + bytes([0xAA] * 32) + bytes([7])
    value = (777).to_bytes(32, "big")
    root = insert(EmptyNode(), key, value)
    proof = get_proof(root, key)
    return StemWitnessPacket(
        epoch=1,
        block_number=100,
        block_root=root_hash(root),
        stem_prefix=key[:-1],
        key=key,
        value=value,
        proof=proof,
        bucket_id=3,
    )


def test_packet_verification_passes_for_valid_packet():
    packet = _build_packet()
    assert verify_witness_packet(packet)


def test_packet_verification_fails_for_wrong_stem_prefix():
    packet = _build_packet()
    bad = StemWitnessPacket(
        epoch=packet.epoch,
        block_number=packet.block_number,
        block_root=packet.block_root,
        stem_prefix=b"\xff" + packet.stem_prefix[1:],
        key=packet.key,
        value=packet.value,
        proof=packet.proof,
        bucket_id=packet.bucket_id,
    )
    assert not verify_witness_packet(bad)


def test_bucket_manifest_verification_round_trip():
    packet = _build_packet()
    manifest = build_bucket_manifest(packet.epoch, packet.bucket_id, [packet])
    assert verify_bucket_manifest(manifest)


def test_bundle_commitment_verification_round_trip():
    packet = _build_packet()
    bundle = build_witness_bundle(
        epoch=packet.epoch,
        block_number=packet.block_number,
        block_root=packet.block_root,
        provider_id=b"provider-a",
        encrypted_blob_hash=b"x" * 32,
        packet_commitments=(packet.commitment(),),
        storage_locator_hash=b"locator" * 4,
    )
    assert verify_witness_bundle(bundle)


def test_decode_stem_witness_packet_rejects_oversized_packet_wire():
    packet = _build_packet()
    encoded = encode_stem_witness_packet_v1(packet)
    oversized = encoded + (b"\x00" * (262145 - len(encoded)))
    with pytest.raises(ValueError, match="packet wire exceeds configured maximum"):
        decode_stem_witness_packet_v1(oversized)


def test_decode_bucket_manifest_rejects_excessive_packet_count():
    # version + epoch + bucket_id + packet_count
    blob = (
        b"\x01"
        + (0).to_bytes(8, "big")
        + (0).to_bytes(4, "big")
        + (16385).to_bytes(4, "big")
    )
    with pytest.raises(ValueError, match="packet_count exceeds configured maximum"):
        decode_bucket_manifest_v1(blob)


def test_sla_registry_stake_and_slash():
    reg = OptionalSLARegistry()
    pos = reg.stake(wallet_id=b"w", provider_id=b"p", bond_amount=100)
    assert pos.slashable == 100
    pos2 = reg.slash_for_missed_delivery(wallet_id=b"w", provider_id=b"p", penalty=30)
    assert pos2.slashable == 70


def test_provider_sla_validation():
    sla = ProviderSLA(
        provider_id=b"p",
        valid_from_epoch=10,
        valid_until_epoch=20,
        max_latency_slots=4,
        min_availability_bps=9900,
        signature=b"sig",
    )
    assert verify_provider_sla(sla, current_epoch=15)


def test_interest_digest_accumulator_deterministic():
    stems = [b"\x00" + bytes([0x01] * 32), b"\x00" + bytes([0x02] * 32)]
    d1 = make_accumulator_interest_digest(stems, b"key")
    d2 = make_accumulator_interest_digest(list(reversed(stems)), b"key")
    assert d1 == d2


def test_subscription_registration_wire_round_trip():
    reg = SubscriptionRegistration(
        commitment=b"c" * 32,
        window_start_epoch=10,
        window_end_epoch=20,
        max_buckets_per_epoch=64,
        encryption_pubkey=b"epk",
    )
    encoded = encode_subscription_registration_v1(reg)
    decoded = decode_subscription_registration_v1(encoded)
    assert decoded == reg


def test_packet_wire_round_trip_and_validation():
    packet = _build_packet()
    encoded = encode_stem_witness_packet_v1(packet)
    decoded = decode_stem_witness_packet_v1(encoded)
    assert decoded == packet
    assert verify_witness_packet(decoded)


def test_packet_wire_rejects_commitment_mismatch():
    packet = _build_packet()
    encoded = bytearray(encode_stem_witness_packet_v1(packet))
    encoded[-1] ^= 0x01
    with pytest.raises(ValueError, match="packet_commitment mismatch"):
        decode_stem_witness_packet_v1(bytes(encoded))


def test_manifest_wire_round_trip():
    packet = _build_packet()
    manifest = build_bucket_manifest(packet.epoch, packet.bucket_id, [packet])
    encoded = encode_bucket_manifest_v1(manifest)
    decoded = decode_bucket_manifest_v1(encoded)
    assert decoded == manifest


def test_stateless_client_requires_locally_trusted_root():
    packet = _build_packet()
    client = StatelessStemClient(verified_block_root=packet.block_root)
    ok = client.verify_packet(packet)
    assert ok.accepted

    wrong_client = StatelessStemClient(verified_block_root=b"z" * 32)
    bad = wrong_client.verify_packet(packet)
    assert not bad.accepted


def test_partially_stateless_client_caches_verified_stem_values():
    packet = _build_packet()
    client = PartiallyStatelessStemClient(verified_block_root=packet.block_root)
    result = client.verify_and_cache_packet(packet)
    assert result.accepted
    assert client.cached_value(packet.key) == packet.value


def _build_packet_with_stem_marker(marker: int) -> StemWitnessPacket:
    key = bytes([0]) + bytes([marker] * 32) + bytes([1])
    value = marker.to_bytes(32, "big")
    root = insert(EmptyNode(), key, value)
    proof = get_proof(root, key)
    return StemWitnessPacket(
        epoch=1,
        block_number=100,
        block_root=root_hash(root),
        stem_prefix=key[:-1],
        key=key,
        value=value,
        proof=proof,
        bucket_id=3,
    )


def test_partially_stateless_hot_stem_cache_uses_lru_eviction():
    p1 = _build_packet_with_stem_marker(0x11)
    p2 = _build_packet_with_stem_marker(0x22)
    p3 = _build_packet_with_stem_marker(0x33)

    client = PartiallyStatelessStemClient(verified_block_root=p1.block_root, max_cached_stems=2)
    assert client.verify_and_cache_packet(p1).accepted

    client.set_verified_block_root(p2.block_root, clear_cache=False)
    assert client.verify_and_cache_packet(p2).accepted

    client.set_verified_block_root(p3.block_root, clear_cache=False)
    assert client.verify_and_cache_packet(p3).accepted

    # p1 should be evicted as the least-recently-used stem.
    client.set_verified_block_root(p1.block_root, clear_cache=False)
    assert client.cached_value(p1.key) is None

    client.set_verified_block_root(p2.block_root, clear_cache=False)
    assert client.cached_value(p2.key) == p2.value
    client.set_verified_block_root(p3.block_root, clear_cache=False)
    assert client.cached_value(p3.key) == p3.value


def test_partially_stateless_hot_stem_cache_read_refreshes_lru_order():
    p1 = _build_packet_with_stem_marker(0x44)
    p2 = _build_packet_with_stem_marker(0x55)
    p3 = _build_packet_with_stem_marker(0x66)

    client = PartiallyStatelessStemClient(verified_block_root=p1.block_root, max_cached_stems=2)
    assert client.verify_and_cache_packet(p1).accepted

    client.set_verified_block_root(p2.block_root, clear_cache=False)
    assert client.verify_and_cache_packet(p2).accepted

    # Touch p1 so p2 becomes least-recently-used.
    client.set_verified_block_root(p1.block_root, clear_cache=False)
    assert client.cached_value(p1.key) == p1.value

    client.set_verified_block_root(p3.block_root, clear_cache=False)
    assert client.verify_and_cache_packet(p3).accepted

    # p2 should be evicted; p1 should remain due to refresh.
    client.set_verified_block_root(p2.block_root, clear_cache=False)
    assert client.cached_value(p2.key) is None
    client.set_verified_block_root(p1.block_root, clear_cache=False)
    assert client.cached_value(p1.key) == p1.value


def test_partially_stateless_cache_clears_on_root_rotation_by_default():
    packet = _build_packet()
    client = PartiallyStatelessStemClient(verified_block_root=packet.block_root)
    assert client.verify_and_cache_packet(packet).accepted
    assert client.cached_value(packet.key) == packet.value

    client.set_verified_block_root(b"z" * 32)
    assert client.cached_value(packet.key) is None


def test_partially_stateless_cache_stats_track_hit_and_miss():
    packet = _build_packet()
    client = PartiallyStatelessStemClient(verified_block_root=packet.block_root)
    assert client.verify_and_cache_packet(packet).accepted

    assert client.cached_value(packet.key) == packet.value
    missing_key = bytes([0]) + bytes([0xFE] * 32) + bytes([1])
    assert client.cached_value(missing_key) is None

    stats = client.cache_stats()
    assert stats["cache_hits"] == 1
    assert stats["cache_misses"] == 1
    assert stats["cached_stems"] == 1
    assert stats["max_cached_stems"] == 128


def test_reserved_metadata_packet_detection():
    key = bytes([0]) + bytes([0xBB] * 32) + bytes([240])
    value = (123).to_bytes(32, "big")
    root = insert(EmptyNode(), key, value)
    proof = get_proof(root, key)
    packet = StemWitnessPacket(
        epoch=2,
        block_number=200,
        block_root=root_hash(root),
        stem_prefix=key[:-1],
        key=key,
        value=value,
        proof=proof,
        bucket_id=5,
    )
    assert is_reserved_metadata_packet(packet)


def test_select_redundant_providers_is_deterministic_and_sized():
    providers = [b"p1", b"p2", b"p3", b"p4"]
    s1 = select_redundant_providers(providers, epoch=8, secret_seed=b"seed", required_count=2, extra_count=1)
    s2 = select_redundant_providers(providers, epoch=8, secret_seed=b"seed", required_count=2, extra_count=1)
    assert s1 == s2
    assert len(s1) == 3
    assert len(set(s1)) == 3


def test_packet_freshness_accepts_recent_and_rejects_stale_or_future():
    packet = _build_packet()
    recent = StemWitnessPacket(
        epoch=10,
        block_number=packet.block_number,
        block_root=packet.block_root,
        stem_prefix=packet.stem_prefix,
        key=packet.key,
        value=packet.value,
        proof=packet.proof,
        bucket_id=packet.bucket_id,
    )
    assert verify_packet_freshness(recent, current_epoch=11, max_epoch_lag=2)
    assert not verify_packet_freshness(recent, current_epoch=14, max_epoch_lag=2)
    assert not verify_packet_freshness(recent, current_epoch=8, max_future_epoch_skew=0)


def test_redundant_packet_set_requires_distinct_provider_agreement():
    packet = _build_packet()
    ok = verify_redundant_packet_set(
        packets=[packet, packet],
        provider_ids=[b"p1", b"p2"],
        required_matches=2,
        expected_block_root=packet.block_root,
    )
    assert ok

    not_ok_same_provider = verify_redundant_packet_set(
        packets=[packet, packet],
        provider_ids=[b"p1", b"p1"],
        required_matches=2,
        expected_block_root=packet.block_root,
    )
    assert not not_ok_same_provider

    wrong_root = verify_redundant_packet_set(
        packets=[packet, packet],
        provider_ids=[b"p1", b"p2"],
        required_matches=2,
        expected_block_root=b"z" * 32,
    )
    assert not wrong_root


def test_fetch_policy_plan_includes_targets_cover_and_provider_redundancy():
    policy = StemFetchPolicy(
        bucket_count=64,
        cover_count=2,
        required_provider_matches=2,
        provider_redundancy=1,
    )
    stems = [b"\x00" + bytes([0x10] * 32), b"\x00" + bytes([0x11] * 32)]
    plan = policy.plan_fetch(
        target_stems=stems,
        epoch=7,
        secret_seed=b"seed",
        global_salt=b"salt",
        available_provider_ids=[b"p1", b"p2", b"p3", b"p4"],
    )
    assert len(plan.target_buckets) >= 1
    assert all(bucket in plan.fetch_buckets for bucket in plan.target_buckets)
    assert len(plan.provider_ids) == 3


def test_fetch_policy_response_evaluation_requires_fresh_quorum():
    policy = StemFetchPolicy(required_provider_matches=2, max_epoch_lag=2)
    packet = _build_packet()
    fresh_packet = StemWitnessPacket(
        epoch=10,
        block_number=packet.block_number,
        block_root=packet.block_root,
        stem_prefix=packet.stem_prefix,
        key=packet.key,
        value=packet.value,
        proof=packet.proof,
        bucket_id=packet.bucket_id,
    )

    ok = policy.evaluate_response(
        packets=[fresh_packet, fresh_packet],
        provider_ids=[b"p1", b"p2"],
        expected_block_root=fresh_packet.block_root,
        current_epoch=11,
    )
    assert ok.accepted

    stale = policy.evaluate_response(
        packets=[fresh_packet, fresh_packet],
        provider_ids=[b"p1", b"p2"],
        expected_block_root=fresh_packet.block_root,
        current_epoch=20,
    )
    assert not stale.accepted


def test_simulate_epoch_fetch_with_fallback_succeeds_after_retry():
    policy = StemFetchPolicy(
        bucket_count=32,
        cover_count=1,
        required_provider_matches=2,
        provider_redundancy=0,
    )
    packet = _build_packet()

    attempts = {"n": 0}

    def fetch_fn(_plan):
        attempts["n"] += 1
        if attempts["n"] == 1:
            return [packet], [b"p1"]
        return [packet, packet], [b"p1", b"p2"]

    result, plan, used_attempts = simulate_epoch_fetch_with_fallback(
        base_policy=policy,
        target_stems=[packet.stem_prefix],
        epoch=packet.epoch,
        secret_seed=b"seed",
        global_salt=b"salt",
        available_provider_ids=[b"p1", b"p2", b"p3"],
        expected_block_root=packet.block_root,
        current_epoch=packet.epoch,
        fetch_fn=fetch_fn,
        max_attempts=3,
    )

    assert result.accepted
    assert used_attempts == 2
    assert len(plan.provider_ids) >= 2


def test_simulate_epoch_fetch_with_fallback_returns_last_failure():
    policy = StemFetchPolicy(required_provider_matches=2)
    packet = _build_packet()

    def fetch_fn(_plan):
        return [packet], [b"p1"]

    result, _plan, used_attempts = simulate_epoch_fetch_with_fallback(
        base_policy=policy,
        target_stems=[packet.stem_prefix],
        epoch=packet.epoch,
        secret_seed=b"seed",
        global_salt=b"salt",
        available_provider_ids=[b"p1", b"p2", b"p3"],
        expected_block_root=packet.block_root,
        current_epoch=packet.epoch,
        fetch_fn=fetch_fn,
        max_attempts=2,
    )

    assert not result.accepted
    assert used_attempts == 2


def test_provider_reliability_tracker_updates_rates_and_streaks():
    tracker = ProviderReliabilityTracker()
    tracker.record_result(b"p1", accepted=False, reason="proof verification failed")
    tracker.record_result(b"p1", accepted=False, reason="stale response")
    tracker.record_result(b"p1", accepted=True, reason="ok")

    stats = tracker.snapshot()[b"p1"]
    assert stats.attempts == 3
    assert stats.successes == 1
    assert stats.proof_failures == 1
    assert stats.stale_failures == 1
    assert stats.consecutive_failures == 0


def test_tune_policy_from_reliability_increases_cover_and_redundancy_on_low_reliability():
    base = StemFetchPolicy(cover_count=1, provider_redundancy=0)
    tracker = ProviderReliabilityTracker()
    tracker.record_result(b"p1", accepted=False, reason="proof verification failed")
    tracker.record_result(b"p2", accepted=False, reason="quorum failed")

    tuned = tune_policy_from_reliability(
        base_policy=base,
        tracker=tracker,
        provider_ids=[b"p1", b"p2"],
        min_success_rate=0.8,
        failure_streak_threshold=2,
    )
    assert tuned.cover_count > base.cover_count
    assert tuned.provider_redundancy > base.provider_redundancy


def test_simulate_epoch_fetch_uses_adaptive_tuning_from_live_failures():
    policy = StemFetchPolicy(required_provider_matches=1, provider_redundancy=0, cover_count=0)
    packet = _build_packet()
    tracker = ProviderReliabilityTracker()
    provider_counts: list[int] = []

    def fetch_fn(plan):
        provider_counts.append(len(plan.provider_ids))
        # No responses forces tracker to record missing provider failures.
        return [], []

    result, _plan, attempts = simulate_epoch_fetch_with_fallback(
        base_policy=policy,
        target_stems=[packet.stem_prefix],
        epoch=packet.epoch,
        secret_seed=b"seed",
        global_salt=b"salt",
        available_provider_ids=[b"p1", b"p2", b"p3"],
        expected_block_root=packet.block_root,
        current_epoch=packet.epoch,
        fetch_fn=fetch_fn,
        max_attempts=2,
        reliability_tracker=tracker,
        adaptive_tuning=True,
        tuning_min_success_rate=0.95,
        tuning_failure_streak_threshold=1,
    )

    assert not result.accepted
    assert attempts == 2
    assert provider_counts[0] == 1
    assert provider_counts[1] > provider_counts[0]


def test_simulate_epoch_fetch_adaptive_tuning_recovers_on_retry():
    policy = StemFetchPolicy(required_provider_matches=1, provider_redundancy=0, cover_count=0)
    packet = _build_packet()
    attempt = 0
    provider_counts: list[int] = []

    def fetch_fn(plan):
        nonlocal attempt
        attempt += 1
        provider_counts.append(len(plan.provider_ids))
        if attempt == 1:
            return [], []
        return [packet], [plan.provider_ids[0]]

    result, _plan, attempts = simulate_epoch_fetch_with_fallback(
        base_policy=policy,
        target_stems=[packet.stem_prefix],
        epoch=packet.epoch,
        secret_seed=b"seed",
        global_salt=b"salt",
        available_provider_ids=[b"p1", b"p2", b"p3"],
        expected_block_root=packet.block_root,
        current_epoch=packet.epoch,
        fetch_fn=fetch_fn,
        max_attempts=3,
        adaptive_tuning=True,
    )

    assert result.accepted
    assert attempts == 2
    assert provider_counts[0] == 1
    assert provider_counts[1] > provider_counts[0]


def test_simulate_epoch_fetch_uses_fixed_widening_when_adaptive_disabled():
    policy = StemFetchPolicy(required_provider_matches=1, provider_redundancy=0, cover_count=0)
    packet = _build_packet()
    provider_counts: list[int] = []

    def fetch_fn(plan):
        provider_counts.append(len(plan.provider_ids))
        return [], []

    result, _plan, attempts = simulate_epoch_fetch_with_fallback(
        base_policy=policy,
        target_stems=[packet.stem_prefix],
        epoch=packet.epoch,
        secret_seed=b"seed",
        global_salt=b"salt",
        available_provider_ids=[b"p1", b"p2", b"p3"],
        expected_block_root=packet.block_root,
        current_epoch=packet.epoch,
        fetch_fn=fetch_fn,
        max_attempts=2,
        adaptive_tuning=False,
    )

    assert not result.accepted
    assert attempts == 2
    assert provider_counts == [1, 2]


def test_filter_packets_by_ephemeral_lens_returns_only_selected_stems():
    p1 = _build_packet()

    key2 = bytes([0]) + bytes([0xDD] * 32) + bytes([3])
    root2 = insert(EmptyNode(), key2, (333).to_bytes(32, "big"))
    p2 = StemWitnessPacket(
        epoch=1,
        block_number=101,
        block_root=root_hash(root2),
        stem_prefix=key2[:-1],
        key=key2,
        value=(333).to_bytes(32, "big"),
        proof=get_proof(root2, key2),
        bucket_id=2,
    )

    lens = derive_ephemeral_state_lens(
        target_stems=[p1.stem_prefix],
        wallet_secret=b"wallet-secret",
        current_epoch=9,
        ttl_epochs=1,
    )

    selected = filter_packets_by_ephemeral_lens(lens, [p1, p2], current_epoch=9)
    assert selected == [p1]

    expired = filter_packets_by_ephemeral_lens(lens, [p1, p2], current_epoch=10)
    assert expired == []


def test_measure_query_pattern_leakage_flags_single_provider_visibility():
    metric = measure_query_pattern_leakage(
        [b"p1", b"p1", b"p1", b"p1", b"p2"],
        full_interest_threshold=0.8,
    )

    assert isinstance(metric, ProviderPrivacyMetric)
    assert metric.total_queries == 5
    assert metric.unique_providers == 2
    assert metric.dominant_provider_id == b"p1"
    assert metric.dominant_provider_share == pytest.approx(0.8)
    assert metric.single_provider_full_interest


def test_measure_query_pattern_leakage_balanced_distribution_not_flagged():
    metric = measure_query_pattern_leakage(
        [b"p1", b"p2", b"p1", b"p2"],
        full_interest_threshold=0.75,
    )

    assert metric.total_queries == 4
    assert metric.unique_providers == 2
    assert metric.dominant_provider_share == pytest.approx(0.5)
    assert metric.provider_hhi == pytest.approx(0.5)
    assert not metric.single_provider_full_interest
