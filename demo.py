#!/usr/bin/env python3
"""
Demo: Using the Partitioned Binary Tree reference implementation.

This script demonstrates:
  1. Building a small PBT with account data
  2. Generating and verifying Merkle proofs
  3. Performing insertions, updates, and deletions
  4. Showing locality benefits (same-stem access)
"""

import sys
import os
from copy import deepcopy
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from pbt import (
    EmptyNode,
    insert,
    get,
    delete,
    root_hash,
    get_proof,
    verify_proof,
    get_tree_key_for_basic_data,
    get_tree_key_for_storage_slot,
    get_tree_key_for_code_chunk,
    encode_basic_data,
    EMPTY_VALUE,
    StemFetchPolicy,
    simulate_epoch_fetch_with_fallback,
    StemWitnessPacket,
    ProviderReliabilityTracker,
    measure_query_pattern_leakage,
    derive_ephemeral_state_lens,
    filter_packets_by_ephemeral_lens,
    make_eth_getVerifiedProof_result,
    verify_eth_getVerifiedProof_result,
    make_eth_getStemWitness_result,
    verify_eth_getStemWitness_result,
    default_policy,
    default_release_artifacts,
    FormalVerificationDashboard,
    ProvingWorkload,
    compare_proving_profiles,
)


def demo_basic_account():
    """Create a small account and verify its state."""
    print("=" * 70)
    print("DEMO 1: Basic Account Creation and State")
    print("=" * 70)
    
    # Address (32 bytes)
    address = bytes.fromhex("1234567890123456789012345678901234567890123456789012345678901234")
    
    # Build tree with account data
    root = EmptyNode()
    
    # Insert BASIC_DATA (version, balance, nonce, code_size)
    basic_data_key = get_tree_key_for_basic_data(address)
    basic_data = encode_basic_data(
        version=1,
        balance=10**18,  # 1 ETH
        nonce=42,
        code_size=256,
    )
    root = insert(root, basic_data_key, basic_data)
    print(f"✓ Inserted account basic data")
    
    # Insert first 4 storage slots (co-located in header stem)
    for slot in range(4):
        key = get_tree_key_for_storage_slot(address, slot)
        value = (slot * 1000).to_bytes(32, "big")
        root = insert(root, key, value)
    print(f"✓ Inserted 4 storage slots (all in header stem)")
    
    # Insert first 8 code chunks (co-located in header stem)
    for chunk_id in range(8):
        key = get_tree_key_for_code_chunk(address, chunk_id)
        value = (chunk_id * 100).to_bytes(32, "big")
        root = insert(root, key, value)
    print(f"✓ Inserted 8 code chunks (all in header stem)")
    
    # Show root hash
    rh = root_hash(root)
    print(f"\n✓ Root hash: {rh.hex()[:16]}...")
    print(f"  Tree contains all account hot state in a single stem!\n")
    return root, address, rh


def demo_proofs(root, address, root_hash_expected):
    """Generate and verify Merkle proofs."""
    print("=" * 70)
    print("DEMO 2: Merkle Proof Generation and Verification")
    print("=" * 70)
    
    # Generate proof for storage slot 2
    storage_key = get_tree_key_for_storage_slot(address, 2)
    proof = get_proof(root, storage_key)
    
    print(f"✓ Generated proof for storage slot 2")
    print(f"  Proof size: {len(proof.path_siblings)} siblings in path")
    print(f"  Proof value: {proof.value.hex()[:16]}...")
    
    # Verify the proof
    is_valid = verify_proof(root_hash_expected, proof)
    print(f"✓ Proof verification: {'PASS' if is_valid else 'FAIL'}")
    
    # Try to forge a proof (tamper with value)
    print(f"\n  Attempting to forge proof...")
    bad_proof = type(proof)(
        key=proof.key,
        value=bytes(32),  # wrong value
        stem_values=proof.stem_values,
        path_siblings=proof.path_siblings,
        path_bits=proof.path_bits,
    )
    is_valid_bad = verify_proof(root_hash_expected, bad_proof)
    print(f"✓ Tampered proof rejected: {not is_valid_bad}\n")
    return proof


def demo_updates():
    """Insert, update, and delete operations."""
    print("=" * 70)
    print("DEMO 3: Insert, Update, Delete Operations")
    print("=" * 70)
    
    address = bytes(32)
    root = EmptyNode()
    
    # Insert 3 storage slots
    keys = []
    for slot in range(3):
        key = get_tree_key_for_storage_slot(address, slot)
        value = slot.to_bytes(32, "big")
        root = insert(root, key, value)
        keys.append(key)
    
    print(f"✓ Inserted 3 storage slots")
    h1 = root_hash(root)
    print(f"  Root hash: {h1.hex()[:16]}...")
    
    # Update slot 1
    root = insert(root, keys[1], (999).to_bytes(32, "big"))
    print(f"\n✓ Updated slot 1 to value 999")
    h2 = root_hash(root)
    print(f"  Root hash changed: {h1.hex()[:16]}... → {h2.hex()[:16]}...")
    assert h1 != h2, "Hash should change after update"
    
    # Delete slot 1
    root = delete(root, keys[1])
    print(f"\n✓ Deleted slot 1")
    h3 = root_hash(root)
    print(f"  Root hash changed: {h2.hex()[:16]}... → {h3.hex()[:16]}...")
    assert get(root, keys[1]) == EMPTY_VALUE, "Deleted slot should be empty"
    print(f"  ✓ Slot 1 is now empty")
    

def demo_locality():
    """Show the locality benefit of stems."""
    print("\n" + "=" * 70)
    print("DEMO 4: Locality — Multiple Accesses Share a Stem")
    print("=" * 70)
    
    address = bytes(32)
    root = EmptyNode()
    
    # Insert multiple storage slots (first 4 share header stem)
    print(f"Inserting 4 storage slots (indices 0-3)...")
    for slot in range(4):
        key = get_tree_key_for_storage_slot(address, slot)
        value = slot.to_bytes(32, "big")
        root = insert(root, key, value)
    
    # All 4 should be in same stem — so a proof for any of them
    # should have the same path length
    proof_slot_0 = get_proof(root, get_tree_key_for_storage_slot(address, 0))
    proof_slot_3 = get_proof(root, get_tree_key_for_storage_slot(address, 3))
    
    print(f"\n✓ Proof for slot 0: {len(proof_slot_0.path_siblings)} siblings")
    print(f"✓ Proof for slot 3: {len(proof_slot_3.path_siblings)} siblings")
    
    if len(proof_slot_0.path_siblings) == len(proof_slot_3.path_siblings):
        print(f"✓ Same proof depth: slots share a stem!")
    
    # Now insert a slot beyond the header (slot 5)
    key_slot_5 = get_tree_key_for_storage_slot(address, 5)
    root = insert(root, key_slot_5, (5).to_bytes(32, "big"))
    
    proof_slot_5 = get_proof(root, key_slot_5)
    print(f"\n✓ Proof for slot 5 (overflow): {len(proof_slot_5.path_siblings)} siblings")
    print(f"  (Different stem from slots 0-3, so different proof depth)\n")


def demo_private_fetch_with_fallback():
    """Demonstrate adaptive private fetch fallback with live telemetry."""
    print("=" * 70)
    print("DEMO 5: Private Stem Fetch Policy With Fallback")
    print("=" * 70)

    key = bytes([0]) + bytes([0xCC] * 32) + bytes([9])
    value = (2026).to_bytes(32, "big")
    root = insert(EmptyNode(), key, value)
    packet = StemWitnessPacket(
        epoch=12,
        block_number=700,
        block_root=root_hash(root),
        stem_prefix=key[:-1],
        key=key,
        value=value,
        proof=get_proof(root, key),
        bucket_id=1,
    )
    lens = derive_ephemeral_state_lens(
        target_stems=[packet.stem_prefix],
        wallet_secret=b"wallet-seed",
        current_epoch=packet.epoch,
        ttl_epochs=1,
        scope_tag=b"balance+hot-slots",
    )
    one_time_lens = derive_ephemeral_state_lens(
        target_stems=[packet.stem_prefix],
        wallet_secret=b"wallet-seed",
        current_epoch=packet.epoch,
        ttl_epochs=2,
        scope_tag=b"tx-precheck",
        max_uses=1,
    )
    lens_packets = filter_packets_by_ephemeral_lens(lens, [packet], current_epoch=packet.epoch)
    consumed = one_time_lens.consume(current_epoch=packet.epoch)

    policy = StemFetchPolicy(
        bucket_count=32,
        cover_count=1,
        required_provider_matches=2,
        provider_redundancy=0,
        max_epoch_lag=2,
    )

    state = {"attempt": 0}
    attempt_logs: list[tuple[int, list[str], int, int]] = []
    observed_providers: list[bytes] = []
    tracker = ProviderReliabilityTracker()

    def fetch_fn(plan):
        state["attempt"] += 1
        provider_labels = [pid.decode("ascii") for pid in plan.provider_ids]
        attempt_logs.append(
            (
                state["attempt"],
                provider_labels,
                len(plan.target_buckets),
                len(plan.fetch_buckets),
            )
        )
        observed_providers.extend(plan.provider_ids)
        if state["attempt"] == 1:
            # First response is insufficient for quorum, triggering fallback.
            return [packet], [b"provider-a"]
        return [packet, packet], [b"provider-a", b"provider-b"]

    result, plan, attempts = simulate_epoch_fetch_with_fallback(
        base_policy=policy,
        target_stems=[packet.stem_prefix],
        epoch=packet.epoch,
        secret_seed=b"wallet-seed",
        global_salt=b"global-salt",
        available_provider_ids=[b"provider-a", b"provider-b", b"provider-c"],
        expected_block_root=packet.block_root,
        current_epoch=packet.epoch,
        fetch_fn=fetch_fn,
        max_attempts=3,
        reliability_tracker=tracker,
        adaptive_tuning=True,
        tuning_min_success_rate=0.9,
        tuning_failure_streak_threshold=1,
    )

    print("Retry trace:")
    for attempt_no, providers, target_bucket_count, fetch_bucket_count in attempt_logs:
        print(
            f"  - attempt {attempt_no}: providers={providers}, "
            f"target_buckets={target_bucket_count}, fetch_buckets={fetch_bucket_count}"
        )

    print("Provider reliability snapshot:")
    for provider_id, stats in sorted(tracker.snapshot().items(), key=lambda kv: kv[0]):
        label = provider_id.decode("ascii")
        print(
            f"  - {label}: attempts={stats.attempts}, successes={stats.successes}, "
            f"consecutive_failures={stats.consecutive_failures}"
        )

    privacy_metric = measure_query_pattern_leakage(observed_providers, full_interest_threshold=0.8)
    dominant = (
        privacy_metric.dominant_provider_id.decode("ascii")
        if privacy_metric.dominant_provider_id is not None
        else "none"
    )
    print("Session privacy metric:")
    print(
        "  - "
        f"dominant_provider={dominant}, "
        f"dominant_share={privacy_metric.dominant_provider_share:.2f}, "
        f"hhi={privacy_metric.provider_hhi:.3f}, "
        f"single_provider_full_interest={privacy_metric.single_provider_full_interest}"
    )
    print("Ephemeral state lens:")
    print(
        "  - "
        f"active={lens.is_active(packet.epoch)}, "
        f"stem_count={len(lens.stem_prefixes)}, "
        f"selected_packets={len(lens_packets)}"
    )
    print(
        "  - "
        f"one_time_consumed={consumed}, "
        f"one_time_active_after_consume={one_time_lens.is_active(packet.epoch)}"
    )

    print(f"✓ Attempts used: {attempts}")
    print(f"✓ Target buckets: {list(plan.target_buckets)}")
    print(f"✓ Fetch buckets (with cover): {list(plan.fetch_buckets)}")
    print(f"✓ Selected providers: {[pid.decode('ascii') for pid in plan.provider_ids]}")
    print(f"✓ Local verification result: {result.reason}\n")
    assert result.accepted


def _flip_last_hex_nibble(hex_value: str) -> str:
    if not hex_value.startswith("0x") or len(hex_value) <= 2:
        raise ValueError("expected 0x-prefixed hex string")
    last = hex_value[-1]
    return hex_value[:-1] + ("0" if last != "0" else "1")


def demo_verified_rpc_wallet_status():
    """Show verified/unverified wallet UI status transitions for verified-RPC."""
    print("=" * 70)
    print("DEMO 6: Verified-RPC Wallet Status Flow")
    print("=" * 70)

    address = bytes.fromhex("11" * 32)
    key = get_tree_key_for_basic_data(address)
    value = encode_basic_data(version=1, balance=1234, nonce=5, code_size=0)
    root = insert(EmptyNode(), key, value)
    trusted_root = root_hash(root)
    proof = get_proof(root, key)

    print("eth_getVerifiedProof status flow:")
    print("  - UI status before local checks: UNVERIFIED")
    payload = make_eth_getVerifiedProof_result(
        provider="provider-a",
        block_number=321,
        block_hash=b"h" * 32,
        state_root=trusted_root,
        key=key,
        value=value,
        proof=proof,
    )
    verified = verify_eth_getVerifiedProof_result(payload, expected_state_root=trusted_root)
    print(
        f"  - UI status after local checks: {'VERIFIED' if verified.accepted else 'UNVERIFIED'} "
        f"({verified.reason})"
    )

    tampered = deepcopy(payload)
    tampered["state"]["value"] = "0xxyz"
    rejected = verify_eth_getVerifiedProof_result(tampered, expected_state_root=trusted_root)
    print(
        f"  - UI status on malformed payload: {'VERIFIED' if rejected.accepted else 'UNVERIFIED'} "
        f"({rejected.reason})"
    )

    packet = StemWitnessPacket(
        epoch=2,
        block_number=321,
        block_root=trusted_root,
        stem_prefix=key[:-1],
        key=key,
        value=value,
        proof=proof,
        bucket_id=7,
    )
    print("eth_getStemWitness status flow:")
    print("  - UI status before local checks: UNVERIFIED")
    stem_payload = make_eth_getStemWitness_result(
        provider="provider-a",
        block_hash=b"b" * 32,
        packet=packet,
    )
    stem_verified = verify_eth_getStemWitness_result(
        stem_payload,
        expected_state_root=trusted_root,
    )
    print(
        f"  - UI status after local checks: {'VERIFIED' if stem_verified.accepted else 'UNVERIFIED'} "
        f"({stem_verified.reason})"
    )

    tampered_stem = deepcopy(stem_payload)
    wire = tampered_stem["stemWitness"]["packetWire"]
    tampered_stem["stemWitness"]["packetWire"] = _flip_last_hex_nibble(wire)
    stem_rejected = verify_eth_getStemWitness_result(
        tampered_stem,
        expected_state_root=trusted_root,
    )
    print(
        f"  - UI status on tampered witness: {'VERIFIED' if stem_rejected.accepted else 'UNVERIFIED'} "
        f"({stem_rejected.reason})\n"
    )
    assert verified.accepted
    assert stem_verified.accepted
    assert not rejected.accepted
    assert not stem_rejected.accepted


def demo_formal_verification_dashboard():
    """Show formal verification readiness dashboard output."""
    print("=" * 70)
    print("DEMO 7: Formal Verification Dashboard")
    print("=" * 70)

    artifacts = default_release_artifacts()
    dashboard = FormalVerificationDashboard(default_policy())
    snapshot = dashboard.build_snapshot(artifacts)
    rendered = dashboard.render_markdown(snapshot, include_phone_user_story=True)

    print(f"✓ Overall status: {snapshot.overall_status}")
    print(
        "✓ Required verified: "
        f"{snapshot.required_fully_verified}/{snapshot.total_required}"
    )
    print("\nDashboard markdown preview:\n")
    print(rendered)
    print()
    assert snapshot.overall_status == "PASS"


def demo_proving_profiles():
    """Show circuit-cost and STARK execution profile comparisons."""
    print("=" * 70)
    print("DEMO 8: Circuit Cost And STARK-Friendly Profile Estimates")
    print("=" * 70)

    workload = ProvingWorkload(
        internal_node_hashes=640,
        stem_hashes=160,
        auxiliary_hashes=40,
    )
    comparisons = compare_proving_profiles(workload, baseline_hash_id="keccak256")

    print(
        "Workload summary: "
        f"internal={workload.internal_node_hashes}, "
        f"stem={workload.stem_hashes}, "
        f"aux={workload.auxiliary_hashes}, "
        f"total_hashes={workload.total_hashes}"
    )
    print("Profile comparison (relative to keccak256 baseline):")
    for item in comparisons:
        print(
            f"  - {item.hash_id}: "
            f"constraints={item.total_constraints} "
            f"({item.constraints_vs_baseline:.3f}x), "
            f"trace_rows={item.total_trace_rows} "
            f"({item.trace_rows_vs_baseline:.3f}x)"
        )
    print()


if __name__ == "__main__":
    print("\n" + "=" * 70)
    print("PARTITIONED BINARY TREE REFERENCE IMPLEMENTATION DEMO")
    print("=" * 70 + "\n")
    
    try:
        root, address, rh = demo_basic_account()
        demo_proofs(root, address, rh)
        demo_updates()
        demo_locality()
        demo_private_fetch_with_fallback()
        demo_verified_rpc_wallet_status()
        demo_formal_verification_dashboard()
        demo_proving_profiles()
        
        print("=" * 70)
        print("✓ ALL DEMOS PASSED")
        print("=" * 70 + "\n")
        
    except Exception as e:
        print(f"\n✗ DEMO FAILED: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(1)
