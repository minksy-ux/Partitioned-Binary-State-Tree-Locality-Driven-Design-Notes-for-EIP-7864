"""Tests for verification-aware stem gas accounting."""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from pbt.gas import StemGasPolicy, VerificationAwareStemGasMeter


def test_first_read_charges_branch_plus_chunk():
    policy = StemGasPolicy(witness_branch_cost=10, witness_chunk_cost=3)
    meter = VerificationAwareStemGasMeter(policy)
    stem = b"s" * 33

    charge = meter.charge_read(stem)
    assert charge.total_cost == 13
    assert charge.used_branch_opening
    assert not charge.used_verified_cache_discount


def test_second_read_same_stem_charges_chunk_only():
    policy = StemGasPolicy(witness_branch_cost=10, witness_chunk_cost=3)
    meter = VerificationAwareStemGasMeter(policy)
    stem = b"a" * 33

    _ = meter.charge_read(stem)
    second = meter.charge_read(stem)
    assert second.total_cost == 3
    assert not second.used_branch_opening


def test_write_new_leaf_adds_new_leaf_cost():
    policy = StemGasPolicy(witness_branch_cost=9, witness_chunk_cost=2, write_new_leaf_cost=7)
    meter = VerificationAwareStemGasMeter(policy)
    stem = b"b" * 33

    charge = meter.charge_write(stem, is_new_leaf=True)
    assert charge.total_cost == 18


def test_verified_cache_discount_requires_local_verification_signal():
    policy = StemGasPolicy(
        witness_branch_cost=9,
        witness_chunk_cost=2,
        verified_cache_hit_read_cost=1,
    )
    meter = VerificationAwareStemGasMeter(policy)
    stem = b"c" * 33

    meter.mark_stem_verified(stem)

    # Without local verification signal, no discount is applied.
    cold = meter.charge_read(stem, locally_verified=False)
    assert cold.total_cost == 11
    assert not cold.used_verified_cache_discount


def test_verified_cache_discount_applies_when_verified_and_signaled():
    policy = StemGasPolicy(
        witness_branch_cost=9,
        witness_chunk_cost=2,
        verified_cache_hit_read_cost=1,
    )
    meter = VerificationAwareStemGasMeter(policy)
    stem = b"d" * 33

    meter.mark_stem_verified(stem)
    charge = meter.charge_read(stem, locally_verified=True)
    assert charge.total_cost == 1
    assert charge.used_verified_cache_discount


def test_new_block_resets_opened_and_verified_state():
    meter = VerificationAwareStemGasMeter()
    stem = b"e" * 33

    meter.mark_stem_verified(stem)
    _ = meter.charge_read(stem, locally_verified=True)
    meter.new_block()

    # Verification state cleared, so discount no longer applies automatically.
    charge = meter.charge_read(stem, locally_verified=True)
    assert charge.total_cost == meter.policy.witness_branch_cost + meter.policy.witness_chunk_cost


def test_mark_key_verified_marks_stem_prefix():
    meter = VerificationAwareStemGasMeter(
        StemGasPolicy(witness_branch_cost=7, witness_chunk_cost=2, verified_cache_hit_read_cost=1)
    )
    key = bytes([0]) + bytes([0xAB] * 32) + bytes([7])
    stem_prefix = key[:-1]

    meter.mark_key_verified(key)
    charge = meter.charge_read(stem_prefix, locally_verified=True)
    assert charge.total_cost == 1
    assert charge.used_verified_cache_discount
