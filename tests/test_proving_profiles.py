"""Tests for proving profile and STARK execution estimators."""

import json
import sys
import os
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from pbt.proving_profiles import (
    CalibrationRecord,
    HashCostProfile,
    ProvingWorkload,
    RecursiveStarkPlan,
    available_hash_cost_profile_ids,
    available_binius_profile_ids,
    get_hash_cost_profile,
    register_hash_cost_profile,
    estimate_workload_from_access_pattern,
    default_proving_scenarios,
    estimate_constraint_count,
    estimate_circuit_cost,
    estimate_stark_execution,
    estimate_recursive_stark_execution,
    compare_proving_profiles,
    render_profile_report_markdown,
    calibration_record_for_profile,
    register_calibrated_profiles,
    register_calibrated_profiles_from_file,
)


def test_builtin_profile_ids_include_expected_defaults():
    ids = available_hash_cost_profile_ids()
    assert "blake3" in ids
    assert "keccak256" in ids
    assert "poseidon2" in ids
    assert "blake3_binius" in ids
    assert "poseidon2_binius" in ids


def test_binius_profile_ids_are_exposed_separately():
    ids = available_binius_profile_ids()
    assert "blake3_binius" in ids
    assert "poseidon2_binius" in ids
    assert "keccak256" not in ids


def test_poseidon2_estimates_lower_than_keccak_for_same_workload():
    workload = ProvingWorkload(internal_node_hashes=100, stem_hashes=20, auxiliary_hashes=5)

    poseidon_circuit = estimate_circuit_cost(workload, "poseidon2")
    keccak_circuit = estimate_circuit_cost(workload, "keccak256")
    assert poseidon_circuit.total_constraints < keccak_circuit.total_constraints

    poseidon_stark = estimate_stark_execution(workload, "poseidon2")
    keccak_stark = estimate_stark_execution(workload, "keccak256")
    assert poseidon_stark.total_trace_rows < keccak_stark.total_trace_rows


def test_estimate_totals_match_total_hash_count():
    workload = ProvingWorkload(internal_node_hashes=9, stem_hashes=4, auxiliary_hashes=2)
    profile = get_hash_cost_profile("blake3")

    circuit = estimate_circuit_cost(workload, "blake3")
    stark = estimate_stark_execution(workload, "blake3")

    assert circuit.total_hashes == 15
    assert stark.total_hashes == 15
    assert circuit.total_constraints == 15 * profile.circuit_constraints_per_hash
    assert stark.total_trace_rows == 15 * profile.stark_trace_rows_per_hash


def test_constraint_count_estimate_returns_component_breakdown():
    workload = ProvingWorkload(internal_node_hashes=10, stem_hashes=3, auxiliary_hashes=2)
    breakdown = estimate_constraint_count(workload, "poseidon2")
    per_hash = get_hash_cost_profile("poseidon2").circuit_constraints_per_hash

    assert breakdown.internal_constraints == 10 * per_hash
    assert breakdown.stem_constraints == 3 * per_hash
    assert breakdown.auxiliary_constraints == 2 * per_hash
    assert breakdown.total_constraints == 15 * per_hash


def test_estimate_workload_from_access_pattern_shapes_counts():
    workload = estimate_workload_from_access_pattern(
        unique_stems=5,
        average_branch_depth=20,
        reads_per_stem=3,
        writes_per_stem=1,
        auxiliary_hashes=7,
    )
    assert workload.internal_node_hashes == 100
    assert workload.stem_hashes == 20
    assert workload.auxiliary_hashes == 7


def test_default_proving_scenarios_return_named_workloads():
    scenarios = default_proving_scenarios()
    names = [scenario.name for scenario in scenarios]
    assert "wallet_hot_reads" in names
    assert "stateless_block_execution" in names
    assert "proof_aggregation_burst" in names
    assert all(scenario.workload.total_hashes > 0 for scenario in scenarios)


def test_compare_profiles_sets_keccak_baseline_ratio_to_one():
    workload = ProvingWorkload(internal_node_hashes=7, stem_hashes=3)
    comparisons = compare_proving_profiles(workload, baseline_hash_id="keccak256")
    keccak = [item for item in comparisons if item.hash_id == "keccak256"][0]

    assert keccak.constraints_vs_baseline == 1.0
    assert keccak.trace_rows_vs_baseline == 1.0


def test_compare_profiles_can_limit_hash_id_subset():
    workload = ProvingWorkload(internal_node_hashes=3, stem_hashes=1)
    comparisons = compare_proving_profiles(workload, hash_ids=["poseidon2", "keccak256"])
    ids = [item.hash_id for item in comparisons]
    assert ids == ["keccak256", "poseidon2"]


def test_poseidon2_binius_profile_beats_poseidon2_on_stark_rows():
    workload = ProvingWorkload(internal_node_hashes=24, stem_hashes=6)
    regular = estimate_stark_execution(workload, "poseidon2")
    binius = estimate_stark_execution(workload, "poseidon2_binius")
    assert binius.total_trace_rows < regular.total_trace_rows


def test_register_custom_hash_cost_profile():
    custom_id = "dummy_profile"
    profile = HashCostProfile(
        hash_id=custom_id,
        circuit_constraints_per_hash=111,
        stark_trace_rows_per_hash=222,
    )
    register_hash_cost_profile(profile)

    workload = ProvingWorkload(internal_node_hashes=2, stem_hashes=1)
    circuit = estimate_circuit_cost(workload, custom_id)
    stark = estimate_stark_execution(workload, custom_id)

    assert circuit.total_constraints == 333
    assert stark.total_trace_rows == 666


def test_workload_rejects_negative_counters():
    try:
        ProvingWorkload(internal_node_hashes=-1, stem_hashes=0)
        assert False, "expected ValueError"
    except ValueError:
        pass


def test_recursive_stark_one_layer_equals_base_estimate():
    workload = ProvingWorkload(internal_node_hashes=12, stem_hashes=4)
    recursive = estimate_recursive_stark_execution(
        workload,
        "poseidon2",
        plan=RecursiveStarkPlan(recursion_layers=1),
    )
    base_stark = estimate_stark_execution(workload, "poseidon2")
    base_circuit = estimate_circuit_cost(workload, "poseidon2")

    assert recursive.base_trace_rows == base_stark.total_trace_rows
    assert recursive.recursive_trace_rows == base_stark.total_trace_rows
    assert recursive.base_constraints == base_circuit.total_constraints
    assert recursive.recursive_constraints == base_circuit.total_constraints


def test_recursive_stark_multi_layer_compression_reduces_trace_rows():
    workload = ProvingWorkload(internal_node_hashes=500, stem_hashes=120, auxiliary_hashes=20)
    recursive = estimate_recursive_stark_execution(
        workload,
        "poseidon2_binius",
        plan=RecursiveStarkPlan(
            recursion_layers=3,
            per_layer_compression=0.5,
            layer_overhead_trace_rows=100,
            layer_overhead_constraints=80,
        ),
    )

    assert recursive.recursion_layers == 3
    assert recursive.recursive_trace_rows < recursive.base_trace_rows
    assert recursive.recursive_constraints < recursive.base_constraints


def test_render_profile_report_markdown_contains_expected_columns_and_rows():
    workload = ProvingWorkload(internal_node_hashes=10, stem_hashes=3, auxiliary_hashes=1)
    rendered = render_profile_report_markdown(
        workload,
        hash_ids=["keccak256", "poseidon2_binius"],
        baseline_hash_id="keccak256",
        recursive_plan=RecursiveStarkPlan(
            recursion_layers=2,
            per_layer_compression=0.5,
            layer_overhead_trace_rows=0,
            layer_overhead_constraints=0,
        ),
    )

    assert "| hash_id | binius | total_hashes |" in rendered
    assert "| keccak256 |" in rendered
    assert "| poseidon2_binius |" in rendered


def test_register_calibrated_profiles_records_provenance():
    record = CalibrationRecord(
        hash_id="poseidon2",
        circuit_constraints_per_hash=900,
        stark_trace_rows_per_hash=600,
        benchmark_suite="pbt-rs benches",
        benchmark_commit="deadbeef",
        benchmark_command="cargo bench --bench core_ops",
        measured_at_utc="2026-07-03T00:00:00Z",
        sample_count=12,
    )
    ids = register_calibrated_profiles([record], suffix="_cal")
    assert ids == ["poseidon2_cal"]

    loaded = get_hash_cost_profile("poseidon2_cal")
    assert loaded.circuit_constraints_per_hash == 900
    assert loaded.stark_trace_rows_per_hash == 600

    provenance = calibration_record_for_profile("poseidon2_cal")
    assert provenance is not None
    assert provenance.benchmark_suite == "pbt-rs benches"
    assert provenance.sample_count == 12


def test_register_calibrated_profiles_from_file(tmp_path: Path):
    fixture = {
        "records": [
            {
                "hash_id": "blake3",
                "circuit_constraints_per_hash": 5100,
                "stark_trace_rows_per_hash": 2900,
                "benchmark_suite": "python harness",
                "benchmark_commit": "abc123",
                "benchmark_command": "python scripts/generate_performance_envelopes.py",
                "measured_at_utc": "2026-07-03T01:00:00Z",
                "sample_count": 5,
                "notes": "calibrated from local run"
            }
        ]
    }
    path = tmp_path / "calibration.json"
    path.write_text(json.dumps(fixture), encoding="utf-8")

    ids = register_calibrated_profiles_from_file(path, suffix="_bench")
    assert ids == ["blake3_bench"]
    assert get_hash_cost_profile("blake3_bench").stark_trace_rows_per_hash == 2900
