"""Circuit-cost and STARK-friendly execution profiling helpers.

This module provides a lightweight, deterministic cost model to compare
hash profiles (for example, Keccak-256 vs Poseidon2) on representative
PBT workloads.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path


@dataclass(frozen=True)
class HashCostProfile:
    """Per-hash proving profile constants for a hash function id."""

    hash_id: str
    circuit_constraints_per_hash: int
    stark_trace_rows_per_hash: int
    binius_integration: bool = False

    def __post_init__(self) -> None:
        if not self.hash_id:
            raise ValueError("hash_id must be non-empty")
        if self.circuit_constraints_per_hash <= 0:
            raise ValueError("circuit_constraints_per_hash must be positive")
        if self.stark_trace_rows_per_hash <= 0:
            raise ValueError("stark_trace_rows_per_hash must be positive")


@dataclass(frozen=True)
class ProvingWorkload:
    """Aggregate PBT workload counters for profile estimation."""

    internal_node_hashes: int
    stem_hashes: int
    auxiliary_hashes: int = 0

    def __post_init__(self) -> None:
        if self.internal_node_hashes < 0:
            raise ValueError("internal_node_hashes must be non-negative")
        if self.stem_hashes < 0:
            raise ValueError("stem_hashes must be non-negative")
        if self.auxiliary_hashes < 0:
            raise ValueError("auxiliary_hashes must be non-negative")

    @property
    def total_hashes(self) -> int:
        return self.internal_node_hashes + self.stem_hashes + self.auxiliary_hashes


@dataclass(frozen=True)
class CircuitCostEstimate:
    """Estimated circuit constraints for a workload under one hash profile."""

    hash_id: str
    total_hashes: int
    total_constraints: int


@dataclass(frozen=True)
class ConstraintCountEstimate:
    """Detailed constraint-count estimate split by workload component."""

    hash_id: str
    internal_constraints: int
    stem_constraints: int
    auxiliary_constraints: int
    total_constraints: int


@dataclass(frozen=True)
class StarkExecutionEstimate:
    """Estimated STARK trace rows for a workload under one hash profile."""

    hash_id: str
    total_hashes: int
    total_trace_rows: int


@dataclass(frozen=True)
class RecursiveStarkPlan:
    """Configuration for recursive STARK aggregation estimates."""

    recursion_layers: int = 1
    per_layer_compression: float = 0.55
    layer_overhead_trace_rows: int = 5000
    layer_overhead_constraints: int = 2500

    def __post_init__(self) -> None:
        if self.recursion_layers <= 0:
            raise ValueError("recursion_layers must be positive")
        if not 0 < self.per_layer_compression <= 1:
            raise ValueError("per_layer_compression must be in (0, 1]")
        if self.layer_overhead_trace_rows < 0:
            raise ValueError("layer_overhead_trace_rows must be non-negative")
        if self.layer_overhead_constraints < 0:
            raise ValueError("layer_overhead_constraints must be non-negative")


@dataclass(frozen=True)
class RecursiveStarkEstimate:
    """Recursive STARK estimate including constraint and trace impacts."""

    hash_id: str
    recursion_layers: int
    base_trace_rows: int
    recursive_trace_rows: int
    base_constraints: int
    recursive_constraints: int


@dataclass(frozen=True)
class ProvingProfileComparison:
    """Combined circuit and STARK estimate with baseline-relative ratios."""

    hash_id: str
    total_hashes: int
    total_constraints: int
    total_trace_rows: int
    constraints_vs_baseline: float
    trace_rows_vs_baseline: float


@dataclass(frozen=True)
class ProvingScenario:
    """Named scenario for profile comparisons and reporting."""

    name: str
    workload: ProvingWorkload
    description: str = ""

    def __post_init__(self) -> None:
        if not self.name:
            raise ValueError("scenario name must be non-empty")


@dataclass(frozen=True)
class CalibrationRecord:
    """Benchmark-derived hash profile constants with provenance metadata."""

    hash_id: str
    circuit_constraints_per_hash: int
    stark_trace_rows_per_hash: int
    benchmark_suite: str
    benchmark_commit: str
    benchmark_command: str
    measured_at_utc: str
    sample_count: int
    notes: str = ""
    binius_integration: bool = False

    def __post_init__(self) -> None:
        if not self.hash_id:
            raise ValueError("hash_id must be non-empty")
        if self.circuit_constraints_per_hash <= 0:
            raise ValueError("circuit_constraints_per_hash must be positive")
        if self.stark_trace_rows_per_hash <= 0:
            raise ValueError("stark_trace_rows_per_hash must be positive")
        if not self.benchmark_suite:
            raise ValueError("benchmark_suite must be non-empty")
        if not self.benchmark_commit:
            raise ValueError("benchmark_commit must be non-empty")
        if not self.benchmark_command:
            raise ValueError("benchmark_command must be non-empty")
        if not self.measured_at_utc:
            raise ValueError("measured_at_utc must be non-empty")
        if self.sample_count <= 0:
            raise ValueError("sample_count must be positive")


_profiles: dict[str, HashCostProfile] = {
    # Deliberately coarse defaults for protocol-planning comparisons.
    "blake3": HashCostProfile(
        hash_id="blake3",
        circuit_constraints_per_hash=5400,
        stark_trace_rows_per_hash=3100,
        binius_integration=False,
    ),
    "keccak256": HashCostProfile(
        hash_id="keccak256",
        circuit_constraints_per_hash=12500,
        stark_trace_rows_per_hash=6800,
        binius_integration=False,
    ),
    "poseidon2": HashCostProfile(
        hash_id="poseidon2",
        circuit_constraints_per_hash=950,
        stark_trace_rows_per_hash=720,
        binius_integration=False,
    ),
    "blake3_binius": HashCostProfile(
        hash_id="blake3_binius",
        circuit_constraints_per_hash=4200,
        stark_trace_rows_per_hash=1900,
        binius_integration=True,
    ),
    "poseidon2_binius": HashCostProfile(
        hash_id="poseidon2_binius",
        circuit_constraints_per_hash=780,
        stark_trace_rows_per_hash=420,
        binius_integration=True,
    ),
}

_calibration_provenance: dict[str, CalibrationRecord] = {}


def register_hash_cost_profile(profile: HashCostProfile) -> None:
    """Register or replace a hash proving profile."""
    _profiles[profile.hash_id] = profile


def load_calibration_records(path: str | Path) -> list[CalibrationRecord]:
    """Load benchmark calibration records from JSON file."""
    file_path = Path(path)
    data = json.loads(file_path.read_text(encoding="utf-8"))
    records_raw = data.get("records") if isinstance(data, dict) else None
    if not isinstance(records_raw, list):
        raise ValueError("calibration file must contain an object with a records list")

    records: list[CalibrationRecord] = []
    for item in records_raw:
        if not isinstance(item, dict):
            raise ValueError("calibration record entries must be objects")
        records.append(CalibrationRecord(**item))
    return records


def register_calibrated_profiles(
    records: list[CalibrationRecord],
    suffix: str = "_calibrated",
) -> list[str]:
    """Register benchmark-derived profiles and retain provenance metadata."""
    if not suffix:
        raise ValueError("suffix must be non-empty")

    registered_ids: list[str] = []
    for record in records:
        profile_id = f"{record.hash_id}{suffix}"
        register_hash_cost_profile(
            HashCostProfile(
                hash_id=profile_id,
                circuit_constraints_per_hash=record.circuit_constraints_per_hash,
                stark_trace_rows_per_hash=record.stark_trace_rows_per_hash,
                binius_integration=record.binius_integration,
            )
        )
        _calibration_provenance[profile_id] = record
        registered_ids.append(profile_id)
    return registered_ids


def register_calibrated_profiles_from_file(
    path: str | Path,
    suffix: str = "_calibrated",
) -> list[str]:
    """Load benchmark records from JSON and register calibrated profiles."""
    records = load_calibration_records(path)
    return register_calibrated_profiles(records, suffix=suffix)


def calibration_record_for_profile(hash_id: str) -> CalibrationRecord | None:
    """Return calibration provenance metadata for a registered profile id."""
    return _calibration_provenance.get(hash_id)


def available_hash_cost_profile_ids() -> list[str]:
    """Return supported proving profile ids."""
    return sorted(_profiles.keys())


def available_binius_profile_ids() -> list[str]:
    """Return proving profile ids marked as Binius integrations."""
    return sorted(
        profile.hash_id
        for profile in _profiles.values()
        if profile.binius_integration
    )


def get_hash_cost_profile(hash_id: str) -> HashCostProfile:
    """Return a hash profile by id."""
    try:
        return _profiles[hash_id]
    except KeyError as exc:
        raise ValueError(f"unknown hash cost profile id: {hash_id}") from exc


def estimate_circuit_cost(workload: ProvingWorkload, hash_id: str) -> CircuitCostEstimate:
    """Estimate total circuit constraints for a workload."""
    profile = get_hash_cost_profile(hash_id)
    total_hashes = workload.total_hashes
    counts = estimate_constraint_count(workload, hash_id)
    return CircuitCostEstimate(
        hash_id=profile.hash_id,
        total_hashes=total_hashes,
        total_constraints=counts.total_constraints,
    )


def estimate_constraint_count(
    workload: ProvingWorkload,
    hash_id: str,
) -> ConstraintCountEstimate:
    """Estimate total constraints and per-component breakdown for a workload."""
    profile = get_hash_cost_profile(hash_id)
    internal_constraints = (
        workload.internal_node_hashes * profile.circuit_constraints_per_hash
    )
    stem_constraints = workload.stem_hashes * profile.circuit_constraints_per_hash
    auxiliary_constraints = (
        workload.auxiliary_hashes * profile.circuit_constraints_per_hash
    )
    return ConstraintCountEstimate(
        hash_id=profile.hash_id,
        internal_constraints=internal_constraints,
        stem_constraints=stem_constraints,
        auxiliary_constraints=auxiliary_constraints,
        total_constraints=internal_constraints + stem_constraints + auxiliary_constraints,
    )


def estimate_stark_execution(
    workload: ProvingWorkload,
    hash_id: str,
) -> StarkExecutionEstimate:
    """Estimate STARK trace rows for a workload."""
    profile = get_hash_cost_profile(hash_id)
    total_hashes = workload.total_hashes
    return StarkExecutionEstimate(
        hash_id=profile.hash_id,
        total_hashes=total_hashes,
        total_trace_rows=total_hashes * profile.stark_trace_rows_per_hash,
    )


def estimate_recursive_stark_execution(
    workload: ProvingWorkload,
    hash_id: str,
    plan: RecursiveStarkPlan | None = None,
) -> RecursiveStarkEstimate:
    """Estimate recursive STARK aggregation costs.

    The model uses per-layer compression plus fixed layer overheads for both
    trace rows and constraints.
    """
    recursive_plan = plan or RecursiveStarkPlan()
    base_stark = estimate_stark_execution(workload, hash_id)
    base_constraints = estimate_circuit_cost(workload, hash_id).total_constraints

    trace_rows = base_stark.total_trace_rows
    constraints = base_constraints
    for _ in range(1, recursive_plan.recursion_layers):
        trace_rows = int(trace_rows * recursive_plan.per_layer_compression)
        trace_rows += recursive_plan.layer_overhead_trace_rows
        constraints = int(constraints * recursive_plan.per_layer_compression)
        constraints += recursive_plan.layer_overhead_constraints

    return RecursiveStarkEstimate(
        hash_id=hash_id,
        recursion_layers=recursive_plan.recursion_layers,
        base_trace_rows=base_stark.total_trace_rows,
        recursive_trace_rows=trace_rows,
        base_constraints=base_constraints,
        recursive_constraints=constraints,
    )


def estimate_workload_from_access_pattern(
    unique_stems: int,
    average_branch_depth: int,
    reads_per_stem: int,
    writes_per_stem: int = 0,
    auxiliary_hashes: int = 0,
) -> ProvingWorkload:
    """Build a workload estimate from a stem-level access pattern.

    The estimate is intentionally simple and deterministic:
    - internal hashes scale with unique stems and average branch depth,
    - stem hashes scale with per-stem read/write activity.
    """
    if unique_stems < 0:
        raise ValueError("unique_stems must be non-negative")
    if average_branch_depth < 0:
        raise ValueError("average_branch_depth must be non-negative")
    if reads_per_stem < 0:
        raise ValueError("reads_per_stem must be non-negative")
    if writes_per_stem < 0:
        raise ValueError("writes_per_stem must be non-negative")
    if auxiliary_hashes < 0:
        raise ValueError("auxiliary_hashes must be non-negative")

    internal_hashes = unique_stems * average_branch_depth
    stem_hashes = unique_stems * (reads_per_stem + writes_per_stem)
    return ProvingWorkload(
        internal_node_hashes=internal_hashes,
        stem_hashes=stem_hashes,
        auxiliary_hashes=auxiliary_hashes,
    )


def default_proving_scenarios() -> list[ProvingScenario]:
    """Return representative default proving scenarios."""
    return [
        ProvingScenario(
            name="wallet_hot_reads",
            description="Wallet reads concentrated in a small hot-stem set",
            workload=estimate_workload_from_access_pattern(
                unique_stems=8,
                average_branch_depth=24,
                reads_per_stem=6,
                writes_per_stem=0,
                auxiliary_hashes=16,
            ),
        ),
        ProvingScenario(
            name="stateless_block_execution",
            description="Representative mixed read/write block witness load",
            workload=estimate_workload_from_access_pattern(
                unique_stems=220,
                average_branch_depth=29,
                reads_per_stem=4,
                writes_per_stem=2,
                auxiliary_hashes=640,
            ),
        ),
        ProvingScenario(
            name="proof_aggregation_burst",
            description="Many stems with moderate reads for batched proving",
            workload=estimate_workload_from_access_pattern(
                unique_stems=640,
                average_branch_depth=30,
                reads_per_stem=3,
                writes_per_stem=1,
                auxiliary_hashes=1200,
            ),
        ),
    ]


def render_profile_report_markdown(
    workload: ProvingWorkload,
    hash_ids: list[str] | None = None,
    baseline_hash_id: str = "keccak256",
    recursive_plan: RecursiveStarkPlan | None = None,
) -> str:
    """Render a markdown comparison report for one workload."""
    comparisons = compare_proving_profiles(
        workload,
        hash_ids=hash_ids,
        baseline_hash_id=baseline_hash_id,
    )
    recursive = {
        row.hash_id: estimate_recursive_stark_execution(
            workload,
            hash_id=row.hash_id,
            plan=recursive_plan,
        )
        for row in comparisons
    }

    lines = [
        "| hash_id | binius | total_hashes | constraints | trace_rows | recursive_trace_rows | constraints_vs_baseline | trace_vs_baseline |",
        "|---|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for row in comparisons:
        profile = get_hash_cost_profile(row.hash_id)
        recursive_row = recursive[row.hash_id]
        lines.append(
            "| "
            f"{row.hash_id} | "
            f"{int(profile.binius_integration)} | "
            f"{row.total_hashes} | "
            f"{row.total_constraints} | "
            f"{row.total_trace_rows} | "
            f"{recursive_row.recursive_trace_rows} | "
            f"{row.constraints_vs_baseline:.3f} | "
            f"{row.trace_rows_vs_baseline:.3f} |"
        )
    return "\n".join(lines)


def compare_proving_profiles(
    workload: ProvingWorkload,
    hash_ids: list[str] | None = None,
    baseline_hash_id: str = "keccak256",
) -> list[ProvingProfileComparison]:
    """Compare circuit and STARK estimates across hash profiles."""
    ids = hash_ids or available_hash_cost_profile_ids()
    if not ids:
        return []

    baseline_circuit = estimate_circuit_cost(workload, baseline_hash_id)
    baseline_stark = estimate_stark_execution(workload, baseline_hash_id)

    if baseline_circuit.total_constraints == 0:
        base_constraints = 1
    else:
        base_constraints = baseline_circuit.total_constraints
    if baseline_stark.total_trace_rows == 0:
        base_trace_rows = 1
    else:
        base_trace_rows = baseline_stark.total_trace_rows

    comparisons: list[ProvingProfileComparison] = []
    for hash_id in ids:
        circuit = estimate_circuit_cost(workload, hash_id)
        stark = estimate_stark_execution(workload, hash_id)
        comparisons.append(
            ProvingProfileComparison(
                hash_id=hash_id,
                total_hashes=workload.total_hashes,
                total_constraints=circuit.total_constraints,
                total_trace_rows=stark.total_trace_rows,
                constraints_vs_baseline=circuit.total_constraints / base_constraints,
                trace_rows_vs_baseline=stark.total_trace_rows / base_trace_rows,
            )
        )

    return sorted(comparisons, key=lambda item: item.hash_id)
