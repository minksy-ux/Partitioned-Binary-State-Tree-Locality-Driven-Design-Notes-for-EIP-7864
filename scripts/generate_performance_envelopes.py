#!/usr/bin/env python3
"""Generate reproducible proving performance envelope artifacts."""

from __future__ import annotations

import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

OUT_PATH = Path("dist/performance-envelopes.json")


def _git_commit() -> str:
    try:
        out = subprocess.check_output(["git", "rev-parse", "HEAD"]).decode("utf-8").strip()
        return out
    except Exception:
        return "unknown"


def main() -> int:
    from pbt.proving_profiles import (
        available_hash_cost_profile_ids,
        calibration_record_for_profile,
        compare_proving_profiles,
        default_proving_scenarios,
        register_calibrated_profiles_from_file,
    )

    calibration_file = Path("pbt-rs/tests/vectors/proving_profile_calibration.json")
    calibrated_ids: list[str] = []
    if calibration_file.exists():
        calibrated_ids = register_calibrated_profiles_from_file(calibration_file)

    scenarios = default_proving_scenarios()
    profile_ids = available_hash_cost_profile_ids()

    records: list[dict[str, object]] = []
    for scenario in scenarios:
        comparisons = compare_proving_profiles(
            scenario.workload,
            hash_ids=profile_ids,
            baseline_hash_id="keccak256",
        )
        rows = []
        for item in comparisons:
            row = {
                "hash_id": item.hash_id,
                "total_hashes": item.total_hashes,
                "total_constraints": item.total_constraints,
                "total_trace_rows": item.total_trace_rows,
                "constraints_vs_baseline": item.constraints_vs_baseline,
                "trace_rows_vs_baseline": item.trace_rows_vs_baseline,
            }
            provenance = calibration_record_for_profile(item.hash_id)
            if provenance is not None:
                row["calibration"] = {
                    "benchmark_suite": provenance.benchmark_suite,
                    "benchmark_commit": provenance.benchmark_commit,
                    "benchmark_command": provenance.benchmark_command,
                    "measured_at_utc": provenance.measured_at_utc,
                    "sample_count": provenance.sample_count,
                }
            rows.append(row)
        records.append(
            {
                "scenario": scenario.name,
                "description": scenario.description,
                "workload": {
                    "internal_node_hashes": scenario.workload.internal_node_hashes,
                    "stem_hashes": scenario.workload.stem_hashes,
                    "auxiliary_hashes": scenario.workload.auxiliary_hashes,
                },
                "profiles": rows,
            }
        )

    output = {
        "schema_version": "1.0.0",
        "generated_at_utc": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "generator_commit": _git_commit(),
        "calibration_source": str(calibration_file) if calibration_file.exists() else "none",
        "registered_calibrated_profiles": calibrated_ids,
        "scenarios": records,
    }

    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUT_PATH.write_text(json.dumps(output, indent=2) + "\n", encoding="utf-8")
    print(f"performance-envelopes: PASS: wrote {OUT_PATH}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
