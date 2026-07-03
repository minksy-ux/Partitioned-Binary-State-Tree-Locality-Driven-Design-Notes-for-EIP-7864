#!/usr/bin/env python3
"""Validate network-readiness.manifest.json for EF/client CI gating."""

from __future__ import annotations

import json
import sys
from pathlib import Path

ALLOWED_STATUS = {"pending", "in_progress", "complete", "waived"}
REQUIRED_GATES = [
    "crypto_review",
    "cross_client_conformance",
    "deterministic_vectors_frozen",
    "performance_envelopes_published",
    "activation_and_rollback_plan",
]


def fail(message: str) -> int:
    print(f"network-readiness: FAIL: {message}")
    return 1


def main() -> int:
    manifest_path = Path("network-readiness.manifest.json")
    if not manifest_path.exists():
        return fail("missing network-readiness.manifest.json")

    try:
        data = json.loads(manifest_path.read_text(encoding="utf-8"))
    except Exception as exc:  # pragma: no cover - defensive parse guard
        return fail(f"invalid JSON: {exc}")

    for key in [
        "schema_version",
        "production_profile",
        "experimental_profile",
        "gates",
        "release_decision",
    ]:
        if key not in data:
            return fail(f"missing required top-level field: {key}")

    production = data["production_profile"]
    release_decision = data["release_decision"]
    gates = data["gates"]

    if not isinstance(production.get("allowed_hash_modes"), list):
        return fail("production_profile.allowed_hash_modes must be a list")

    if "gemini" in production.get("allowed_hash_modes", []):
        return fail("gemini cannot be in production_profile.allowed_hash_modes")

    if production.get("allow_vectorfold") is True:
        return fail("production_profile.allow_vectorfold must be false")

    for gate in REQUIRED_GATES:
        if gate not in gates:
            return fail(f"missing required gate: {gate}")
        status = gates[gate].get("status")
        if status not in ALLOWED_STATUS:
            return fail(f"invalid status for {gate}: {status}")

    production_eligible = release_decision.get("production_eligible")
    if not isinstance(production_eligible, bool):
        return fail("release_decision.production_eligible must be boolean")

    blocking = [
        gate
        for gate in REQUIRED_GATES
        if gates[gate].get("status") not in {"complete", "waived"}
    ]

    if production_eligible and blocking:
        return fail(
            "production_eligible is true but blocking gates remain: "
            + ", ".join(blocking)
        )

    print("network-readiness: PASS")
    print(f"network-readiness: production_eligible={production_eligible}")
    if blocking:
        print("network-readiness: blocking_gates=" + ", ".join(blocking))
    return 0


if __name__ == "__main__":
    sys.exit(main())
