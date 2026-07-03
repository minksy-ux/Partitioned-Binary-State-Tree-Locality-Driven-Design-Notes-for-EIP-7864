#!/usr/bin/env python3
"""Execute a lightweight rollback readiness drill and emit a report artifact."""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

REPORT_PATH = Path("dist/rollback-drill-report.json")
DIST = Path("dist")
DRILL_DIR = DIST / "rollback-drill"
TRACKED_FILES = [
    "pbt-rs-source.tar.gz",
    "pbt-rs-sha256.txt",
    "network-readiness-summary.txt",
    "release-manifest.json",
    "signing-status.txt",
    "sbom.spdx.json",
    "provenance.intoto.jsonl",
]


def _run(cmd: list[str]) -> tuple[bool, str]:
    result = subprocess.run(cmd, check=False, capture_output=True, text=True)
    return result.returncode == 0, (result.stdout + result.stderr)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _ensure_release_artifacts() -> tuple[bool, str]:
    return _run([sys.executable, "scripts/build_ef_handoff.py"])


def _snapshot_dist(target_dir: Path) -> None:
    target_dir.mkdir(parents=True, exist_ok=True)
    for name in TRACKED_FILES:
        src = DIST / name
        if src.exists():
            shutil.copy2(src, target_dir / name)
    waiver = DIST / "signing-waiver.json"
    if waiver.exists():
        shutil.copy2(waiver, target_dir / waiver.name)


def _restore_dist(source_dir: Path) -> None:
    for name in TRACKED_FILES + ["signing-waiver.json"]:
        dst = DIST / name
        src = source_dir / name
        if src.exists():
            shutil.copy2(src, dst)
        elif dst.exists():
            dst.unlink()


def main() -> int:
    ensure_ok, ensure_output = _ensure_release_artifacts()
    if not ensure_ok:
        report = {
            "schema_version": "1.0.0",
            "generated_at_utc": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "overall_ok": False,
            "error": "failed to prepare release artifacts",
            "prepare_output_excerpt": "\n".join(ensure_output.splitlines()[-30:]),
        }
        REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
        REPORT_PATH.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        print(f"rollback-drill: FAIL: wrote {REPORT_PATH}")
        return 1

    if DRILL_DIR.exists():
        shutil.rmtree(DRILL_DIR)
    current_dir = DRILL_DIR / "current"
    previous_dir = DRILL_DIR / "previous"
    _snapshot_dist(current_dir)
    _snapshot_dist(previous_dir)

    # Simulate a previous release artifact set by mutating summary while
    # preserving verifier-compatible checksums in manifest for that snapshot.
    summary_path = previous_dir / "network-readiness-summary.txt"
    if summary_path.exists():
        summary_path.write_text(
            summary_path.read_text(encoding="utf-8")
            + "\nrollback-drill: simulated previous release snapshot\n",
            encoding="utf-8",
        )
        manifest_path = previous_dir / "release-manifest.json"
        if manifest_path.exists():
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            for artifact in manifest.get("artifacts", []):
                if artifact.get("path") == "dist/network-readiness-summary.txt":
                    artifact["sha256"] = _sha256(summary_path)
            manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")

    original_hashes = {
        name: _sha256(DIST / name)
        for name in TRACKED_FILES
        if (DIST / name).exists()
    }

    _restore_dist(previous_dir)
    rollback_ok, rollback_output = _run([sys.executable, "scripts/verify_release_artifacts.py"])

    _restore_dist(current_dir)
    restored_ok, restored_output = _run([sys.executable, "scripts/verify_release_artifacts.py"])

    restored_hashes = {
        name: _sha256(DIST / name)
        for name in TRACKED_FILES
        if (DIST / name).exists()
    }
    hashes_restored = restored_hashes == original_hashes

    checks = {
        "python_tests": [sys.executable, "-m", "pytest", "-q", "tests/test_minimal_verifier.py"],
        "rust_tests": [
            "cargo",
            "test",
            "--manifest-path",
            "pbt-rs/Cargo.toml",
            "--",
            "--nocapture",
        ],
        "cross_client_conformance": [sys.executable, "scripts/run_cross_client_conformance.py"],
    }

    results: dict[str, dict[str, object]] = {}
    all_ok = True
    for name, command in checks.items():
        ok, output = _run(command)
        all_ok = all_ok and ok
        results[name] = {
            "ok": ok,
            "command": command,
            "output_excerpt": "\n".join(output.splitlines()[-20:]),
        }

    all_ok = all_ok and rollback_ok and restored_ok and hashes_restored
    results["rollback_swap_verify"] = {
        "ok": rollback_ok,
        "command": [sys.executable, "scripts/verify_release_artifacts.py"],
        "output_excerpt": "\n".join(rollback_output.splitlines()[-20:]),
    }
    results["restore_verify"] = {
        "ok": restored_ok,
        "command": [sys.executable, "scripts/verify_release_artifacts.py"],
        "output_excerpt": "\n".join(restored_output.splitlines()[-20:]),
    }
    results["restored_hashes_match_original"] = {
        "ok": hashes_restored,
        "expected": original_hashes,
        "actual": restored_hashes,
    }

    report = {
        "schema_version": "1.0.0",
        "generated_at_utc": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "overall_ok": all_ok,
        "checks": results,
    }
    REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
    REPORT_PATH.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

    if all_ok:
        print(f"rollback-drill: PASS: wrote {REPORT_PATH}")
        return 0

    print(f"rollback-drill: FAIL: wrote {REPORT_PATH}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
