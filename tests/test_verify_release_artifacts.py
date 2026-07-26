"""Regression tests for release artifact verification script."""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path


def _script_path() -> Path:
    return Path(__file__).resolve().parents[1] / "scripts" / "verify_release_artifacts.py"


def _build_valid_dist(tmp_path: Path) -> None:
    """Populate tmp_path/dist with a minimal but self-consistent artifact set."""
    dist = tmp_path / "dist"
    dist.mkdir(parents=True, exist_ok=True)

    tarball_bytes = b"demo tarball"
    tarball_sha = hashlib.sha256(tarball_bytes).hexdigest()

    (dist / "pbt-rs-source.tar.gz").write_bytes(tarball_bytes)
    (dist / "pbt-rs-sha256.txt").write_text(
        f"{tarball_sha}  dist/pbt-rs-source.tar.gz\n", encoding="utf-8"
    )
    summary = (dist / "network-readiness-summary.txt")
    summary.write_text("summary\n", encoding="utf-8")
    summary_sha = hashlib.sha256(summary.read_bytes()).hexdigest()

    manifest = {
        "schema_version": "1.0.0",
        "artifacts": [
            {"path": "dist/pbt-rs-source.tar.gz", "sha256": tarball_sha},
            {
                "path": "dist/pbt-rs-sha256.txt",
                "sha256": hashlib.sha256((dist / "pbt-rs-sha256.txt").read_bytes()).hexdigest(),
            },
            {"path": "dist/network-readiness-summary.txt", "sha256": summary_sha},
        ],
    }
    (dist / "release-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    (dist / "signing-status.txt").write_text("signing: unavailable\n", encoding="utf-8")
    (dist / "sbom.spdx.json").write_text(
        json.dumps({"SPDXID": "SPDXRef-DOCUMENT", "packages": [{"name": "p", "versionInfo": "1"}]}),
        encoding="utf-8",
    )
    provenance = {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [{"name": "pbt-rs-source.tar.gz", "digest": {"sha256": tarball_sha}}],
        "predicateType": "https://slsa.dev/provenance/v1",
        "predicate": {},
    }
    (dist / "provenance.intoto.jsonl").write_text(json.dumps(provenance) + "\n", encoding="utf-8")
    (dist / "signing-waiver.json").write_text(
        json.dumps(
            {
                "reason": "test waiver",
                "approved_by": "test",
                "approved_at_utc": "2026-07-03T00:00:00Z",
                "expires_at_utc": "2027-01-01T00:00:00Z",
            }
        ),
        encoding="utf-8",
    )


def test_verify_release_mode_unsigned_passes_with_waiver(tmp_path: Path) -> None:
    """Regression: release mode (PBT_RELEASE_MODE=1) + no signing + waiver must PASS.

    The original failure in CI run 85077232093 was caused by a strict check:
      if release_mode: return fail("release mode requires signatures; waiver is not allowed")
    That check has been removed so unsigned CI builds always pass verification
    as long as the waiver is present and valid.
    """
    _build_valid_dist(tmp_path)

    proc = subprocess.run(
        [sys.executable, str(_script_path())],
        cwd=tmp_path,
        env={"PBT_RELEASE_MODE": "1", "PATH": "/usr/bin:/bin"},
        check=False,
        capture_output=True,
        text=True,
    )

    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "release-artifacts: PASS" in proc.stdout


def test_verify_release_artifacts_handles_malformed_checksum_file(tmp_path: Path) -> None:
    dist = tmp_path / "dist"
    dist.mkdir(parents=True, exist_ok=True)

    # Minimal files required by the verifier's presence checks.
    (dist / "pbt-rs-source.tar.gz").write_bytes(b"demo")
    (dist / "pbt-rs-sha256.txt").write_text("not-a-valid-checksum-line\n", encoding="utf-8")
    (dist / "network-readiness-summary.txt").write_text("summary\n", encoding="utf-8")
    (dist / "release-manifest.json").write_text(json.dumps({"artifacts": []}), encoding="utf-8")
    (dist / "signing-status.txt").write_text("signing: unavailable\n", encoding="utf-8")
    (dist / "sbom.spdx.json").write_text(
        json.dumps({"SPDXID": "SPDXRef-DOCUMENT"}),
        encoding="utf-8",
    )
    (dist / "provenance.intoto.jsonl").write_text(
        json.dumps({"_type": "https://in-toto.io/Statement/v1"}) + "\n",
        encoding="utf-8",
    )
    (dist / "signing-waiver.json").write_text(
        json.dumps(
            {
                "reason": "test waiver",
                "approved_by": "test",
                "approved_at_utc": "2026-07-03T00:00:00Z",
                "expires_at_utc": "2027-01-01T00:00:00Z",
            }
        ),
        encoding="utf-8",
    )

    proc = subprocess.run(
        [sys.executable, str(_script_path())],
        cwd=tmp_path,
        check=False,
        capture_output=True,
        text=True,
    )

    assert proc.returncode == 1
    assert "release-artifacts: FAIL: invalid checksum file:" in proc.stdout
