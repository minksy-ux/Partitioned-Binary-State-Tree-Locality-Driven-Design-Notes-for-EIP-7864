"""Regression tests for release artifact verification script."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


def _script_path() -> Path:
    return Path(__file__).resolve().parents[1] / "scripts" / "verify_release_artifacts.py"


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
