"""Regression tests for supply chain artifact validator signing policy."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


def _script_path() -> Path:
    return Path(__file__).resolve().parents[1] / "scripts" / "validate_supply_chain_artifacts.py"


def _write_required_artifacts(tmp_path: Path) -> None:
    dist = tmp_path / "dist"
    dist.mkdir(parents=True, exist_ok=True)

    (tmp_path / "requirements.lock").write_text("pytest==8.0.0\n", encoding="utf-8")
    (dist / "sbom.spdx.json").write_text(
        json.dumps(
            {
                "SPDXID": "SPDXRef-DOCUMENT",
                "packages": [{"name": "pbt", "versionInfo": "0.0.0-test"}],
            }
        ),
        encoding="utf-8",
    )
    (dist / "provenance.intoto.jsonl").write_text(
        json.dumps(
            {
                "subject": [
                    {
                        "name": "dummy",
                        "digest": {
                            "sha256": "a" * 64,
                        },
                    }
                ]
            }
        )
        + "\n",
        encoding="utf-8",
    )
    (dist / "signing-status.txt").write_text("signing: unavailable\n", encoding="utf-8")


def test_validate_supply_chain_allows_waiver_before_release_mode_signing_failure(
    tmp_path: Path,
) -> None:
    _write_required_artifacts(tmp_path)
    dist = tmp_path / "dist"
    (dist / "signing-waiver.json").write_text(
        json.dumps(
            {
                "reason": "CI runner has no key material",
                "approved_by": "release-engineering",
                "approved_at_utc": "2026-07-04T00:00:00Z",
                "expires_at_utc": "2026-12-31T00:00:00Z",
            }
        ),
        encoding="utf-8",
    )

    env = {
        "PBT_RELEASE_MODE": "1",
        "PBT_SIGNING_ENABLED": "1",
    }

    proc = subprocess.run(
        [sys.executable, str(_script_path())],
        cwd=tmp_path,
        env=env,
        check=False,
        capture_output=True,
        text=True,
    )

    assert proc.returncode == 0
    assert "supply-chain: PASS" in proc.stdout


def test_validate_supply_chain_fails_in_release_mode_when_waiver_missing(
    tmp_path: Path,
) -> None:
    _write_required_artifacts(tmp_path)

    env = {
        "PBT_RELEASE_MODE": "1",
        "PBT_SIGNING_ENABLED": "1",
    }

    proc = subprocess.run(
        [sys.executable, str(_script_path())],
        cwd=tmp_path,
        env=env,
        check=False,
        capture_output=True,
        text=True,
    )

    assert proc.returncode == 1
    assert "release mode requires signing: enabled when PBT_SIGNING_ENABLED=1" in proc.stdout