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
    # Override signing-status.txt to "signing: enabled" so the waiver validation
    # code path is actually exercised (the validator only checks the waiver when
    # signing is enabled in the status file).
    (dist / "signing-status.txt").write_text("signing: enabled\n", encoding="utf-8")
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


def test_validate_supply_chain_rejects_unsigned_release_without_explicit_override(
    tmp_path: Path,
) -> None:
    # signing-status.txt says "signing: unavailable" (from _write_required_artifacts).
    # With strict policy defaults, this must fail unless the override is set.
    _write_required_artifacts(tmp_path)

    env = {
        "PBT_RELEASE_MODE": "1",
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
    assert "strict signing is required by default" in proc.stdout


def test_validate_supply_chain_allows_unsigned_release_with_explicit_override_and_waiver(
    tmp_path: Path,
) -> None:
    _write_required_artifacts(tmp_path)

    (tmp_path / "dist" / "signing-waiver.json").write_text(
        json.dumps(
            {
                "reason": "signing unavailable in ephemeral CI",
                "approved_by": "release-engineering",
                "approved_at_utc": "2026-07-06T00:00:00Z",
                "expires_at_utc": "2026-12-31T00:00:00Z",
            }
        ),
        encoding="utf-8",
    )

    # Mirror explicit graceful override mode.
    env = {
        "PBT_RELEASE_MODE": "1",
        "PBT_SIGNING_GRACEFUL_OVERRIDE": "1",
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


def test_validate_supply_chain_override_requires_waiver(
    tmp_path: Path,
) -> None:
    _write_required_artifacts(tmp_path)

    env = {
        "PBT_RELEASE_MODE": "1",
        "PBT_SIGNING_GRACEFUL_OVERRIDE": "1",
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
    assert "missing signing waiver artifact" in proc.stdout