"""Regression tests for CI workflow hardening and anti-waiting behavior."""

from __future__ import annotations

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
AUTO_REVIEW_TRIGGER = ROOT / ".github" / "workflows" / "auto-review-trigger.yml"
NETWORK_READINESS = ROOT / ".github" / "workflows" / "network-readiness.yml"


def _load_yaml(path: Path) -> dict:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def test_auto_review_trigger_is_gated_to_target_repository() -> None:
    data = _load_yaml(AUTO_REVIEW_TRIGGER)
    job = data["jobs"].get("publish-pr-number")
    assert job is not None, "publish-pr-number job must exist"
    assert job.get("if") == "${{ github.repository == 'ethereum/EIPs' }}"


def test_auto_review_trigger_has_non_target_skip_job() -> None:
    data = _load_yaml(AUTO_REVIEW_TRIGGER)
    job = data["jobs"].get("skip-non-target-repo")
    assert job is not None, "skip-non-target-repo job must exist"
    assert job.get("name") == "Skip outside ethereum/EIPs"
    assert job.get("if") == "${{ github.repository != 'ethereum/EIPs' }}"


def test_network_readiness_cancels_stale_runs() -> None:
    data = _load_yaml(NETWORK_READINESS)
    concurrency = data.get("concurrency")
    assert concurrency is not None, "network-readiness workflow must define concurrency"
    assert concurrency.get("group") == "network-readiness-${{ github.workflow }}-${{ github.ref }}"
    assert concurrency.get("cancel-in-progress") is True
