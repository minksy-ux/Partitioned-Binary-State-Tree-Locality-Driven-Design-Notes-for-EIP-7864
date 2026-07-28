"""Regression tests for the auto-review-bot workflow config-check guard.

These tests verify that the workflow skips `ethereum/eip-review-bot` without
failing when `config/eip-editors.yml` is absent, as implemented in the
``Check review bot config exists`` step.
"""

from __future__ import annotations

from pathlib import Path

import yaml

_WORKFLOW = Path(__file__).resolve().parents[1] / ".github" / "workflows" / "auto-review-bot.yml"


def _workflow_text() -> str:
    return _WORKFLOW.read_text(encoding="utf-8")


def test_workflow_file_exists() -> None:
    assert _WORKFLOW.exists(), "auto-review-bot.yml must exist"


def test_config_check_step_present() -> None:
    """A dedicated step must check for config/eip-editors.yml existence."""
    text = _workflow_text()
    assert "Check review bot config exists" in text
    assert "config/eip-editors.yml" in text
    assert "check-config" in text


def test_review_bot_gated_on_config_existence() -> None:
    """The Auto Review Bot step must only run when the config file is present."""
    text = _workflow_text()
    # The condition must reference check-config output
    assert "steps.check-config.outputs.exists == 'true'" in text


def test_review_bot_gated_on_target_repository() -> None:
    """The Auto Review Bot step must only run for the ethereum/EIPs repository."""
    text = _workflow_text()
    assert "github.repository == 'ethereum/EIPs'" in text


def test_graceful_skip_when_config_missing() -> None:
    """A graceful non-failing skip path must exist when config is absent."""
    text = _workflow_text()
    assert "Review bot config missing, skip gracefully" in text
    assert "steps.check-config.outputs.exists != 'true'" in text


def test_graceful_skip_when_no_pr_context() -> None:
    """A graceful non-failing skip path must exist when no PR is resolved."""
    text = _workflow_text()
    assert "No PR context, skip gracefully" in text


def test_review_bot_step_is_non_blocking() -> None:
    """The Auto Review Bot step must not fail the job when the bot returns an error."""
    data = yaml.safe_load(_workflow_text())
    steps = data["jobs"]["auto-review-bot"]["steps"]
    bot_step = next((s for s in steps if s.get("name") == "Auto Review Bot"), None)
    assert bot_step is not None, "Auto Review Bot step must exist"
    assert bot_step.get("continue-on-error") is True, (
        "Auto Review Bot step must have continue-on-error: true"
    )


def test_review_bot_step_is_guarded_to_ethereum_eips_repo() -> None:
    """The bot should run only in ethereum/EIPs to avoid external fork failures."""
    text = _workflow_text()
    assert "github.repository == 'ethereum/EIPs'" in text


def test_review_bot_job_is_guarded_to_ethereum_eips_repo() -> None:
    """The job itself should be gated to avoid unnecessary non-target execution."""
    text = _workflow_text()
    assert "github.event.workflow_run.conclusion == 'success' && github.repository == 'ethereum/EIPs'" in text


def test_review_bot_action_is_pinned_to_latest_stable_commit() -> None:
    """The action pin must match the reviewed stable upstream commit."""
    text = _workflow_text()
    assert (
        "uses: ethereum/eip-review-bot@ce664cd9250a11ecf9420b8a29cafafa9ca7ce75"
        in text
    )


def test_non_target_repo_skip_job_exists() -> None:
    """A dedicated job should report skip details for non-target repositories."""
    data = yaml.safe_load(_workflow_text())
    job = data["jobs"].get("skip-non-target-repo")
    assert job is not None, "skip-non-target-repo job must exist"
    assert job.get("name") == "Skip outside ethereum/EIPs"
    assert (
        job.get("if")
        == "${{ github.event.workflow_run.conclusion == 'success' && github.repository != 'ethereum/EIPs' }}"
    )
