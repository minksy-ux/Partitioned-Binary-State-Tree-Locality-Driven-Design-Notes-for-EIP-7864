"""Regression tests for the auto-review-bot workflow config-check guard.

These tests verify that the workflow skips `ethereum/eip-review-bot` without
failing when `config/eip-editors.yml` is absent, as implemented in the
``Check review bot config exists`` step.
"""

from __future__ import annotations

from pathlib import Path

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


def test_graceful_skip_when_config_missing() -> None:
    """A graceful non-failing skip path must exist when config is absent."""
    text = _workflow_text()
    assert "Review bot config missing, skip gracefully" in text
    assert "steps.check-config.outputs.exists != 'true'" in text


def test_graceful_skip_when_no_pr_context() -> None:
    """A graceful non-failing skip path must exist when no PR is resolved."""
    text = _workflow_text()
    assert "No PR context, skip gracefully" in text
