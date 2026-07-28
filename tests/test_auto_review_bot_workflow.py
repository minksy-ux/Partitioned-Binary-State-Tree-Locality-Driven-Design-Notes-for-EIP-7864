"""Regression tests for the auto-review-bot workflow config-check guard.

These tests verify that the workflow skips `ethereum/eip-review-bot` without
failing when `config/eip-editors.yml` is absent, as implemented in the
``Check review bot config exists`` step.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

_WORKFLOW = Path(__file__).resolve().parents[1] / ".github" / "workflows" / "auto-review-bot.yml"
# Pattern matching a fully-pinned action ref: owner/repo@<40 lowercase hex chars>
_SHA_PIN_PATTERN = re.compile(r"^[^@]+@[0-9a-f]{40}$")


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


def test_review_bot_step_is_non_blocking() -> None:
    """The Auto Review Bot step must not fail the job when the bot returns an error."""
    data = yaml.safe_load(_workflow_text())
    steps = data["jobs"]["auto-review-bot"]["steps"]
    bot_step = next((s for s in steps if s.get("name") == "Auto Review Bot"), None)
    assert bot_step is not None, "Auto Review Bot step must exist"
    assert bot_step.get("continue-on-error") is True, (
        "Auto Review Bot step must have continue-on-error: true"
    )


def test_review_bot_action_sha_is_pinned() -> None:
    """The eip-review-bot action must be pinned to a full commit SHA, not a mutable tag."""
    data = yaml.safe_load(_workflow_text())
    steps = data["jobs"]["auto-review-bot"]["steps"]
    bot_step = next((s for s in steps if s.get("name") == "Auto Review Bot"), None)
    assert bot_step is not None, "Auto Review Bot step must exist"
    uses = bot_step.get("uses", "")
    assert _SHA_PIN_PATTERN.match(uses), (
        f"Auto Review Bot action must be pinned to a full commit SHA (40 hex chars), got: {uses!r}"
    )


def test_outcome_summary_step_present() -> None:
    """A 'Report Auto Review Bot outcome' step must surface the bot result for observability."""
    data = yaml.safe_load(_workflow_text())
    steps = data["jobs"]["auto-review-bot"]["steps"]
    report_step = next(
        (s for s in steps if s.get("name") == "Report Auto Review Bot outcome"), None
    )
    assert report_step is not None, (
        "Workflow must contain a 'Report Auto Review Bot outcome' step"
    )
    # The step must only run when the bot actually ran (not when it was skipped)
    condition = report_step.get("if", "")
    assert condition == "steps.auto-review-bot.outcome != 'skipped'", (
        "Outcome summary step must have exactly "
        "if: steps.auto-review-bot.outcome != 'skipped'; "
        f"got: {condition!r}"
    )
