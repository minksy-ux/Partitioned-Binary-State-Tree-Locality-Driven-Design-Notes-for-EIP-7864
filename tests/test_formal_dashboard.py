"""Tests for the formal verification dashboard."""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from pbt.formal import ProofArtifact, default_policy, default_release_artifacts
from pbt.formal_dashboard import FormalVerificationDashboard


def _complete_required_artifacts() -> list[ProofArtifact]:
    return default_release_artifacts()


def test_dashboard_passes_for_complete_required_artifacts():
    dashboard = FormalVerificationDashboard(default_policy())
    snapshot = dashboard.build_snapshot(_complete_required_artifacts())

    assert snapshot.overall_status == "PASS"
    assert snapshot.required_fully_verified == snapshot.total_required
    assert snapshot.policy_errors == ()

    rendered = dashboard.render_markdown(snapshot)
    assert "# Formal Verification Dashboard" in rendered
    assert "| consensus_rules | required | VERIFIED |" in rendered


def test_dashboard_flags_ai_assisted_missing_recheck():
    dashboard = FormalVerificationDashboard(default_policy())
    artifacts = _complete_required_artifacts()
    artifacts[-1] = ProofArtifact(
        component="pbt_insert_delete",
        proof_system="Lean4",
        machine_checked=True,
        checker_commands=("lean --run pbt.lean",),
        ai_assisted=True,
        independent_recheck_commands=(),
    )

    snapshot = dashboard.build_snapshot(artifacts)

    assert snapshot.overall_status == "ATTENTION"
    assert any("independent recheck" in err.lower() for err in snapshot.policy_errors)

    row = next(r for r in snapshot.component_rows if r.component == "pbt_insert_delete")
    assert row.status == "GAP"
    assert any("independent_recheck_commands" in reason for reason in row.gap_reasons)


def test_dashboard_flags_duplicate_component_artifacts():
    dashboard = FormalVerificationDashboard(default_policy())
    artifacts = _complete_required_artifacts()
    artifacts.append(
        ProofArtifact(
            component="consensus_rules",
            proof_system="Lean4",
            machine_checked=True,
            checker_commands=("lean --run consensus-alt.lean",),
        )
    )

    snapshot = dashboard.build_snapshot(artifacts)

    assert snapshot.overall_status == "ATTENTION"
    assert any("duplicate proof artifact" in err for err in snapshot.policy_errors)


def test_dashboard_can_render_phone_user_story_section():
    dashboard = FormalVerificationDashboard(default_policy())
    snapshot = dashboard.build_snapshot(_complete_required_artifacts())

    rendered = dashboard.render_markdown(snapshot, include_phone_user_story=True)
    assert "## Phone User Story" in rendered
    assert "mid-range Android device" in rendered
