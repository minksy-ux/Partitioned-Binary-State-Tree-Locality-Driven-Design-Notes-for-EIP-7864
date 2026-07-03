"""Formal verification dashboard for release readiness tracking."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone

from .formal import FormalVerificationPolicy, ProofArtifact


@dataclass(frozen=True)
class DashboardComponentRow:
    component: str
    required: bool
    present: bool
    machine_checked: bool
    has_checker_commands: bool
    ai_assisted: bool
    has_independent_recheck: bool
    status: str
    gap_reasons: tuple[str, ...]


@dataclass(frozen=True)
class FormalVerificationDashboardSnapshot:
    generated_at_utc: str
    overall_status: str
    total_required: int
    required_present: int
    required_fully_verified: int
    total_artifacts: int
    machine_checked_artifacts: int
    ai_assisted_artifacts: int
    ai_assisted_with_recheck: int
    policy_errors: tuple[str, ...]
    component_rows: tuple[DashboardComponentRow, ...]


class FormalVerificationDashboard:
    """Builds compact, machine-readable readiness snapshots."""

    def __init__(self, policy: FormalVerificationPolicy):
        self.policy = policy

    def build_snapshot(
        self,
        artifacts: list[ProofArtifact],
        generated_at_utc: str | None = None,
    ) -> FormalVerificationDashboardSnapshot:
        by_component: dict[str, ProofArtifact] = {}
        duplicate_components: list[str] = []
        for artifact in artifacts:
            if artifact.component in by_component:
                duplicate_components.append(artifact.component)
            by_component[artifact.component] = artifact

        required_set = set(self.policy.required_components)
        component_names = sorted(required_set.union(by_component.keys()))

        rows: list[DashboardComponentRow] = []
        required_present = 0
        required_fully_verified = 0

        for component in component_names:
            artifact = by_component.get(component)
            required = component in required_set
            gap_reasons: list[str] = []

            if artifact is None:
                if required:
                    gap_reasons.append("missing required proof artifact")
                row = DashboardComponentRow(
                    component=component,
                    required=required,
                    present=False,
                    machine_checked=False,
                    has_checker_commands=False,
                    ai_assisted=False,
                    has_independent_recheck=False,
                    status="GAP" if required else "OPTIONAL",
                    gap_reasons=tuple(gap_reasons),
                )
                rows.append(row)
                continue

            if required:
                required_present += 1

            has_checker_commands = bool(artifact.checker_commands)
            has_independent_recheck = bool(artifact.independent_recheck_commands)

            if required and not artifact.machine_checked:
                gap_reasons.append("not machine-checked")
            if required and not has_checker_commands:
                gap_reasons.append("missing checker_commands")
            if required and artifact.ai_assisted and not has_independent_recheck:
                gap_reasons.append("AI-assisted artifact missing independent_recheck_commands")

            if required:
                status = "VERIFIED" if not gap_reasons else "GAP"
                if status == "VERIFIED":
                    required_fully_verified += 1
            else:
                status = "OPTIONAL"

            row = DashboardComponentRow(
                component=component,
                required=required,
                present=True,
                machine_checked=artifact.machine_checked,
                has_checker_commands=has_checker_commands,
                ai_assisted=artifact.ai_assisted,
                has_independent_recheck=has_independent_recheck,
                status=status,
                gap_reasons=tuple(gap_reasons),
            )
            rows.append(row)

        policy_errors = list(self.policy.validate(artifacts))
        for component in duplicate_components:
            policy_errors.append(f"duplicate proof artifact for component: {component}")

        machine_checked_artifacts = sum(1 for a in artifacts if a.machine_checked)
        ai_assisted_artifacts = sum(1 for a in artifacts if a.ai_assisted)
        ai_assisted_with_recheck = sum(
            1
            for a in artifacts
            if a.ai_assisted and bool(a.independent_recheck_commands)
        )

        overall_status = (
            "PASS"
            if not policy_errors and required_fully_verified == len(self.policy.required_components)
            else "ATTENTION"
        )

        return FormalVerificationDashboardSnapshot(
            generated_at_utc=generated_at_utc or _utc_now_iso(),
            overall_status=overall_status,
            total_required=len(self.policy.required_components),
            required_present=required_present,
            required_fully_verified=required_fully_verified,
            total_artifacts=len(artifacts),
            machine_checked_artifacts=machine_checked_artifacts,
            ai_assisted_artifacts=ai_assisted_artifacts,
            ai_assisted_with_recheck=ai_assisted_with_recheck,
            policy_errors=tuple(policy_errors),
            component_rows=tuple(rows),
        )

    def render_markdown(
        self,
        snapshot: FormalVerificationDashboardSnapshot,
        include_phone_user_story: bool = False,
    ) -> str:
        lines: list[str] = []
        lines.append("# Formal Verification Dashboard")
        lines.append("")
        lines.append(f"- generated_at_utc: {snapshot.generated_at_utc}")
        lines.append(f"- overall_status: {snapshot.overall_status}")
        lines.append(
            "- required_coverage: "
            f"{snapshot.required_fully_verified}/{snapshot.total_required} fully verified"
        )
        lines.append(
            "- machine_checked_artifacts: "
            f"{snapshot.machine_checked_artifacts}/{snapshot.total_artifacts}"
        )
        lines.append(
            "- ai_assisted_recheck_coverage: "
            f"{snapshot.ai_assisted_with_recheck}/{snapshot.ai_assisted_artifacts}"
        )
        lines.append("")
        lines.append("| Component | Scope | Status | Machine-Checked | Checker Commands | AI-Assisted | Independent Recheck | Gaps |")
        lines.append("|---|---|---|---|---|---|---|---|")

        for row in snapshot.component_rows:
            scope = "required" if row.required else "optional"
            gaps = "; ".join(row.gap_reasons) if row.gap_reasons else "-"
            lines.append(
                "| "
                f"{row.component} | {scope} | {row.status} | "
                f"{_yes_no(row.machine_checked)} | {_yes_no(row.has_checker_commands)} | "
                f"{_yes_no(row.ai_assisted)} | {_yes_no(row.has_independent_recheck)} | {gaps} |"
            )

        if snapshot.policy_errors:
            lines.append("")
            lines.append("## Policy Errors")
            for err in snapshot.policy_errors:
                lines.append(f"- {err}")

        if include_phone_user_story:
            lines.append("")
            lines.append("## Phone User Story")
            lines.append("")
            lines.append("A user on a mid-range Android device opens a wallet to check balances, token approvals, and NFT ownership.")
            lines.append("")
            lines.append("1. The wallet requests state payloads and proof material from one or more witness providers.")
            lines.append("2. The wallet verifies header linkage and PBT proofs locally before showing final values.")
            lines.append("3. Frequently used verified stems are cached locally for fast follow-up reads.")
            lines.append("4. If responses are incomplete or conflicting, retrieval widens and retries automatically.")
            lines.append("5. The UI clearly marks pending or unverified data until local checks succeed.")

        return "\n".join(lines)


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _yes_no(flag: bool) -> str:
    return "yes" if flag else "no"
