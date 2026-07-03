"""Formal-verification policy checks for consensus-critical releases.

This module does not prove correctness itself; it enforces release-time metadata
requirements that each critical component has machine-checked proofs and that
AI-assisted proofs are independently re-checkable.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ProofArtifact:
    component: str
    proof_system: str
    machine_checked: bool
    checker_commands: tuple[str, ...]
    ai_assisted: bool = False
    independent_recheck_commands: tuple[str, ...] = ()


class FormalVerificationPolicy:
    """Validates that required components satisfy machine-checking constraints."""

    def __init__(self, required_components: tuple[str, ...]):
        if not required_components:
            raise ValueError("required_components must not be empty")
        self.required_components = required_components

    def validate(self, artifacts: list[ProofArtifact]) -> list[str]:
        errors: list[str] = []
        by_component = {a.component: a for a in artifacts}

        for component in self.required_components:
            if component not in by_component:
                errors.append(f"missing proof artifact for required component: {component}")
                continue

            artifact = by_component[component]
            if not artifact.machine_checked:
                errors.append(f"component {component} is not machine-checked")
            if not artifact.checker_commands:
                errors.append(f"component {component} missing checker_commands")

            if artifact.ai_assisted:
                if not artifact.machine_checked:
                    errors.append(f"AI-assisted component {component} must be machine-checked")
                if not artifact.independent_recheck_commands:
                    errors.append(
                        f"AI-assisted component {component} missing independent recheck commands"
                    )

        return errors


DEFAULT_REQUIRED_COMPONENTS: tuple[str, ...] = (
    "consensus_rules",
    "evm_state_transition",
    "critical_system_contracts",
    "pbt_insert_delete",
)


def default_policy() -> FormalVerificationPolicy:
    return FormalVerificationPolicy(DEFAULT_REQUIRED_COMPONENTS)


def default_release_artifacts() -> list[ProofArtifact]:
    """Return a canonical set of example proof artifacts for demos and tooling."""
    return [
        ProofArtifact(
            component="consensus_rules",
            proof_system="Lean4",
            machine_checked=True,
            checker_commands=("lean --run consensus.lean",),
        ),
        ProofArtifact(
            component="evm_state_transition",
            proof_system="Coq",
            machine_checked=True,
            checker_commands=("coqc evm.v",),
        ),
        ProofArtifact(
            component="critical_system_contracts",
            proof_system="Isabelle",
            machine_checked=True,
            checker_commands=("isabelle build contracts",),
        ),
        ProofArtifact(
            component="pbt_insert_delete",
            proof_system="Lean4",
            machine_checked=True,
            checker_commands=("lean --run pbt.lean",),
            ai_assisted=True,
            independent_recheck_commands=("lean --run pbt.lean", "lake test"),
        ),
    ]
