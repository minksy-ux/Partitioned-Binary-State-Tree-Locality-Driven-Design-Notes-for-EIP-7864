"""Tests for formal-verification policy enforcement helpers."""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from pbt.formal import ProofArtifact, default_policy


def test_default_policy_accepts_complete_machine_checked_artifacts():
    policy = default_policy()
    artifacts = [
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
    assert policy.validate(artifacts) == []


def test_policy_flags_missing_component_and_machine_checking_errors():
    policy = default_policy()
    artifacts = [
        ProofArtifact(
            component="consensus_rules",
            proof_system="Lean4",
            machine_checked=False,
            checker_commands=(),
        )
    ]

    errors = policy.validate(artifacts)
    assert any("missing proof artifact for required component: evm_state_transition" in e for e in errors)
    assert any("component consensus_rules is not machine-checked" in e for e in errors)
    assert any("component consensus_rules missing checker_commands" in e for e in errors)


def test_policy_requires_independent_recheck_for_ai_assisted_artifacts():
    policy = default_policy()
    artifacts = [
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
            independent_recheck_commands=(),
        ),
    ]

    errors = policy.validate(artifacts)
    assert any("AI-assisted component pbt_insert_delete missing independent recheck commands" in e for e in errors)
