# Activation And Rollback Runbook

## Activation Preconditions

- `network-readiness.manifest.json` gates marked `complete` or `waived`.
- `python scripts/validate_network_readiness.py` passes.
- `python scripts/verify_release_artifacts.py` passes.
- Signed artifacts available and verified.

## Activation Procedure

1. Verify release artifacts and signatures.
2. Roll out to canary client cohort.
3. Run cross-client conformance checks on canary nodes.
4. Promote to broader cohort if no regressions for two epochs.

## Rollback Triggers

- Cross-client root/proof divergence.
- Local verification failure rate exceeds threshold.
- Critical security incident or signature mismatch.

## Rollback Procedure

1. Freeze new activations.
2. Revert to previous known-good release artifact set.
3. Re-run smoke checks: Python/Rust tests and conformance report.
4. Publish incident report and postmortem summary.

## Drill Cadence

- Run `python scripts/run_rollback_drill.py` in CI on every PR.
- Require successful drill artifact output in `dist/rollback-drill-report.json`.
