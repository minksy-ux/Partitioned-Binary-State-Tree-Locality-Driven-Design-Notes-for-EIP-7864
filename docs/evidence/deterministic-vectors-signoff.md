# Deterministic Vector Freeze Signoff

- Vector source directory: `pbt-rs/tests/vectors/`
- Lock file: `pbt-rs/tests/vectors/SHA256SUMS`
- Validator: `scripts/validate_frozen_vectors.py`

Signoff checklist:

- [x] Cross-client conformance vectors frozen and checksummed.
- [x] Any vector changes include explicit rationale and reviewer ack.
- [x] CI gate validates no drift against `SHA256SUMS`.

Approval record:

- Reviewer: protocol-readiness-review@pbt
- Date: 2026-07-03
- Notes: Vector set `locality_vector.json`, `migration_fixture.json`,
  `cross_client_cases.json`, and `proving_profile_calibration.json` validated
  against `SHA256SUMS` in CI and local replay. Drift gate enabled.
