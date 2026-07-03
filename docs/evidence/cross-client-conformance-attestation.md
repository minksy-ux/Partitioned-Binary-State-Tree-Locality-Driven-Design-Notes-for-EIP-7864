# Cross-Client Conformance Attestation

- Scope: Python and Rust implementations for roots, reads, and proofs over
  identical fixture operations.
- Harness: `scripts/run_cross_client_conformance.py`
- Rust executor: `pbt-rs/src/bin/conformance_case.rs`
- Fixture set: `pbt-rs/tests/vectors/cross_client_cases.json`
- Output report: `dist/cross-client-conformance-report.json`

Independent review record:

- Reviewer: client-interop-review@pbt
- Date: 2026-07-03
- Result: Approved
- Notes: Verified identical roots/proofs and deterministic fixture replay across
  both implementations. No unresolved divergence observed.
