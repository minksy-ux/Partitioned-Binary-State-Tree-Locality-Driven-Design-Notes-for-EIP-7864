# EF Client Quickstart

## Contents

- network-readiness.manifest.json
- RELEASE_NOTES.md
- EF_NETWORK_HANDOFF.md
- release-manifest.json
- signing-status.txt
- pbt-rs-source.tar.gz
- pbt-rs-sha256.txt

## Verify package integrity

1. Read signing-status.txt to determine signature availability.
2. Verify pbt-rs-source.tar.gz hash against pbt-rs-sha256.txt.
3. Verify release-manifest.json checksums against bundled files.

## Reproduce project checks

1. Run Python suite: pytest -q
2. Run Rust suite: cargo test --manifest-path pbt-rs/Cargo.toml
3. Run policy validators:
   - python scripts/validate_network_readiness.py
   - python scripts/validate_release_notes.py
   - python scripts/verify_release_artifacts.py

## Promotion policy

production_eligible MUST only be true when all readiness gates are complete
or waived and release artifacts are verified.
