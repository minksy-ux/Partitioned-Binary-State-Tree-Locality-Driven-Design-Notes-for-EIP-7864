# API Stability Policy

Public API surface is defined by `pbt.__all__` and locked by
`api-surface.lock.json`.

Release policy for breaking API changes:

1. Any export removal from the lock file is a breaking change.
2. Breaking API changes require a major version bump in `pyproject.toml`.
3. Release notes must include the changelog label `api-breaking`.

Validation:

- `scripts/validate_api_surface.py` enforces exact export lock parity.
- `scripts/validate_api_release_policy.py` enforces major bump + label when
  export removals are detected versus the previous commit baseline.
