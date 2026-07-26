#!/usr/bin/env bash
set -euo pipefail

# Block tracked generated artifacts from entering history.
TRACKED_ARTIFACTS=$(git ls-files | grep -E '(^|/)__pycache__/|\.py[cod]$|^pbt-rs/target/' || true)

if [ -n "$TRACKED_ARTIFACTS" ]; then
  echo "Tracked generated artifacts are not allowed:"
  echo "$TRACKED_ARTIFACTS"
  exit 1
fi

echo "No tracked generated artifacts found."