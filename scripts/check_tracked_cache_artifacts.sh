#!/usr/bin/env bash
set -euo pipefail

# Block tracked Python cache/bytecode artifacts from entering history.
TRACKED_CACHE_ARTIFACTS=$(git ls-files | grep -E '(^|/)__pycache__/|\.py[cod]$' || true)

if [ -n "$TRACKED_CACHE_ARTIFACTS" ]; then
  echo "Tracked Python cache/bytecode artifacts are not allowed:"
  echo "$TRACKED_CACHE_ARTIFACTS"
  exit 1
fi

echo "No tracked Python cache/bytecode artifacts found."