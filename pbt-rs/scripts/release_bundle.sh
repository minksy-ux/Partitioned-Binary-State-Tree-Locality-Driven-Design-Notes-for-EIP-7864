#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
DIST_DIR="$ROOT_DIR/dist"
RUST_DIR="$ROOT_DIR/pbt-rs"

mkdir -p "$DIST_DIR"

# Ensure tests are green before producing handoff artifacts.
if [[ -f "$HOME/.cargo/env" ]]; then
  # shellcheck disable=SC1090
  source "$HOME/.cargo/env"
fi

pushd "$ROOT_DIR" >/dev/null
cargo test --manifest-path "$RUST_DIR/Cargo.toml"

if command -v pytest >/dev/null 2>&1; then
  pytest -q
else
  echo "pytest not found; skipping Python test run" >&2
fi

TARBALL="$DIST_DIR/pbt-rs-source.tar.gz"
SHA_FILE="$DIST_DIR/pbt-rs-sha256.txt"
SUMMARY_FILE="$DIST_DIR/network-readiness-summary.txt"

rm -f "$TARBALL" "$SHA_FILE" "$SUMMARY_FILE"

tar \
  --exclude='pbt-rs/target' \
  --exclude='.git' \
  --exclude='.pytest_cache' \
  --exclude='.hypothesis' \
  -czf "$TARBALL" \
  pbt-rs \
  EF_NETWORK_HANDOFF.md \
  README.md \
  IMPLEMENTATION.md

sha256sum "$TARBALL" > "$SHA_FILE"

{
  echo "Network readiness bundle generated"
  echo "Timestamp (UTC): $(date -u +"%Y-%m-%dT%H:%M:%SZ")"
  echo "Git commit: $(git rev-parse HEAD)"
  echo "Tarball: $TARBALL"
  echo "Checksum file: $SHA_FILE"
} > "$SUMMARY_FILE"

popd >/dev/null

echo "Bundle created: $TARBALL"
echo "Checksum: $SHA_FILE"
echo "Summary: $SUMMARY_FILE"
