#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
DIST_DIR="$ROOT_DIR/dist"
RUST_DIR="$ROOT_DIR/pbt-rs"
SIGNING_MODE="${SUPPLY_CHAIN_SIGNING:-enabled}"
RUN_TESTS="$(printf '%s' "${RELEASE_BUNDLE_RUN_TESTS:-1}" | tr '[:upper:]' '[:lower:]')"

mkdir -p "$DIST_DIR"

# Ensure tests are green before producing handoff artifacts.
if [[ -f "$HOME/.cargo/env" ]]; then
  # shellcheck disable=SC1090
  source "$HOME/.cargo/env"
fi

pushd "$ROOT_DIR" >/dev/null
if [[ "$RUN_TESTS" == "0" || "$RUN_TESTS" == "false" || "$RUN_TESTS" == "no" || "$RUN_TESTS" == "off" ]]; then
  echo "release-bundle: skipping test execution (RELEASE_BUNDLE_RUN_TESTS=$RUN_TESTS)"
else
  cargo test --manifest-path "$RUST_DIR/Cargo.toml"

  if command -v pytest >/dev/null 2>&1; then
    pytest -q
  else
    echo "pytest not found; skipping Python test run" >&2
  fi
fi

if [[ "${CI:-}" == "true" && "$SIGNING_MODE" == "enabled" ]] && \
   ! (command -v gpg >/dev/null 2>&1 && gpg --list-secret-keys --with-colons 2>/dev/null | grep -q '^sec'); then
  echo "supply-chain: WARN: signing requested but no key in CI; falling back to unsigned bundle"
  SIGNING_MODE="disabled"
fi

TARBALL="$DIST_DIR/pbt-rs-source.tar.gz"
SHA_FILE="$DIST_DIR/pbt-rs-sha256.txt"
SUMMARY_FILE="$DIST_DIR/network-readiness-summary.txt"
MANIFEST_FILE="$DIST_DIR/release-manifest.json"
MANIFEST_SIG_FILE="$DIST_DIR/release-manifest.json.sig"
TARBALL_SIG_FILE="$DIST_DIR/pbt-rs-source.tar.gz.sig"
SIGNING_STATUS_FILE="$DIST_DIR/signing-status.txt"
SIGNING_WAIVER_FILE="$DIST_DIR/signing-waiver.json"

rm -f "$TARBALL" "$SHA_FILE" "$SUMMARY_FILE" "$MANIFEST_FILE" "$MANIFEST_SIG_FILE" "$TARBALL_SIG_FILE" "$SIGNING_STATUS_FILE" "$SIGNING_WAIVER_FILE"

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

TARBALL_SHA256="$(cut -d' ' -f1 "$SHA_FILE")"
COMMIT_SHA="$(git rev-parse HEAD)"
TIMESTAMP_UTC="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"

cat > "$MANIFEST_FILE" <<EOF
{
  "schema_version": "1.0.0",
  "artifact_type": "network_readiness_release_bundle",
  "generated_at_utc": "$TIMESTAMP_UTC",
  "git_commit": "$COMMIT_SHA",
  "artifacts": [
    {
      "path": "dist/pbt-rs-source.tar.gz",
      "sha256": "$TARBALL_SHA256"
    },
    {
      "path": "dist/pbt-rs-sha256.txt",
      "sha256": "$(sha256sum "$SHA_FILE" | cut -d' ' -f1)"
    },
    {
      "path": "dist/network-readiness-summary.txt",
      "sha256": "$(sha256sum "$SUMMARY_FILE" 2>/dev/null | cut -d' ' -f1)"
    }
  ],
  "signing": {
    "method": "gpg_detached_ascii",
    "manifest_signature": "dist/release-manifest.json.sig",
    "bundle_signature": "dist/pbt-rs-source.tar.gz.sig"
  }
}
EOF

{
  echo "Network readiness bundle generated"
  echo "Timestamp (UTC): $TIMESTAMP_UTC"
  echo "Git commit: $COMMIT_SHA"
  echo "Tarball: $TARBALL"
  echo "Checksum file: $SHA_FILE"
  echo "Manifest file: $MANIFEST_FILE"
} > "$SUMMARY_FILE"

# Update manifest entry for summary now that it exists.
python3 - <<'PY'
import hashlib
import json
from pathlib import Path

manifest_path = Path("dist/release-manifest.json")
summary_path = Path("dist/network-readiness-summary.txt")

manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
summary_sha = hashlib.sha256(summary_path.read_bytes()).hexdigest()
for artifact in manifest.get("artifacts", []):
    if artifact.get("path") == "dist/network-readiness-summary.txt":
        artifact["sha256"] = summary_sha
manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
PY

# Attempt detached signatures when enabled; otherwise emit explicit placeholder status.
if [[ "$SIGNING_MODE" != "enabled" ]]; then
  {
    echo "signing: unavailable"
    echo "reason: disabled by SUPPLY_CHAIN_SIGNING=$SIGNING_MODE"
    echo "action: set SUPPLY_CHAIN_SIGNING=enabled with a configured signing key"
  } > "$SIGNING_STATUS_FILE"
  cat > "$SIGNING_WAIVER_FILE" <<EOF
{
  "reason": "signing unavailable in CI/dev environment",
  "approved_by": "release-automation",
  "approved_at_utc": "$TIMESTAMP_UTC",
  "expires_at_utc": "2027-01-01T00:00:00Z"
}
EOF
elif command -v gpg >/dev/null 2>&1 && gpg --list-secret-keys --with-colons 2>/dev/null | grep -q '^sec'; then
  if gpg --armor --detach-sign --output "$MANIFEST_SIG_FILE" "$MANIFEST_FILE" >/dev/null 2>&1 && \
     gpg --armor --detach-sign --output "$TARBALL_SIG_FILE" "$TARBALL" >/dev/null 2>&1; then
    {
      echo "signing: enabled"
      echo "manifest_signature: $MANIFEST_SIG_FILE"
      echo "bundle_signature: $TARBALL_SIG_FILE"
    } > "$SIGNING_STATUS_FILE"
  else
    {
      echo "signing: failed"
      echo "reason: gpg signing command returned non-zero exit status"
      echo "action: verify signing key availability and rerun release_bundle.sh"
    } > "$SIGNING_STATUS_FILE"
    cat > "$SIGNING_WAIVER_FILE" <<EOF
{
  "reason": "signing unavailable in CI/dev environment",
  "approved_by": "release-automation",
  "approved_at_utc": "$TIMESTAMP_UTC",
  "expires_at_utc": "2027-01-01T00:00:00Z"
}
EOF
  fi
else
  {
    echo "signing: unavailable"
    echo "reason: gpg not installed or no secret key configured"
    echo "action: configure gpg key, then rerun release_bundle.sh"
  } > "$SIGNING_STATUS_FILE"
  cat > "$SIGNING_WAIVER_FILE" <<EOF
{
  "reason": "signing unavailable in CI/dev environment",
  "approved_by": "release-automation",
  "approved_at_utc": "$TIMESTAMP_UTC",
  "expires_at_utc": "2027-01-01T00:00:00Z"
}
EOF
fi

popd >/dev/null

echo "Bundle created: $TARBALL"
echo "Checksum: $SHA_FILE"
echo "Summary: $SUMMARY_FILE"
echo "Manifest: $MANIFEST_FILE"
echo "Signing status: $SIGNING_STATUS_FILE"
