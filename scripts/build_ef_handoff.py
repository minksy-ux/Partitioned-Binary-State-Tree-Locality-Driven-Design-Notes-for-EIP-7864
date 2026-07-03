#!/usr/bin/env python3
"""Build an Ethereum Foundation handoff package from validated artifacts."""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tarfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, cast

ROOT = Path(__file__).resolve().parents[1]
DIST = ROOT / "dist"
HANDOFF_DIR = DIST / "ef-handoff"
HANDOFF_TARBALL = DIST / "ef-handoff-package.tar.gz"

REQUIRED_RELEASE_ARTIFACTS = [
    DIST / "pbt-rs-source.tar.gz",
    DIST / "pbt-rs-sha256.txt",
    DIST / "network-readiness-summary.txt",
    DIST / "release-manifest.json",
    DIST / "signing-status.txt",
]


def run(cmd: list[str]) -> None:
    subprocess.run(cmd, check=True, cwd=ROOT)


def _has_release_bundle_artifacts() -> bool:
    return all(path.exists() for path in REQUIRED_RELEASE_ARTIFACTS)


def ensure_release_bundle() -> None:
    python = sys.executable
    run([python, "scripts/validate_network_readiness.py"])
    run([python, "scripts/validate_release_notes.py"])

    if _has_release_bundle_artifacts():
        try:
            run([python, "scripts/verify_release_artifacts.py"])
            return
        except subprocess.CalledProcessError:
            # Existing artifacts can be stale (for example, a tarball updated
            # without refreshed provenance). Fall back to regeneration.
            pass

    run(["bash", "pbt-rs/scripts/release_bundle.sh"])
    run([python, "scripts/generate_supply_chain_artifacts.py"])
    run([python, "scripts/verify_release_artifacts.py"])


def read_json(path: Path) -> dict[str, Any]:
    return cast(dict[str, Any], json.loads(path.read_text(encoding="utf-8")))


def git(cmd: list[str]) -> str:
    try:
        out = subprocess.check_output(["git", *cmd], cwd=ROOT)
    except Exception:
        return "unknown"
    return out.decode("utf-8").strip()


def build_manifest() -> dict:
    readiness = read_json(ROOT / "network-readiness.manifest.json")
    release_manifest = read_json(DIST / "release-manifest.json")

    gates = readiness.get("gates", {})
    blocking = [
        name
        for name, gate in gates.items()
        if gate.get("status") not in {"complete", "waived"}
    ]

    return {
        "schema_version": "1.0.0",
        "package_type": "ethereum-foundation-handoff",
        "generated_at_utc": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "repository": {
            "name": git(["remote", "get-url", "origin"]),
            "branch": git(["rev-parse", "--abbrev-ref", "HEAD"]),
            "commit": git(["rev-parse", "HEAD"]),
        },
        "readiness": {
            "production_eligible": readiness.get("release_decision", {}).get(
                "production_eligible", False
            ),
            "blocking_gates": blocking,
            "release_notes_path": "RELEASE_NOTES.md",
            "handoff_doc_path": "EF_NETWORK_HANDOFF.md",
        },
        "artifacts": release_manifest.get("artifacts", []),
        "release_manifest_path": "dist/release-manifest.json",
        "signing_status_path": "dist/signing-status.txt",
    }


def write_quickstart() -> None:
    quickstart = HANDOFF_DIR / "EF_CLIENT_QUICKSTART.md"
    quickstart.write_text(
        """# EF Client Quickstart

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
""",
        encoding="utf-8",
    )


def build_handoff_package() -> None:
    if HANDOFF_DIR.exists():
        shutil.rmtree(HANDOFF_DIR)
    HANDOFF_DIR.mkdir(parents=True)

    required_files = [
        ROOT / "network-readiness.manifest.json",
        ROOT / "RELEASE_NOTES.md",
        ROOT / "EF_NETWORK_HANDOFF.md",
        *REQUIRED_RELEASE_ARTIFACTS,
    ]
    for path in required_files:
        if not path.exists():
            raise FileNotFoundError(f"required file missing: {path}")

    manifest = build_manifest()
    (HANDOFF_DIR / "EF_HANDOFF_MANIFEST.json").write_text(
        json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
    )

    for src in required_files:
        target = HANDOFF_DIR / src.name
        shutil.copy2(src, target)

    write_quickstart()

    if HANDOFF_TARBALL.exists():
        HANDOFF_TARBALL.unlink()
    with tarfile.open(HANDOFF_TARBALL, "w:gz") as tar:
        tar.add(HANDOFF_DIR, arcname="ef-handoff")

    print(f"EF handoff directory: {HANDOFF_DIR}")
    print(f"EF handoff tarball: {HANDOFF_TARBALL}")


def main() -> None:
    ensure_release_bundle()
    build_handoff_package()


if __name__ == "__main__":
    main()
