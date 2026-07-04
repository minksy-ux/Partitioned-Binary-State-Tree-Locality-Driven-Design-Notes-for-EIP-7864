#!/usr/bin/env python3
"""Validate required supply chain artifacts and strict signing policy."""

from __future__ import annotations

import hashlib
import json
import os
import re
import sys
from pathlib import Path

DIST = Path("dist")
REQUIRED = [
    Path("requirements.lock"),
    DIST / "sbom.spdx.json",
    DIST / "provenance.intoto.jsonl",
    DIST / "signing-status.txt",
]
SIGNING_WAIVER = DIST / "signing-waiver.json"
TARBALL = DIST / "pbt-rs-source.tar.gz"


def _is_release_mode() -> bool:
    env = os.environ.get("PBT_RELEASE_MODE", "").strip().lower()
    if env in {"1", "true", "yes", "on"}:
        return True
    if env in {"0", "false", "no", "off"}:
        return False
    return False


def _is_signing_explicitly_disabled() -> bool:
    env = os.environ.get("SUPPLY_CHAIN_SIGNING", "").strip().lower()
    return env in {"0", "false", "no", "off", "disabled"}


def _is_signing_enabled_requested() -> bool:
    env = os.environ.get("PBT_SIGNING_ENABLED", "").strip().lower()
    if env in {"1", "true", "yes", "on"}:
        return True
    if env in {"0", "false", "no", "off"}:
        return False
    return not _is_signing_explicitly_disabled()


def fail(message: str) -> int:
    print(f"supply-chain: FAIL: {message}")
    return 1


def main() -> int:
    for path in REQUIRED:
        if not path.exists():
            return fail(f"missing required artifact: {path}")

    try:
        sbom = json.loads((DIST / "sbom.spdx.json").read_text(encoding="utf-8"))
    except Exception as exc:
        return fail(f"invalid SBOM JSON: {exc}")
    if not isinstance(sbom, dict) or "SPDXID" not in sbom:
        return fail("SBOM must contain SPDXID")
    packages = sbom.get("packages")
    if not isinstance(packages, list) or not packages:
        return fail("SBOM must contain non-empty packages list")

    for package in packages:
        if not isinstance(package, dict):
            return fail("SBOM packages entries must be objects")
        if not package.get("name"):
            return fail("SBOM package entry missing name")
        if not package.get("versionInfo"):
            return fail("SBOM package entry missing versionInfo")

    provenance_lines = (DIST / "provenance.intoto.jsonl").read_text(encoding="utf-8").splitlines()
    if not provenance_lines:
        return fail("provenance.intoto.jsonl must not be empty")
    try:
        statement = json.loads(provenance_lines[0])
    except Exception as exc:
        return fail(f"invalid provenance statement JSON: {exc}")
    subjects = statement.get("subject") if isinstance(statement, dict) else None
    if not isinstance(subjects, list) or not subjects:
        return fail("provenance subject list must be non-empty")
    digest = subjects[0].get("digest", {}).get("sha256") if isinstance(subjects[0], dict) else None
    if not isinstance(digest, str) or not re.fullmatch(r"[a-f0-9]{64}", digest):
        return fail("provenance subject digest.sha256 must be a 64-char lowercase hex string")

    signing_status = (DIST / "signing-status.txt").read_text(encoding="utf-8")
    if "signing: enabled" not in signing_status:
        if SIGNING_WAIVER.exists():
            try:
                waiver = json.loads(SIGNING_WAIVER.read_text(encoding="utf-8"))
            except Exception as exc:
                return fail(f"invalid signing waiver json: {exc}")
            required_fields = ["reason", "approved_by", "approved_at_utc", "expires_at_utc"]
            missing = [field for field in required_fields if not waiver.get(field)]
            if missing:
                return fail("signing waiver missing fields: " + ", ".join(missing))
        elif "signing: unavailable" not in signing_status and "signing: failed" not in signing_status:
            return fail(
                "strict signing policy requires signing: enabled or dist/signing-waiver.json"
            )

    release_mode = _is_release_mode()
    if release_mode and TARBALL.exists():
        actual_sha = hashlib.sha256(TARBALL.read_bytes()).hexdigest()
        if actual_sha != digest:
            return fail("provenance digest does not match release tarball in release mode")

    print("supply-chain: PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
