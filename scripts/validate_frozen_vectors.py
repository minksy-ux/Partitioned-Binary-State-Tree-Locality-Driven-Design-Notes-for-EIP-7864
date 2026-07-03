#!/usr/bin/env python3
"""Validate that vector fixtures match the committed checksum lock file."""

from __future__ import annotations

import hashlib
import sys
from pathlib import Path

VECTORS_DIR = Path("pbt-rs/tests/vectors")
LOCK_FILE = VECTORS_DIR / "SHA256SUMS"


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _load_expected(lock_file: Path) -> dict[str, str]:
    expected: dict[str, str] = {}
    for line in lock_file.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        parts = stripped.split(maxsplit=1)
        if len(parts) != 2:
            raise ValueError(f"invalid checksum line: {line}")
        digest, rel_path = parts
        expected[rel_path] = digest.lower()
    return expected


def _load_actual(vectors_dir: Path) -> dict[str, str]:
    actual: dict[str, str] = {}
    for file_path in sorted(vectors_dir.glob("*.json")):
        rel = file_path.as_posix()
        actual[rel] = _sha256(file_path)
    return actual


def main() -> int:
    if not VECTORS_DIR.exists():
        print(f"frozen-vectors: FAIL: missing directory {VECTORS_DIR}")
        return 1
    if not LOCK_FILE.exists():
        print(f"frozen-vectors: FAIL: missing lock file {LOCK_FILE}")
        return 1

    try:
        expected = _load_expected(LOCK_FILE)
    except Exception as exc:
        print(f"frozen-vectors: FAIL: invalid lock file: {exc}")
        return 1

    actual = _load_actual(VECTORS_DIR)

    expected_keys = set(expected)
    actual_keys = set(actual)
    missing = sorted(expected_keys - actual_keys)
    added = sorted(actual_keys - expected_keys)

    if missing:
        print("frozen-vectors: FAIL: files listed in lock file are missing:")
        for item in missing:
            print(f"  - {item}")
        return 1

    if added:
        print("frozen-vectors: FAIL: new vector files are not in lock file:")
        for item in added:
            print(f"  - {item}")
        return 1

    mismatches = []
    for rel in sorted(actual):
        if expected[rel] != actual[rel]:
            mismatches.append((rel, expected[rel], actual[rel]))

    if mismatches:
        print("frozen-vectors: FAIL: checksum mismatches detected:")
        for rel, old_hash, new_hash in mismatches:
            print(f"  - {rel}")
            print(f"    expected: {old_hash}")
            print(f"    actual:   {new_hash}")
        return 1

    print("frozen-vectors: PASS")
    print(f"frozen-vectors: files={len(actual)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
