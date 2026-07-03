#!/usr/bin/env python3
"""Validate release policy for API export removals."""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

LOCK_PATH = Path("api-surface.lock.json")
PYPROJECT_PATH = Path("pyproject.toml")
RELEASE_NOTES_PATH = Path("RELEASE_NOTES.md")


def fail(message: str) -> int:
    print(f"api-release-policy: FAIL: {message}")
    return 1


def _git_show(rev_path: str) -> str | None:
    try:
        out = subprocess.check_output(["git", "show", rev_path])
        return out.decode("utf-8")
    except Exception:
        return None


def _major_version(pyproject_text: str) -> int:
    match = re.search(
        r'^version\s*=\s*"(\d+)\.(\d+)\.(\d+)"\s*$',
        pyproject_text,
        flags=re.MULTILINE,
    )
    if not match:
        raise ValueError("could not parse project version from pyproject.toml")
    return int(match.group(1))


def main() -> int:
    if not LOCK_PATH.exists():
        return fail("missing api-surface.lock.json")
    if not PYPROJECT_PATH.exists():
        return fail("missing pyproject.toml")
    if not RELEASE_NOTES_PATH.exists():
        return fail("missing RELEASE_NOTES.md")

    current_lock = json.loads(LOCK_PATH.read_text(encoding="utf-8"))
    current_exports = set(current_lock.get("exports", []))
    if not current_exports:
        return fail("current api-surface lock exports list is empty")

    previous_lock_text = _git_show("HEAD~1:api-surface.lock.json")
    previous_pyproject_text = _git_show("HEAD~1:pyproject.toml")
    if previous_lock_text is None or previous_pyproject_text is None:
        print("api-release-policy: PASS (no previous baseline available)")
        return 0

    previous_lock = json.loads(previous_lock_text)
    previous_exports = set(previous_lock.get("exports", []))
    removed_exports = sorted(previous_exports - current_exports)

    if not removed_exports:
        print("api-release-policy: PASS")
        return 0

    current_major = _major_version(PYPROJECT_PATH.read_text(encoding="utf-8"))
    previous_major = _major_version(previous_pyproject_text)
    if current_major <= previous_major:
        return fail(
            "API export removals detected but major version was not incremented"
        )

    release_notes = RELEASE_NOTES_PATH.read_text(encoding="utf-8").lower()
    if "api-breaking" not in release_notes:
        return fail(
            "API export removals detected but RELEASE_NOTES.md is missing 'api-breaking' label"
        )

    print("api-release-policy: PASS")
    print("api-release-policy: removed_exports=" + ", ".join(removed_exports))
    return 0


if __name__ == "__main__":
    sys.exit(main())
