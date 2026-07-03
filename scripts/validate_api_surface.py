#!/usr/bin/env python3
"""Validate the locked public API surface exported by pbt.__init__."""

from __future__ import annotations

import importlib
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


LOCK_PATH = Path("api-surface.lock.json")


def main() -> int:
    if not LOCK_PATH.exists():
        print(f"api-surface: FAIL: missing lock file {LOCK_PATH}")
        return 1

    lock = json.loads(LOCK_PATH.read_text(encoding="utf-8"))
    expected = lock.get("exports")
    if not isinstance(expected, list):
        print("api-surface: FAIL: lock file must contain exports list")
        return 1

    module = importlib.import_module(lock.get("module", "pbt"))
    actual = sorted(name for name in getattr(module, "__all__", []) if isinstance(name, str))
    expected_sorted = sorted(expected)

    missing = sorted(set(expected_sorted) - set(actual))
    added = sorted(set(actual) - set(expected_sorted))

    if missing or added:
        print("api-surface: FAIL: public API drift detected")
        if missing:
            print("api-surface: missing exports:")
            for item in missing:
                print(f"  - {item}")
        if added:
            print("api-surface: added exports:")
            for item in added:
                print(f"  - {item}")
        return 1

    print("api-surface: PASS")
    print(f"api-surface: exports={len(actual)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
