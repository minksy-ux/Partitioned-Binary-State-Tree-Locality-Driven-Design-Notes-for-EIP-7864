#!/usr/bin/env python3
"""Validate release notes policy for production-eligible promotions."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

MANIFEST_PATH = Path("network-readiness.manifest.json")
RELEASE_NOTES_PATH = Path("RELEASE_NOTES.md")

REQUIRED_SECTIONS = [
    "Release Scope",
    "Security Review",
    "Audit Evidence",
    "Client Compatibility",
    "Activation Scope",
    "Rollback Plan",
]

PLACEHOLDER_PATTERNS = [
    r"\bTBD\b",
    r"\bTODO\b",
    r"\bPLACEHOLDER\b",
    r"^\s*-\s*$",
]


def fail(message: str) -> int:
    print(f"release-notes: FAIL: {message}")
    return 1


def parse_sections(markdown: str) -> dict[str, str]:
    # Parse level-2 markdown sections: ## Heading
    matches = list(re.finditer(r"^##\s+(.+?)\s*$", markdown, flags=re.MULTILINE))
    sections: dict[str, str] = {}
    for idx, match in enumerate(matches):
        title = match.group(1).strip()
        start = match.end()
        end = matches[idx + 1].start() if idx + 1 < len(matches) else len(markdown)
        body = markdown[start:end].strip()
        sections[title] = body
    return sections


def contains_placeholder(text: str) -> bool:
    upper = text.upper()
    for pattern in PLACEHOLDER_PATTERNS:
        if re.search(pattern, upper, flags=re.MULTILINE):
            return True
    return False


def main() -> int:
    if not MANIFEST_PATH.exists():
        return fail("missing network-readiness.manifest.json")

    try:
        manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    except Exception as exc:  # pragma: no cover
        return fail(f"invalid manifest JSON: {exc}")

    production_eligible = (
        manifest.get("release_decision", {}).get("production_eligible", False)
    )
    if not isinstance(production_eligible, bool):
        return fail("release_decision.production_eligible must be boolean")

    if not RELEASE_NOTES_PATH.exists():
        if production_eligible:
            return fail("production_eligible=true requires RELEASE_NOTES.md")
        print("release-notes: PASS (production_eligible=false; release notes optional)")
        return 0

    markdown = RELEASE_NOTES_PATH.read_text(encoding="utf-8")
    sections = parse_sections(markdown)

    missing = [name for name in REQUIRED_SECTIONS if name not in sections]
    if missing:
        return fail("missing required sections: " + ", ".join(missing))

    if production_eligible:
        for section in REQUIRED_SECTIONS:
            body = sections.get(section, "").strip()
            if len(body) < 40:
                return fail(f"section '{section}' is too short for production release")
            if contains_placeholder(body):
                return fail(f"section '{section}' contains placeholder content")

    print("release-notes: PASS")
    print(f"release-notes: production_eligible={production_eligible}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
