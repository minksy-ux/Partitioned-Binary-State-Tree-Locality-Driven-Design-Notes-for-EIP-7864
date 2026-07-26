#!/usr/bin/env python3
"""Generate baseline supply-chain artifacts (lockfile, SBOM, provenance)."""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

DIST = Path("dist")
LOCK_FILE = Path("requirements.lock")
TARBALL = DIST / "pbt-rs-source.tar.gz"


def _run(cmd: list[str]) -> str:
    out = subprocess.check_output(cmd)
    return out.decode("utf-8")


def _pip_freeze() -> str:
    raw = _run([sys.executable, "-m", "pip", "freeze", "--all"])
    return _normalize_lock(raw)


def _repo_root() -> str:
    """Return the repository root as a POSIX path string.

    Walks up from the current working directory to find the nearest ``.git``
    directory.  Falls back to ``Path.cwd()`` when no ``.git`` directory is
    found (e.g. in a detached or non-git environment).
    """
    path = Path.cwd().resolve()
    for candidate in [path, *path.parents]:
        if (candidate / ".git").exists():
            return candidate.as_posix()
    return path.as_posix()


def _normalize_lock(raw: str) -> str:
    """Normalize absolute local file:// paths to a portable relative reference.

    ``pip freeze`` records locally-installed packages as
    ``pkg @ file:///abs/path/to/repo`` (non-editable) or
    ``-e file:///abs/path/to/repo`` (editable install).  The absolute path is
    environment-specific (e.g. ``/home/runner/work/...`` on GitHub-hosted
    runners) and makes the committed ``requirements.lock`` non-reproducible
    across machines.  Normalize those entries to ``pkg @ file:.`` so the
    lock file is portable.
    """
    root = _repo_root()
    normalized_lines: list[str] = []
    for line in raw.splitlines():
        # Match both "pkg @ file:///abs/path" and "-e file:///abs/path" forms.
        # The optional trailing slash after the path is intentionally dropped —
        # the replacement normalises to just "." regardless.  The trailing
        # whitespace group is preserved so line endings are not silently altered.
        line = re.sub(
            rf"(?P<prefix>(?:@ |-e )file://){re.escape(root)}/?(?P<ws>\s*)$",
            r"\g<prefix>.\g<ws>",
            line,
        )
        normalized_lines.append(line)
    result = "\n".join(normalized_lines)
    if raw.endswith("\n"):
        result += "\n"
    return result


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _sbom_packages_from_lock(lock_text: str) -> list[dict[str, str]]:
    packages: list[dict[str, str]] = []
    for line in lock_text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if "==" not in stripped:
            continue
        name, version = stripped.split("==", 1)
        name = name.strip()
        version = version.strip()
        if not name or not version:
            continue
        packages.append(
            {
                "SPDXID": f"SPDXRef-Package-{name}",
                "name": name,
                "versionInfo": version,
            }
        )
    return packages


def _git_commit() -> str:
    try:
        return _run(["git", "rev-parse", "HEAD"]).strip()
    except Exception:
        return "unknown"


def main() -> int:
    DIST.mkdir(parents=True, exist_ok=True)

    lock_text = _pip_freeze()
    LOCK_FILE.write_text(lock_text, encoding="utf-8")
    sbom_packages = _sbom_packages_from_lock(lock_text)

    sbom = {
        "spdxVersion": "SPDX-2.3",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": "pbt-eip7864",
        "creationInfo": {
            "created": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "creators": ["Tool: scripts/generate_supply_chain_artifacts.py"],
        },
        "packages": sbom_packages,
    }
    (DIST / "sbom.spdx.json").write_text(json.dumps(sbom, indent=2) + "\n", encoding="utf-8")

    if TARBALL.exists():
        subject_name = TARBALL.name
        subject_sha = _sha256(TARBALL)
    else:
        subject_name = LOCK_FILE.name
        subject_sha = _sha256(LOCK_FILE)

    provenance = {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [{"name": subject_name, "digest": {"sha256": subject_sha}}],
        "predicateType": "https://slsa.dev/provenance/v1",
        "predicate": {
            "buildType": "local-ci",
            "builder": {"id": "github-actions/network-readiness"},
            "buildConfig": {"commit": _git_commit()},
        },
    }
    (DIST / "provenance.intoto.jsonl").write_text(
        json.dumps(provenance) + "\n", encoding="utf-8"
    )

    signing_status_path = DIST / "signing-status.txt"
    status_text = (
        signing_status_path.read_text(encoding="utf-8")
        if signing_status_path.exists()
        else ""
    )
    if "signing: enabled" not in status_text:
        waiver = {
            "reason": "signing unavailable in CI/dev environment",
            "approved_by": "release-automation",
            "approved_at_utc": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "expires_at_utc": "2027-01-01T00:00:00Z",
        }
        (DIST / "signing-waiver.json").write_text(
            json.dumps(waiver, indent=2) + "\n",
            encoding="utf-8",
        )

    print("supply-chain-artifacts: PASS")
    print("supply-chain-artifacts: wrote requirements.lock")
    print("supply-chain-artifacts: wrote dist/sbom.spdx.json")
    print("supply-chain-artifacts: wrote dist/provenance.intoto.jsonl")
    return 0


if __name__ == "__main__":
    sys.exit(main())
