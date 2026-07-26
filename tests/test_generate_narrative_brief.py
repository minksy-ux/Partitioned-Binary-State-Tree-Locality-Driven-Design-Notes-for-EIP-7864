"""Tests for narrative brief generator script."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path


def _script_path() -> Path:
    return Path(__file__).resolve().parents[1] / "scripts" / "generate_narrative_brief.py"


def test_generate_narrative_brief_prints_all_sections() -> None:
    proc = subprocess.run(
        [sys.executable, str(_script_path())],
        check=False,
        capture_output=True,
        text=True,
    )

    assert proc.returncode == 0
    assert "1. Executive Summary (3-4 lines)" in proc.stdout
    assert "2. Technical Version (Protocol-Engineer Oriented)" in proc.stdout
    assert "3. Governance Version (Neutral Tone)" in proc.stdout
    assert "4. Combined Paragraph" in proc.stdout
    assert "5. HVBST / Stemtree 2.0 Addendum" in proc.stdout
    assert "Hybrid Vector-Binary Stem Tree (HVBST)" in proc.stdout
    assert "Adaptive Vector-Binary State Tree (\"Stemtree 2.0\")" in proc.stdout
    assert "| Aspect | Pure Verkle | Pure Binary + STARK | Hybrid Vector-Binary (Proposed) |" in proc.stdout


def test_generate_narrative_brief_supports_custom_labels(tmp_path: Path) -> None:
    output_path = tmp_path / "brief.md"
    addendum_path = tmp_path / "addendum.md"
    proc = subprocess.run(
        [
            sys.executable,
            str(_script_path()),
            "--prototype-label",
            "HashLab",
            "--primary-approach",
            "partitioned-binary-tree",
            "--alternative-approach",
            "vector commitments",
            "--stem-hook-label",
            "storage-tier hooks",
            "--hybrid-name",
            "HybridX",
            "--hybrid-alias",
            "Stemtree Next",
            "--hybrid-addendum-output",
            str(addendum_path),
            "--output",
            str(output_path),
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert proc.returncode == 0
    assert output_path.exists()
    assert addendum_path.exists()

    content = output_path.read_text(encoding="utf-8")
    assert "HashLab" in content
    assert "partitioned-binary-tree" in content
    assert "vector commitments" in content
    assert "storage-tier hooks" in content
    assert "HybridX" in content
    assert "Stemtree Next" in content

    addendum_content = addendum_path.read_text(encoding="utf-8")
    assert "5. HVBST / Stemtree 2.0 Addendum" in addendum_content
    assert "HybridX" in addendum_content
    assert "Stemtree Next" in addendum_content
    assert "1. Executive Summary (3-4 lines)" not in addendum_content


def test_generate_narrative_brief_supports_hybrid_only_stdout() -> None:
    proc = subprocess.run(
        [
            sys.executable,
            str(_script_path()),
            "--only-hybrid-addendum",
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert proc.returncode == 0
    assert "5. HVBST / Stemtree 2.0 Addendum" in proc.stdout
    assert "1. Executive Summary (3-4 lines)" not in proc.stdout
