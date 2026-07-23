"""Regression test for Rust manifest benchmark targets."""

from __future__ import annotations

import tomllib
from pathlib import Path


def test_bench_targets_resolve() -> None:
    manifest_path = Path(__file__).resolve().parents[1] / "pbt-rs" / "Cargo.toml"
    manifest = tomllib.loads(manifest_path.read_text(encoding="utf-8"))

    for bench in manifest.get("bench", []):
        name = bench["name"]
        candidates = (
            [manifest_path.parent / bench["path"]]
            if "path" in bench
            else [
                manifest_path.parent / "benches" / f"{name}.rs",
                manifest_path.parent / "benches" / name / "main.rs",
            ]
        )

        assert any(path.exists() for path in candidates), (
            f"bench target {name!r} must point to an existing source file"
        )
