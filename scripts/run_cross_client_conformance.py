#!/usr/bin/env python3
"""Cross-client conformance runner for Python and Rust PBT implementations."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from pbt.nodes import EmptyNode  # noqa: E402
from pbt.tree import delete, get, get_proof, insert, root_hash, verify_proof  # noqa: E402


def _decode_hex(data: str) -> bytes:
    try:
        return bytes.fromhex(data)
    except ValueError as exc:
        raise ValueError(f"invalid hex {data!r}: {exc}") from exc


def _normalize_suite(suite: dict[str, Any]) -> dict[str, Any]:
    if suite.get("schema_version") != "1.0.0":
        raise ValueError(f"unsupported schema_version: {suite.get('schema_version')}")
    if not isinstance(suite.get("cases"), list):
        raise ValueError("cases must be a list")
    return suite


def _run_python_case(case: dict[str, Any]) -> dict[str, Any]:
    root = EmptyNode()

    for operation in case["operations"]:
        op = operation["op"]
        key = _decode_hex(operation["key"])
        if len(key) < 2:
            raise ValueError(f"key must be >=2 bytes: {operation['key']}")

        if op == "insert":
            value = _decode_hex(operation["value"])
            if len(value) != 32:
                raise ValueError("insert value must be 32 bytes")
            root = insert(root, key, value)
        elif op == "delete":
            root = delete(root, key)
        else:
            raise ValueError(f"unsupported operation: {op}")

    reads: dict[str, str] = {}
    for key_hex in case["reads"]:
        key = _decode_hex(key_hex)
        reads[key_hex] = get(root, key).hex()

    proof_results: dict[str, dict[str, Any]] = {}
    rh = root_hash(root)
    for key_hex in case["proof_queries"]:
        key = _decode_hex(key_hex)
        proof = get_proof(root, key)
        proof_results[key_hex] = {
            "value": proof.value.hex(),
            "valid": verify_proof(rh, proof),
        }

    return {
        "id": case["id"],
        "root": rh.hex(),
        "reads": dict(sorted(reads.items())),
        "proofs": dict(sorted(proof_results.items())),
    }


def _run_python_suite(suite: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": suite["schema_version"],
        "cases": [_run_python_case(case) for case in suite["cases"]],
    }


def _run_rust_suite(suite_path: Path) -> dict[str, Any]:
    cmd = [
        "cargo",
        "run",
        "--quiet",
        "--manifest-path",
        "pbt-rs/Cargo.toml",
        "--bin",
        "conformance_case",
        "--",
        str(suite_path),
    ]
    result = subprocess.run(cmd, check=False, capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(
            "rust conformance execution failed\n"
            f"stdout:\n{result.stdout}\n"
            f"stderr:\n{result.stderr}"
        )
    return _normalize_suite(json.loads(result.stdout))


def _write_report(report_path: Path, content: dict[str, Any]) -> None:
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(content, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--suite",
        default="pbt-rs/tests/vectors/cross_client_cases.json",
        help="Path to conformance suite JSON",
    )
    parser.add_argument(
        "--report",
        default="dist/cross-client-conformance-report.json",
        help="Path to write the conformance report JSON",
    )
    args = parser.parse_args()

    suite_path = Path(args.suite)
    if not suite_path.exists():
        print(f"cross-client-conformance: FAIL: missing suite file: {suite_path}")
        return 1

    suite = _normalize_suite(json.loads(suite_path.read_text(encoding="utf-8")))
    python_result = _run_python_suite(suite)
    rust_result = _run_rust_suite(suite_path)

    report = {
        "schema_version": suite["schema_version"],
        "suite": str(suite_path),
        "python": python_result,
        "rust": rust_result,
        "match": python_result == rust_result,
    }
    _write_report(Path(args.report), report)

    if report["match"]:
        print("cross-client-conformance: PASS")
        print(f"cross-client-conformance: report={args.report}")
        return 0

    print("cross-client-conformance: FAIL: Python and Rust results differ")
    print(f"cross-client-conformance: report={args.report}")
    return 1


if __name__ == "__main__":
    sys.exit(main())