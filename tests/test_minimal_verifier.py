"""Tests for minimal verifier budget target helpers."""

import json
import sys
import os
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from pbt.minimal_verifier import (
    VerifierBudgetMeasurement,
    default_budget_targets,
    get_budget_target,
    evaluate_budget,
)


def test_default_targets_include_phone_profiles():
    targets = default_budget_targets()
    names = [item.device_class for item in targets]
    assert "Mid-range Phone (2026)" in names
    assert "High-end Phone" in names


def test_mid_range_budget_passes_when_under_limits():
    target = get_budget_target("Mid-range Phone (2026)")
    measurement = VerifierBudgetMeasurement(
        device_class=target.device_class,
        ram_mb=480,
        sync_seconds=24.0,
        verify_ms_per_block=1500.0,
    )
    result = evaluate_budget(measurement, target)
    assert result.within_budget
    assert result.failures == ()


def test_budget_reports_specific_failures():
    target = get_budget_target("High-end Phone")
    measurement = VerifierBudgetMeasurement(
        device_class=target.device_class,
        ram_mb=1300,
        sync_seconds=12.0,
        verify_ms_per_block=700.0,
    )
    result = evaluate_budget(measurement, target)
    assert not result.within_budget
    assert "ram" in result.failures
    assert "sync" in result.failures
    assert "verify" in result.failures


def test_budget_rejects_negative_measurements():
    try:
        VerifierBudgetMeasurement(
            device_class="Mid-range Phone (2026)",
            ram_mb=-1,
            sync_seconds=1.0,
            verify_ms_per_block=1.0,
        )
        assert False, "expected ValueError"
    except ValueError:
        pass


def test_budget_reports_device_class_mismatch():
    target = get_budget_target("High-end Phone")
    measurement = VerifierBudgetMeasurement(
        device_class="Mid-range Phone (2026)",
        ram_mb=500,
        sync_seconds=8.0,
        verify_ms_per_block=400.0,
    )
    result = evaluate_budget(measurement, target)
    assert not result.within_budget
    assert "device_class" in result.failures


def test_fixture_driven_minimal_verifier_compliance_suite():
    fixture_path = (
        Path(__file__).resolve().parent / "fixtures" / "minimal_verifier_compliance.json"
    )
    fixture = json.loads(fixture_path.read_text(encoding="utf-8"))
    assert fixture["schema_version"] == "1.0.0"

    for case in fixture["cases"]:
        target = get_budget_target(case["target_device_class"])
        measurement = VerifierBudgetMeasurement(**case["measurement"])
        actual = evaluate_budget(measurement, target)
        expected = case["expected"]
        assert actual.within_budget == expected["within_budget"], case["id"]
        assert sorted(actual.failures) == sorted(expected["failures"]), case["id"]
