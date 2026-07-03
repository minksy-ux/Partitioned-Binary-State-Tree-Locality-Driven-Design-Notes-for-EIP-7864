"""Minimal verifier budget targets and evaluation helpers."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class VerificationBudgetTarget:
    device_class: str
    max_ram_mb: int
    max_sync_seconds: float
    max_verify_ms_per_block: float
    target_mode: str

    def __post_init__(self) -> None:
        if not self.device_class:
            raise ValueError("device_class must be non-empty")
        if self.max_ram_mb <= 0:
            raise ValueError("max_ram_mb must be positive")
        if self.max_sync_seconds <= 0:
            raise ValueError("max_sync_seconds must be positive")
        if self.max_verify_ms_per_block <= 0:
            raise ValueError("max_verify_ms_per_block must be positive")
        if not self.target_mode:
            raise ValueError("target_mode must be non-empty")


@dataclass(frozen=True)
class VerifierBudgetMeasurement:
    device_class: str
    ram_mb: int
    sync_seconds: float
    verify_ms_per_block: float

    def __post_init__(self) -> None:
        if not self.device_class:
            raise ValueError("device_class must be non-empty")
        if self.ram_mb < 0:
            raise ValueError("ram_mb must be non-negative")
        if self.sync_seconds < 0:
            raise ValueError("sync_seconds must be non-negative")
        if self.verify_ms_per_block < 0:
            raise ValueError("verify_ms_per_block must be non-negative")


@dataclass(frozen=True)
class BudgetEvaluation:
    within_budget: bool
    failures: tuple[str, ...]


def default_budget_targets() -> list[VerificationBudgetTarget]:
    """Return default phone-grade budget targets."""
    return [
        VerificationBudgetTarget(
            device_class="Mid-range Phone (2026)",
            max_ram_mb=512,
            max_sync_seconds=30.0,
            max_verify_ms_per_block=2000.0,
            target_mode="Full verification",
        ),
        VerificationBudgetTarget(
            device_class="High-end Phone",
            max_ram_mb=1024,
            max_sync_seconds=10.0,
            max_verify_ms_per_block=500.0,
            target_mode="Default wallet mode",
        ),
    ]


def get_budget_target(device_class: str) -> VerificationBudgetTarget:
    for target in default_budget_targets():
        if target.device_class == device_class:
            return target
    raise ValueError(f"unknown device_class: {device_class}")


def evaluate_budget(
    measurement: VerifierBudgetMeasurement,
    target: VerificationBudgetTarget,
) -> BudgetEvaluation:
    failures: list[str] = []
    if measurement.device_class != target.device_class:
        failures.append("device_class")
    if measurement.ram_mb > target.max_ram_mb:
        failures.append("ram")
    if measurement.sync_seconds > target.max_sync_seconds:
        failures.append("sync")
    if measurement.verify_ms_per_block > target.max_verify_ms_per_block:
        failures.append("verify")
    return BudgetEvaluation(within_budget=not failures, failures=tuple(failures))
