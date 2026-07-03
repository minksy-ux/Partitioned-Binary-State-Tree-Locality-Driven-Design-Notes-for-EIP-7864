"""Verification-aware stem gas accounting helpers.

This module models stem-aware gas charging with explicit local-verification
gating for cache-hit discounts.
"""

from __future__ import annotations

from dataclasses import dataclass

from .tree import split_key


@dataclass(frozen=True)
class StemGasPolicy:
    """Configurable gas constants for stem-aware accounting."""

    witness_branch_cost: int = 8
    witness_chunk_cost: int = 2
    write_new_leaf_cost: int = 5
    verified_cache_hit_read_cost: int = 1

    def __post_init__(self) -> None:
        if self.witness_branch_cost < 0:
            raise ValueError("witness_branch_cost must be non-negative")
        if self.witness_chunk_cost < 0:
            raise ValueError("witness_chunk_cost must be non-negative")
        if self.write_new_leaf_cost < 0:
            raise ValueError("write_new_leaf_cost must be non-negative")
        if self.verified_cache_hit_read_cost < 0:
            raise ValueError("verified_cache_hit_read_cost must be non-negative")


@dataclass(frozen=True)
class StemCharge:
    """Result of a single gas charge operation."""

    total_cost: int
    used_branch_opening: bool
    used_verified_cache_discount: bool


class VerificationAwareStemGasMeter:
    """Tracks per-block stem access costs and verification-gated discounts."""

    def __init__(self, policy: StemGasPolicy | None = None):
        self.policy = policy or StemGasPolicy()
        self._opened_stems: set[bytes] = set()
        self._verified_hot_stems: set[bytes] = set()

    def new_block(self) -> None:
        """Reset per-block access and verification state."""
        self._opened_stems.clear()
        self._verified_hot_stems.clear()

    def mark_stem_verified(self, stem_prefix: bytes) -> None:
        """Mark a stem as locally verified and eligible for cache-hit discounts."""
        self._verified_hot_stems.add(stem_prefix)

    def mark_key_verified(self, key: bytes) -> None:
        """Mark the key's stem as locally verified."""
        stem_prefix, _ = split_key(key)
        self.mark_stem_verified(stem_prefix)

    def charge_read(self, stem_prefix: bytes, locally_verified: bool = False) -> StemCharge:
        """Charge gas for a read access to a stem.

        Discount rule: verified cache-hit pricing applies only when both:
        1) the stem is marked locally verified for the current block context,
        2) this call indicates local verification succeeded (`locally_verified=True`).
        """
        used_branch = False
        used_discount = False

        if stem_prefix not in self._opened_stems:
            can_use_verified_discount = (
                locally_verified and stem_prefix in self._verified_hot_stems
            )
            if can_use_verified_discount:
                cost = self.policy.verified_cache_hit_read_cost
                used_discount = True
            else:
                cost = self.policy.witness_branch_cost + self.policy.witness_chunk_cost
                used_branch = True
            self._opened_stems.add(stem_prefix)
            return StemCharge(cost, used_branch, used_discount)

        return StemCharge(
            total_cost=self.policy.witness_chunk_cost,
            used_branch_opening=False,
            used_verified_cache_discount=False,
        )

    def charge_write(
        self,
        stem_prefix: bytes,
        is_new_leaf: bool,
        locally_verified: bool = False,
    ) -> StemCharge:
        """Charge gas for a write access to a stem."""
        base = self.charge_read(stem_prefix=stem_prefix, locally_verified=locally_verified)
        extra = self.policy.write_new_leaf_cost if is_new_leaf else 0
        return StemCharge(
            total_cost=base.total_cost + extra,
            used_branch_opening=base.used_branch_opening,
            used_verified_cache_discount=base.used_verified_cache_discount,
        )
