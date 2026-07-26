#!/usr/bin/env python3
"""Generate multi-audience narrative brief text for state-tree proposals."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class BriefConfig:
    prototype_label: str = "GeminiHash"
    primary_approach: str = "binary-hash-tree"
    alternative_approach: str = "Verkle trees"
    stem_hook_label: str = "stem-aware hooks"
    hybrid_name: str = "Hybrid Vector-Binary Stem Tree (HVBST)"
    hybrid_alias: str = 'Adaptive Vector-Binary State Tree ("Stemtree 2.0")'


def build_hybrid_addendum(config: BriefConfig) -> str:
    return (
        "5. HVBST / Stemtree 2.0 Addendum\n\n"
        f"{config.hybrid_name} with pluggable commitments, also described as "
        f"{config.hybrid_alias}, extends the same pragmatic posture: preserve a "
        "deterministic binary base while allowing cryptographic agility where it "
        "delivers measurable wins.\n\n"
        "Key design principles:\n"
        "1. Primary structure: partitioned binary tree for canonical minimal shape, "
        "simple parsing, and strong locality. Keep the stem model: one-byte "
        "storage_type plus prefix-free position plus 8-bit subindex for 256 slots.\n"
        "2. Hybrid commitment layer: internal node and stem commitments are "
        "pluggable at the protocol level via hash_id or commitment_id at "
        "activation or per-fork.\n"
        "3. Default profile: binary Merkle commitments (Keccak or Blake3) for "
        "minimal risk and high implementer familiarity.\n"
        "4. High-performance profile: Verkle-style vector commitments at small, "
        "high-impact widths (for example 256-ary stem commitments with IPA or "
        "KZG), without forcing a full vector tree globally.\n"
        "5. zk-optimized profile: Poseidon2 or Circle/Binius-native binary "
        "commitments for proving-heavy environments.\n"
        "6. Conservative or post-quantum profile: lattice-inspired commitments "
        "or hybrid profiles to reduce long-term cryptographic lock-in.\n\n"
        "Why this is better than pure options:\n\n"
        "| Aspect | Pure Verkle | Pure Binary + STARK | Hybrid Vector-Binary (Proposed) |\n"
        "| --- | --- | --- | --- |\n"
        "| Proof Size | Excellent | Good (with STARK) | Best (adaptive) |\n"
        "| Prover Speed | Good | Excellent (Binius/Circle) | Best (choose backend) |\n"
        "| Simplicity and Verifier | Medium | Excellent | Excellent (binary base) |\n"
        "| Crypto Assumptions | ECC | Hash-only | Pluggable (minimal lock-in) |\n"
        "| Locality and Gas | Good | Excellent | Excellent (stem-based) |\n"
        "| Post-Quantum | Weak | Strong (lattice) | Strong (switchable) |\n"
        "| Canonical and Predictable | Good | Excellent | Excellent |\n\n"
        "Standout features:\n"
        "1. Stem-level vectorization: keep 256-slot stems for locality and "
        "pay-for-what-you-touch gas, while optionally using vector commitments "
        "at the stem boundary for compression where width matters most.\n"
        "2. Commitment agility done right: pin commitment scheme per hard fork "
        "with overlap windows, include commitment_type in proofs, and require "
        "verifier support for active profile(s).\n"
        "3. Unified witness format: one proof envelope across backends, with root "
        "reconstruction driven by declared commitment rules.\n"
        "4. Locality and expiry integration: co-locate account, code, and hot "
        "storage in stems; reserve key bits for expiry epochs and metadata; allow "
        "optional witness compression hints for multi-key proofs.\n"
        "5. Prover-optimized non-consensus modes: binary paths (Binius/Circle), "
        "Poseidon2 for circuit-heavy deployments, lattice-first conservatism, and "
        "mixed binary-path plus vector-stem profiles.\n"
        "6. Phone-grade verifier first: retain a minimal compliance target while "
        "allowing smaller proofs in vector mode and faster checks in binary mode.\n\n"
        "Migration and activation:\n"
        "1. Use a deterministic conversion block followed by post-fork enforcement.\n"
        "2. Start with binary Keccak or Blake3 profile to minimize rollout risk.\n"
        "3. Enable Poseidon2 plus vector-stem profile after audit maturity.\n"
        "4. Keep lattice-oriented profile as a longer-horizon safety option.\n\n"
        "Rationale summary:\n"
        "This is convergent evolution, not novelty for its own sake: binary base "
        "for determinism and verifier simplicity, stem locality plus selective "
        "vectorization for proof efficiency, and commitment agility for long-term "
        "cryptographic resilience. The result is a practical path toward default "
        "stateless clients, phone verifiers, and client-side proving while "
        "preserving Ethereum's core value of user-verifiable truth.\n"
    )


def build_brief(config: BriefConfig) -> str:
    executive = (
        "1. Executive Summary (3-4 lines)\n\n"
        f"This design keeps non-consensus experiments (for example, "
        f"{config.prototype_label}) separated from consensus-critical logic, "
        "enabling innovation without destabilizing the base protocol.\n"
        f"It favors a {config.primary_approach} path over "
        f"{config.alternative_approach} for now, reflecting practical deployment "
        "judgment rather than ideological commitment.\n"
        "The real risk is not the core data structure alone, but migration safety "
        f"and gas-accounting correctness, especially around {config.stem_hook_label}.\n"
        "Success will depend on phased rollout, tight audits, and broad "
        "client/community coordination.\n"
    )

    technical = (
        "2. Technical Version (Protocol-Engineer Oriented)\n\n"
        "The architecture cleanly isolates non-consensus prototypes "
        f"(e.g., {config.prototype_label}) from consensus execution, which is the "
        "right boundary for high-velocity experimentation under low consensus risk. "
        "That separation preserves room for cryptographic and performance "
        "exploration while keeping the canonical state transition path reviewable "
        "and deterministic.\n\n"
        f"Choosing a {config.primary_approach} instead of "
        f"{config.alternative_approach} appears operationally pragmatic: it leans "
        "on familiar proof and verification patterns, existing implementation "
        "intuition, and lower integration uncertainty, while still targeting core "
        "objectives such as witness efficiency, locality-aware access patterns, and "
        "implementation tractability. Framed this way, it is a sequencing decision, "
        "not a repudiation of earlier goals.\n\n"
        "The most security-sensitive areas remain migration and economics:\n"
        "1. Migration correctness: state conversion invariants, replay and rollback "
        "safety, dual-read or shadow-state periods, and deterministic cross-client "
        "equivalence checks.\n"
        "2. Gas-model integrity: preventing underpricing and overpricing of access "
        "paths, preserving incentive compatibility, and hardening "
        f"{config.stem_hook_label} against edge-case exploitation.\n"
        "3. Operational safety: bounded blast radius through phased activation, "
        "comprehensive test vectors, client conformance harnesses, and explicit "
        "rollback criteria.\n\n"
        "Historically, the strongest path for state-tree changes has been phased "
        "pragmatism: start with a tractable step that delivers measurable wins, "
        "preserve optionality, and expand scope only after correctness and "
        "economics are demonstrated in production-like conditions.\n"
    )

    governance = (
        "3. Governance Version (Neutral Tone)\n\n"
        "The proposal takes a cautious-but-progressive route: experimental ideas "
        "stay outside consensus first, while the main protocol path remains "
        "conservative and auditable. This helps the ecosystem learn quickly "
        "without taking unnecessary consensus risk.\n\n"
        f"While the design uses a {config.primary_approach} instead of "
        f"{config.alternative_approach} at this stage, the underlying objective is "
        "consistent: improve state scalability and proof practicality in a way that "
        "can realistically ship. The choice looks like an implementation-path "
        "decision based on feasibility and timing, not a permanent philosophical "
        "split.\n\n"
        "As with any state-tree transition, the hardest questions are migration and "
        "fee mechanics. The community will need clear auditing evidence, explicit "
        "rollout checkpoints, and strong cross-client agreement before activation. "
        "A phased plan with transparent success criteria and rollback readiness is "
        "the most credible route to consensus.\n"
    )

    combined = (
        "4. Combined Paragraph\n\n"
        f"Non-consensus prototypes such as {config.prototype_label} are kept "
        "separate from consensus-critical execution, enabling ambitious "
        "experimentation while protecting protocol safety. The current preference "
        f"for a {config.primary_approach} over {config.alternative_approach} reads "
        "as practical sequencing: pursue what can be implemented, audited, and "
        "coordinated now, while preserving long-term flexibility around the same "
        "core goals. The decisive challenges are migration correctness and "
        "gas-accounting integrity, especially around "
        f"{config.stem_hook_label}, where small errors can have consensus or "
        "economic impact. As with prior state-architecture efforts, the most "
        "credible strategy is phased deployment, rigorous cross-client verification, "
        "and explicit community buy-in at each activation gate.\n"
    )

    hybrid_addendum = build_hybrid_addendum(config)

    return "\n".join([executive, technical, governance, combined, hybrid_addendum])


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Generate an executive, technical, governance, and combined narrative "
            "brief for a state-tree proposal."
        )
    )
    parser.add_argument(
        "--prototype-label",
        default="GeminiHash",
        help="Label for non-consensus prototype examples.",
    )
    parser.add_argument(
        "--primary-approach",
        default="binary-hash-tree",
        help="Primary state-tree approach.",
    )
    parser.add_argument(
        "--alternative-approach",
        default="Verkle trees",
        help="Alternative approach used for comparison.",
    )
    parser.add_argument(
        "--stem-hook-label",
        default="stem-aware hooks",
        help="Short label for gas/accounting hook complexity.",
    )
    parser.add_argument(
        "--hybrid-name",
        default="Hybrid Vector-Binary Stem Tree (HVBST)",
        help="Primary label for the hybrid addendum design.",
    )
    parser.add_argument(
        "--hybrid-alias",
        default='Adaptive Vector-Binary State Tree ("Stemtree 2.0")',
        help="Secondary label for the hybrid addendum design.",
    )
    parser.add_argument(
        "--only-hybrid-addendum",
        action="store_true",
        help="Emit only section 5 (HVBST / Stemtree 2.0 addendum).",
    )
    parser.add_argument(
        "--hybrid-addendum-output",
        type=Path,
        default=None,
        help="Optional standalone markdown path for section 5 output.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Optional output markdown path. Defaults to stdout.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    config = BriefConfig(
        prototype_label=args.prototype_label,
        primary_approach=args.primary_approach,
        alternative_approach=args.alternative_approach,
        stem_hook_label=args.stem_hook_label,
        hybrid_name=args.hybrid_name,
        hybrid_alias=args.hybrid_alias,
    )
    brief_text = build_brief(config)
    hybrid_addendum_text = build_hybrid_addendum(config)

    if args.hybrid_addendum_output is not None:
        args.hybrid_addendum_output.parent.mkdir(parents=True, exist_ok=True)
        args.hybrid_addendum_output.write_text(hybrid_addendum_text + "\n", encoding="utf-8")
        print(f"wrote hybrid addendum: {args.hybrid_addendum_output}")

    selected_text = hybrid_addendum_text if args.only_hybrid_addendum else brief_text

    if args.output is None:
        print(selected_text)
        return 0

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(selected_text + "\n", encoding="utf-8")
    print(f"wrote narrative brief: {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
