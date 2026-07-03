# Vision One-Pager: Verifiable State Tree

Tagline: Ethereum: Verify, don't trust - on your phone.

## Why This Matters

Ethereum should let users verify critical state directly on consumer hardware. The Verifiable State Tree direction makes local verification a default UX expectation instead of a specialist mode.

## What Changes

- Replace variable-arity, RLP-heavy state structure with a canonical binary tree.
- Make stems the first-class locality unit for efficient reads and proofs.
- Keep hash agility while supporting proving-oriented hash profiles.
- Standardize proof-carrying RPC and local verification workflows.

## Consumer-Hardware North Star

- Mid-range phone (2026): 512 MB RAM, sync under 30s, proof verification under 2s per block.
- High-end phone: 1 GB RAM, sync under 10s, proof verification under 500ms per block.

## Execution-Layer Story

PBT is designed to co-evolve with prover-friendly VM work. Combined with a RISC-V-centric execution path and Poseidon2-oriented proving stacks, total proving cost is expected to drop by more than 80% versus current EVM + MPT baselines on representative workloads.

## State Sustainability

Reserved metadata lanes enable deterministic partial state-expiry semantics without restructuring proof paths. This keeps long-term state growth manageable while preserving local-verification guarantees.

## Ecosystem Outcomes to Measure

- Average witness size for account access under 10 KB.
- More than 50% of validators operating stateless or partially stateless clients within 2 years.
- Measurable reduction in centralized RPC dependence for common wallet reads.
- Publicly tracked proving-cost reduction milestones.

## Product Message

Proofs, not promises. Your wallet verifies.
