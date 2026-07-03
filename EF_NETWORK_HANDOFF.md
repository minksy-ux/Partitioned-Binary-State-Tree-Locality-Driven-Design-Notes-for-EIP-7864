# Ethereum Foundation Handoff and Network Readiness

This repository is a research/reference implementation for EIP-7864-oriented state structures.
It is not a consensus client and cannot directly deploy protocol rules to Ethereum mainnet.

This document defines what an Ethereum client team (or EF research/engineering team) needs in order to evaluate and potentially integrate these ideas into a real network rollout process.

## What Is Ready in This Repository

- Canonical key derivation and partitioned tree model (Python + Rust reference code)
- Batch Merkle proofs and optional VectorFold prototype mode
- Hash agility with Blake3, Poseidon2 placeholder mode, and Gemini prototype mode
- Property/integration tests for core behavior

## Safety Boundaries

- GeminiHash and VectorFold are experimental.
- Production paths must use Blake3 or audited Poseidon2 backend until Gemini is reviewed.
- This repository does not define activation logic for Ethereum consensus clients.

## Required Steps Before Any Mainnet Candidate

1. Cryptographic review
- Independent review of Gemini permutation/compression, domain separation, and transcript binding.
- Third-party audit report and public test vectors.

2. Client-spec alignment
- Translate this reference behavior into execution-client specification language.
- Add compatibility tests across at least two independent client implementations.

3. Deterministic vectors
- Freeze JSON vectors for key derivation, proof verification, and migration semantics.
- Add cross-language conformance tests (Rust, Python, and client language).

4. Performance and resource envelopes
- Publish proving/verifying CPU and memory ceilings for consumer hardware.
- Include witness/proof size measurements at block-scale workloads.

5. Activation governance
- Define EIP activation path (devnet -> testnet -> mainnet) and rollback plan.
- Include fork-choice and failure-mode playbooks.

## CI Gate Included Here

This repository now includes a CI gate (`.github/workflows/network-readiness.yml`) that:

- validates `network-readiness.manifest.json` policy gates,
- runs Python tests
- runs Rust tests
- builds a deterministic release bundle for EF/client review

## Machine-Readable Readiness Manifest

The file [network-readiness.manifest.json](network-readiness.manifest.json) is the source of truth for release policy.

- It explicitly blocks Gemini and VectorFold from production profile use.
- It tracks required promotion gates (audit, conformance, vectors, performance, activation/rollback).
- CI validates the manifest through [scripts/validate_network_readiness.py](scripts/validate_network_readiness.py).

To mark production eligibility, update gate statuses to `complete`/`waived` with evidence and set `release_decision.production_eligible` to `true`.

## Release Bundle

Run:

```bash
bash pbt-rs/scripts/release_bundle.sh
```

Artifacts written to `dist/`:

- `pbt-rs-source.tar.gz`
- `pbt-rs-sha256.txt`
- `network-readiness-summary.txt`

## What EF/Client Teams Can Do Next

1. Consume release bundle and vectors.
2. Reproduce all tests in isolated CI.
3. Port reference logic into client prototype branch.
4. Run shadow-network experiments before any testnet consideration.
