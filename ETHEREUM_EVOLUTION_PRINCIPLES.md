# Ethereum Evolution Principles (Companion to EIP-7864)

This document captures ecosystem-level principles that motivated EIP-7864 but are intentionally separated from the core state-tree specification.

EIP-7864 remains the consensus source for tree shape, key derivation, proof verification, gas hooks, and migration semantics.

## Purpose

The purpose of this companion is to preserve long-horizon direction without overloading a core state-structure EIP with governance and roadmap mandates that require broader process consensus.

## Principle Set

### 1. Consumer-Device Verification

The ecosystem should target practical local verification on mainstream consumer hardware, including mobile devices, and continuously publish benchmark targets and methodology.

Priority implementation track:

- ship a minimal phone-grade verifier reference binary (Rust and/or WASM),
- prove viability on mid-range Android hardware,
- provide embeddable components for wallet teams.

### 2. Formal Verification Maturity

Consensus-critical components should be progressively machine-checked. Verifiability cost should be tracked as a first-class engineering metric.

Priority implementation track:

- publish a public formal-verification dashboard with component-level coverage,
- require reproducible proof-check pipelines in CI for consensus-critical logic,
- publish unresolved verification gaps and remediation timelines.

### 3. L2 Quality And Interop Bar

L2 systems should publish transparent proof, dispute, data-availability, and decentralization properties. Trust-minimized bridge standards should be preferred over committee/multisig trust.

### 4. Complexity Budgeting

Protocol evolution should manage complexity as a bounded resource and periodically retire legacy mechanisms where possible.

### 5. Privacy Baseline

Common wallet flows should minimize query-pattern leakage and avoid single-provider observability where practical.

### 6. Decentralization Metrics

Client diversity, staking concentration, RPC concentration, and builder concentration should be measured and published with pre-agreed response playbooks.

### 7. Cryptographic Agility And PQ Readiness

Long-horizon planning should include migration paths toward post-quantum-safe operation while preserving compatibility and user safety.

### 8. Verified RPC As UX Default

Wallet UX should clearly distinguish locally verified values from unverified remote responses.

Priority implementation track:

- standardize a minimal verified-RPC companion protocol,
- require proof-carrying responses in wallet-facing SDK defaults,
- treat RPC endpoints as untrusted witness providers by design.

### 11. Mandatory State Expiry Protocol

State expiry should move from optional roadmap concept to a mandatory protocol track with deterministic rules and explicit proof semantics.

Priority implementation track:

- define expiry metadata locations in reserved keyspace,
- standardize expiry transition and grace-window rules,
- require expiry-proof verification compatibility for stateless and partially stateless clients.
- publish cross-client expiry transition vectors and revival vectors,
- gate activation on public conformance dashboards and interop testnet results.

### 12. Memorable Public Messaging

Ecosystem communication should use a stable, memorable verification-first message while preserving precise technical naming in specs.

Priority messaging track:

- normative name in specs: Partitioned Binary Tree (PBT),
- public-facing message: "Ethereum: verify, do not trust.",
- wallet and SDK UX should expose verified/unverified status in user language.

Recommended supporting taglines:

- "Proofs, not promises."
- "Your wallet verifies."
- "Local checks. Global consensus."

### 13. Canonical Phone User Story

A concrete, reproducible phone-user journey should be treated as a release-gating artifact, not just explanatory text.

Priority implementation track:

- publish a canonical flow for balance, token, and NFT reads,
- define SLOs for verified-read latency and retry behavior,
- include fixture-based replay tests against reference providers.

### 9. Social Recovery And Timelock Safety

Account UX should prioritize recoverability and key-theft mitigation by default.

### 10. Censorship-Resistance Monitoring

Inclusion fairness and censorship latency should be tracked and reported with transparent methodologies.

## Suggested Public Dashboard Signals

- share of wallet sessions using local verification by default,
- median verified-read latency on mobile hardware,
- proof size distribution for common balance/token/NFT flows,
- provider concentration for witness retrieval traffic,
- hot-stem cache hit rates in reference clients.
- formal-verification coverage by protocol component,
- open verification gaps and mean time to closure,
- state-expiry rollout progress (client support, proof conformance, activation readiness).

## Relationship To EIP-7864

EIP-7864 references this document for ecosystem objectives and deployment philosophy. If any statement here conflicts with EIP-7864 consensus language, EIP-7864 controls consensus behavior.
