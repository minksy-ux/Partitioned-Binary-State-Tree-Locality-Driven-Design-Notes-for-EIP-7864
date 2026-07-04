# Release Notes

## Release Scope

Draft release notes for the PBT reference implementation and readiness toolchain.
This file is required for production-eligible promotions and should be copied into the GitHub release body.

## Security Review

Research-phase status: GeminiHash and VectorFold are experimental and not approved for production profile use.
Production profile remains limited to Blake3 or audited Poseidon2 implementations.

## Audit Evidence

No external cryptographic audit has been attached for GeminiHash yet.
Attach audit references and reviewer sign-offs here before setting production_eligible=true.

## Client Compatibility

Current repository is a reference implementation and not a consensus client.
Client compatibility evidence must include at least two independent client implementations.

## Activation Scope

No network activation is proposed from this repository directly.
Activation details must include staged devnet/testnet rollout boundaries and criteria.

## Rollback Plan

Rollback planning is currently pending and must include trigger conditions, operator runbooks,
and post-incident verification procedures before any production-eligible designation.
