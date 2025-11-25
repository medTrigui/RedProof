# Phase 0 – Threat & Trust Model

## Assets
- **Evidence integrity**: TLS transcript commitments, proofs, and metadata.
- **Operator privacy**: CLI usage should not leak target credentials or PII beyond the claim.
- **Verifier trust**: Blue teams rely on deterministic, tamper-evident artifacts.

## Roles
| Actor | Goal | Capabilities |
| --- | --- | --- |
| Authorized Red Teamer (prover) | Capture evidence within scope. | Full CLI access, target reachability, can rerun captures. |
| Blue Team / PSIRT (verifier) | Validate artifacts without raw data. | Access to verifier binary, artifact file. |
| Rogue Tester | Fabricate or tamper with artifacts. | CLI access but no target authorization. |
| Malicious Verifier | Attempt to learn extra info from artifact. | Access to artifact internals, can run custom tooling. |

## Assumptions
1. Prover has legal authorization to test the target domain.
2. TLS stack (Rustls/OpenSSL) correctly validates certificates.
3. Local workstation is trusted (no malware altering binaries in-memory).
4. Time synchronization is within a few seconds (for timestamping later phases).

## Out-of-Scope Threats (Phase 0)
- Compromise of the prover host OS.
- CA compromise or fraudulent certificates.
- Attacks on future ZK circuits (Phase 3+). For Phase 0 we only model commitments.

## Primary Threats & Mitigations
| Threat | Mitigation |
| --- | --- |
| Fabricated artifact detached from TLS context | Bind domain, time, TLS version, cipher, and cert fingerprints into commitments. |
| Transcript tampering after capture | Base64 commitments validated before verification; future phases add signature/timestamp. |
| Over-disclosure of sensitive data | Statement grammar constrains disclosure; regex scope defaults to `any` and will enforce truncation policy later. |
| Unauthorized target scanning | CLI will require `--force` with justification; audit log planned for later phases. |
| Verifier learns more than intended | Minimal metadata plus optional selective disclosure proofs; no raw headers/bodies included. |

## Trust Boundaries
- **Network boundary**: HTTPS session between prover and target.
- **Artifact boundary**: `.red` file shared with verifiers; only contains commitments + selective statements.
- **Verifier runtime**: Offline command that should not contact external services unless explicitly configured (e.g., timestamp validation later).

## Residual Risks
- Without third-party timestamping, a rogue tester could back-date evidence. Mitigation tracked for Phase 2/4.
- CLI currently relies on operators to document scope; enforcement (#scope-file) to be designed later.
- Base64 validation catches tampering but does not prove cryptographic binding; requires Phase 2 commitments and Phase 3 ZK proofs.
