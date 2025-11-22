# RedProof

RedProof delivers verifiable, privacy-preserving HTTPS evidence artifacts so red-team findings carry cryptographic weight without leaking sensitive payloads.

## Why RedProof
- Replace screenshots or HAR dumps with TLS-bound, selective-disclosure proofs (.red files).
- Provide blue teams with independently verifiable statements while minimizing data handling risk.
- Bridge offensive testing workflows with applied crypto (commitments plus optional ZK circuits).

## Repository Layout (initial scaffolding)
- `prover/` - Rust CLI that captures HTTPS sessions, evaluates statements, and emits artifacts.
- `verifier/` - CLI/library for deterministic proof validation; future WASM target for UI flows.
- `zk/` - Shared zero-knowledge gadgets (equality, regex DFA, hash equality) plus circuit tests.
- `artifact/` - CBOR/JSON schema definitions, codecs, and signing/verification helpers.
- `statements/` - Statement grammar, parser, and semantic validation utilities.
- `docs/` - Design notes, roadmap, critique, and operational guidance.
- `examples/` - Reference fixtures, mock targets, and sample `.red` artifacts once generated.

