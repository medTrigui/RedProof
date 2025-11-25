# Phase 2 – Commitments & Naïve Verification

Goal: take the raw capture output from Phase 1 and turn it into a minimal `.red` artifact pipeline. The prover should build cryptographic commitments over the captured bytes, serialize the artifact, and the verifier should validate schema + commitments (without zero-knowledge proofs yet).

## Scope
- Implement transcript commitment logic (handshake + app data) using BLAKE3 for speed and SHA-256 for compatibility. Capture both digests so we can choose at verify-time.
- Bind metadata (domain, timestamp, TLS version, cipher, ALPN, cert fingerprints) into the commitment context to prevent downgrade/replay attacks.
- Extend `redproof-artifact` with commitment algorithms, optional witness blobs, and deterministic serialization helpers.
- Update `redproof-prover` to emit actual `.red` files (CBOR or JSON) that include commitments, the parsed statement, and a placeholder `proof` blob (could be base64-encoded “naive-proof” for now).
- Update `redproof-verifier` to read `.red`, validate schema, recompute commitments against an embedded transcript digest, and output `VALID/INVALID` with errors for mismatches.
- Add fixture artifacts under `examples/phase-2/` with deterministic inputs so tests can check both prover and verifier behavior.

## Out of Scope (Phase 3+)
- Zero-knowledge proofs (regex equality) – we only run basic equality checks here.
- Timestamp notarization / RFC3161 integration.
- Multi-statement packing or DP aggregation.

## Deliverables
1. `prover/src/commit.rs` (or similar) implementing transcript hashing + artifact serialization.
2. `verifier/src/checks.rs` verifying commitments and TLS metadata.
3. CLI flags: `--out proof.red`, `--format json|cbor`, `--hash-alg blake3|sha256`.
4. Sample artifacts + transcripts in `examples/phase-2/` with README showing expected verify output.
5. Documentation: `docs/phase-2/README.md` (scope) and `docs/phase-2/runbook.md` (how to generate/verify artifacts) plus threat-model updates referencing commitment guarantees.

## Acceptance Criteria
- `cargo test -p redproof-prover` and `cargo test -p redproof-verifier` exercise commitment round-trips with mock transcripts.
- Manual flow: capture via Phase 1 CLI, run `redproof-prover --out artifact.red`, then `redproof-verify artifact.red` returns `VALID` with the same statement result as the capture preview.
- Verifier rejects tampered artifacts (edit a commitment and see `INVALID: handshake digest mismatch`).
- Artifact serialization is deterministic; repeated runs with identical inputs produce byte-identical files (checked in tests via hex digests).

## Technical Notes
- Transcript format: store minimal canonical chunks (e.g., `handshake: Vec<u8>` and `app_data: Vec<u8>`) even if we only hash them; optionally store truncated samples for debugging gated behind `--debug`.
- Consider using `serde_cbor` for binary `.red` plus `serde_json` for human-friendly mode. Provide CLI switch.
- Use `once_cell` or global static to hold hashers if perf becomes a concern; but start simple with incremental `Hasher` objects.
- Logging should clearly differentiate between capture errors vs. commitment mismatches.

## Risks & Mitigations
| Risk | Mitigation |
| --- | --- |
| Hash algorithms drift between prover/verifier | Version fields + tests that ensure algorithms are recorded per artifact. |
| Large transcript memory usage | Introduce size caps, stream hashing while capturing to avoid keeping full body in memory (optional optimization). |
| Attackers craft collisions | Provide dual-hash (BLAKE3 + SHA-256) to make collisions impractical given scope. |
| Determinism regressions | Add snapshot tests comparing serialized artifacts against golden files. |

## Testing Strategy
- Unit tests for commitment builder (hash known buffers, compare digests).
- Integration tests: generate artifact from fixture capture, verify with CLI, tamper artifact and assert failure.
- Property tests ensuring serialization round-trips via CBOR/JSON produce the same Rust struct.
- CI: extend GitHub workflow to run prover/verifier crates individually.

## Next Steps
1. Design transcript struct (handshake bytes, body, metadata) and integrate with Phase 1 capture output.
2. Implement commitment module + tests.
3. Wire prover CLI to produce `.red` artifacts (JSON default, optional CBOR).
4. Implement verifier commitment checks + CLI output.
5. Update docs/runbook with instructions and sample commands.
