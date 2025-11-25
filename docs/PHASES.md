# RedProof Project Phases (Plain-English Walkthrough)

This document keeps a running log of what we have accomplished so far, why it matters, and what comes next. It is written in simple language so new contributors (or future us) can quickly understand the journey.

## What RedProof Is
- A CLI toolkit for red teams to capture HTTPS evidence and produce small `.red` files.
- Each artifact proves a single statement (e.g., “Strict-Transport-Security header was missing”) without dumping the full response.
- Blue teams run a verifier CLI that checks cryptographic commitments and prints VALID/INVALID along with the statement summary.

## Phase 0 – Foundations (Done)
**Goal:** Agree on scope, structure, and trust model before writing real code.

**Highlights**
- Defined the `.red` artifact schema (JSON + CBOR) and committed a sample file.
- Captured the threat model, glossary, CLI UX expectations, and roadmap under `docs/phase-0/`.
- Bootstrapped the Rust workspace (`artifact`, `prover`, `verifier`, `statements`, `zk`) with shared dependencies and GitHub Actions CI skeleton.

**Why it matters**
- Everyone knows the rules of the game (which statements are in scope, what privacy guarantees we promise, why TLS matters).
- Schema + docs give downstream code a contract to target, reducing churn later.

## Phase 1 – HTTPS Capture + Statement Parser (In Progress, capture/test foundation done)
**Goal:** Move from dry-run CLIs to a working capture pipeline and statement parser.

**What we built**
- `prover/src/capture.rs` opens HTTPS connections (GET/HEAD via rustls), records TLS metadata, normalizes headers/body, and returns canonical transcripts.
- `prover/src/evaluate.rs` parses the statement (header presence/equality, hash checks, regex patterns) and reports whether the captured response satisfies the claim.
- Added unit tests for the parser and capture helpers so normalization, truncation limits, and regex scopes behave predictably.
- CLI now supports:
  - `--method get|head`
  - `--hash-alg blake3|sha256`
  - `--format json|cbor`
  - `--dry-run` to print a JSON preview without writing an artifact.

**Why it matters**
- We can hit real targets (e.g., `https://example.com`) and inspect normalized responses before worrying about cryptography.
- Statement parsing errors are surfaced early with friendly messages, keeping future UX smooth.

**Next within Phase 1**
- Add more integration-style tests using mock servers so captures don’t rely on the public internet.
- Flesh out the dry-run preview in docs so QA knows what to look for.

## Phase 2 – Commitments & Naïve Verification (In Progress, core workflow done)
**Goal:** Turn captures into real `.red` artifacts and allow verifiers to independently validate them.

**What is done**
- `prover/src/commit.rs` builds dual commitments (BLAKE3 + SHA-256) and optionally embeds witness blobs (base64 transcripts) for re-verification.
- CLI emits real `.red` files (JSON or CBOR) containing TLS metadata, statement details, commitments, and a placeholder proof marker.
- `verifier/src/main.rs` loads artifacts, validates schema, recomputes commitments (when witness data exists), and prints `VALID` or `INVALID: <reason>` without crashing on tampered files.
- Added fixtures:
  - `examples/phase-2/example.red` (good artifact from `https://example.com`).
  - `examples/phase-2/example-tampered.red` (same file with a corrupted handshake commitment).
- Docs updated (`examples/phase-2/README.md`, `docs/phase-2/runbook.md`) with exact commands/output.

**Why it matters**
- We can now hand a `.red` file to a teammate and they can verify it offline—no screenshots or HAR dumps required.
- Tamper detection is demonstrated in a reproducible way, which is key for trust.

**Still to do in Phase 2**
- More automated tests (e.g., create artifact -> verify -> tamper -> fail) running inside `cargo test`.
- Cleaner error messages when witness blobs are missing.
- Decide on deterministic CBOR encoding (or stick with JSON for now).

## Phase 3 and Beyond (Planned)
- **Phase 3 – ZK Circuits:** Implement equality/regex proofs so we don’t need to ship witness data. This lives in `zk/` and will hook into the prover/verifier.
- **Phase 4 – CLI UX Polish:** Multi-proof bundles, better logging, `redproof list-statements`, etc.
- **Phase 5 – Benchmarks & Field Validation:** Run Alexa Top-100 sweeps, collect size/latency metrics, and document failure modes.
- **Phase 6 – Publication & Responsible Use Kit:** Whitepaper, PSIRT playbooks, disclosure templates, timestamp/notarization hooks.

## Quick Reference
- Run all tests: `cargo test --all --all-features`
- Format/lint: `cargo fmt --all` and `cargo clippy --all-targets --all-features -- -D warnings`
- Dry-run capture: `cargo run -p redproof-prover -- --url https://example.com --prove header:absent:Strict-Transport-Security --dry-run`
- Generate artifact: same command without `--dry-run` plus `--out FILE`
- Verify artifact: `cargo run -p redproof-verifier -- examples/phase-2/example.red`

Feel free to append notes after each phase to keep this timeline current.
