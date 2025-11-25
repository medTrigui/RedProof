# RedProof

RedProof is a CLI toolkit that lets red teams capture HTTPS responses and produce small, cryptographically bound proof artifacts (`.red` files). Each artifact proves a single statement (e.g., “Strict-Transport-Security header was missing”) without dumping the entire payload. Blue teams run the verifier CLI offline and receive a deterministic `VALID` or `INVALID` verdict.

## Why RedProof Exists
- **Authenticity without screenshots:** TLS context (version, cipher, certificate fingerprints) is bound into every artifact so evidence cannot be fabricated later.
- **Selective disclosure:** We only reveal whether a statement is true, not the raw response data, which keeps privacy/document-handling risks low.
- **Automation friendly:** Both prover and verifier are CLI-first, easy to script, and emit machine-readable output when needed.
- **Crypto-ready roadmap:** Phase 2 uses traditional commitments plus witness data; later phases will add zero-knowledge proofs while keeping the same schema.

## Current Capabilities
- Phase 1 capture/evaluation stack (rustls GET/HEAD, normalized headers/body, statement parser) is in place.
- Phase 2 workflow is live:
  - `redproof-prover` can emit JSON or CBOR `.red` files with BLAKE3 or SHA-256 commitments.
  - Witness blobs (base64 transcripts) are embedded so the verifier can recompute hashes today.
  - Sample good/tampered artifacts live under `examples/phase-2/` for demos/tests.
- `redproof-verifier` validates artifacts, recomputes commitments when possible, and prints `VALID` or `INVALID: reason` without crashing.

See [`docs/PHASES.md`](docs/PHASES.md) for a plain-English project timeline.

## Quick Start
**Prerequisites**
- Rust (stable) with `cargo fmt` and `cargo clippy` installed.
- On Windows, install Visual Studio Build Tools (C++ workload) and the Windows 10/11 SDK so `link.exe` and the TLS stack work.

**Standard workflow**
```bash
cargo fmt --all
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all --all-features
```

## Usage Examples
### 1. Dry-run capture (no artifact written)
```bash
cargo run -p redproof-prover -- \
  --url https://example.com \
  --prove header:absent:Strict-Transport-Security \
  --method get \
  --hash-alg blake3 \
  --format json \
  --dry-run
```
Outputs a JSON preview containing request metadata, TLS info, normalized headers, and the statement evaluation.

### 2. Emit an artifact
```bash
cargo run -p redproof-prover -- \
  --url https://example.com \
  --prove header:absent:Strict-Transport-Security \
  --method get \
  --hash-alg blake3 \
  --format json \
  --out examples/phase-2/example.red
```

### 3. Verify the artifact
```bash
cargo run -p redproof-verifier -- examples/phase-2/example.red
# VALID
# Domain: example.com
# Statement: header absent: Strict-Transport-Security
# Commitments: Blake3 (witness=true)
```

### 4. Tamper detection demo
```bash
cargo run -p redproof-verifier -- examples/phase-2/example-tampered.red
# INVALID: handshake digest mismatch
```

## Repository Layout
- `prover/` – CLI, HTTPS capture, statement evaluation, commitment builder.
- `verifier/` – CLI and commitment verification logic.
- `artifact/` – Artifact structs, serde helpers, JSON Schema generator.
- `statements/` – Statement grammar/parser shared across crates.
- `docs/` – Design docs, phase notes, roadmap, architecture reference.
- `examples/` – Fixture artifacts (good + tampered) for demos/regressions.
- `zk/` – Placeholder for future zero-knowledge circuits (Phase 3).

## Documentation & Architecture
- [`docs/PHASES.md`](docs/PHASES.md) – phase-by-phase summary.
- [`docs/phase-*`](docs) – detailed runbooks per milestone.
- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) – mermaid diagrams and deeper explanations.

If you are new to the project, read `docs/PHASES.md`, skim `docs/ARCHITECTURE.md`, then follow the usage examples above to produce and verify your first `.red` artifact. Contributions are welcome—open an issue or PR with your improvements.
