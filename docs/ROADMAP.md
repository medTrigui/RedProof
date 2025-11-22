# RedProof Roadmap & Industry Critique

This roadmap translates the high-level concept into phased, testable deliverables. Each phase lists scope, key tasks, acceptance criteria, and industry-aware critiques to keep RedProof grounded in real red-team workflows.

## Strategic Themes
1. Authenticity without over-collection – proofs must stay TLS-bound yet minimal.
2. Automation-first ergonomics – parity with common CLI tooling (curl, nuclei, burp extensions).
3. Cryptographic correctness – commitments, statement grammar, and ZK circuits must be formally testable and fuzzable.
4. Operational trust – artifacts should survive legal review (chain-of-custody, timestamping, reproducibility).

## Success Metrics
- Proof artifact size: <100 KB for header-level claims.
- Verification latency: <200 ms on laptop-class hardware.
- False-negative rate for supported statements: <1% during Alexa Top 100 regression runs.
- Independent verifier reproducibility: deterministically identical verdicts across OS targets.

## Phase 0 – Repo, Specifications, Trust Model (Day 0–2)
- Tasks: finalize `.red` schema, threat model, glossary, acceptance criteria for statements, baseline `.gitignore` and CI skeleton.
- Deliverables: schema markdown plus JSON schema drafts; threat model doc; CLI UX mockups.
- Exit tests: `cargo fmt` and `clippy` wired, schema validated via `schemars` round-trip tests.
- Critique: many red teams skip formal threat models—force completion now to avoid un-auditable crypto shortcuts.

## Phase 1 – Network Capture & Statement Parser (Week 1)
- Tasks: implement minimal HTTPS GET/HEAD collector (reqwest or hyper-tls), canonical header/body normalization, statement grammar parser with fuzz corpus.
- Deliverables: `prover` crate with capture stub plus `statements` crate publishing an AST.
- Exit tests: integration test hitting public test endpoint (e.g., badssl) and snapshotting normalized transcript.
- Risks / Critique: resist temptation to support POST or authenticated flows—keeps attack surface manageable; add replay protection logging early for legal defensibility.

## Phase 2 – Commitments & Naïve Verification (Week 2)
- Tasks: implement transcript commitments (BLAKE3 for speed plus SHA-256 for compatibility), metadata binding (domain, timestamp, cert fingerprint), deterministic serialization, verifier that replays commitment checks.
- Deliverables: `.red` artifact creation plus verification libraries in `artifact/` reused by both CLIs.
- Exit tests: round-trip property tests across 1K auto-generated responses; CLI integration verifying sample artifact.
- Critique: ensure commitments include TLS context (cipher suite, ALPN) to prevent downgrade disputes; log-time stamping (RFC3161 or Roughtime) should be spec’d now even if implemented later.

## Phase 3 – ZK Circuits (Weeks 3–4)
- Tasks: build equality, hash-equality, and regex (DFA) circuits using Halo2 or Arkworks; define proving/verification key caching; expose `zk/` crate to prover and verifier.
- Deliverables: circuits plus benches, documentation on constraints, deterministic test vectors.
- Exit tests: unit tests verifying ZK proof to statement matches; soundness checked with malformed transcripts.
- Critique: regex proof design must consider catastrophic backtracking; restrict to pre-compiled DFAs to avoid DoS from user-supplied patterns.

## Phase 4 – Artifact Hardening & CLI UX (Week 5)
- Tasks: finalize statement grammar, add multi-proof bundling, implement `redproof list-statements`, ergonomic errors, structured logging, secure temp-file handling.
- Deliverables: CLI man pages, sample `.red` fixtures in `examples/`, docs on integrating with CI/CD.
- Exit tests: `cargo test --all`, golden-manifest verification across OS targets.
- Critique: provide opinionated defaults (for example, always include domain plus ASN), otherwise blue teams will reject artifacts for lack of situational context.

## Phase 5 – Benchmarking & Field Validation (Week 6)
- Tasks: Alexa Top-100 sweeps, latency and size measurements, privacy-leakage quantification, comparison with HAR files and screenshots.
- Deliverables: benchmark report in `docs/`, scripts under `examples/fixtures`, automated Grafana-style dashboard (optional).
- Exit tests: CI job failing if proof size or verify time regress beyond thresholds.
- Critique: include hostile network scenarios (TLS MITM, packet loss) to ensure proofs fail loudly; many orgs require evidence of failure modes.

## Phase 6 – Publication Prep & Responsible Use Kit (Week 7)
- Tasks: whitepaper draft, disclosure workflow templates, legal and ethics appendix, PSIRT adoption playbook.
- Deliverables: `docs/paper/`, `docs/playbooks/`, recorded demo scripts.
- Exit tests: internal dry-run of disclosure flow using mock PSIRT.
- Critique: without clear disclosure guidance, blue teams may distrust artifacts; invest in education material earlier if possible.

## Cross-Cutting Improvements & Industry Critique
- Chain-of-custody: integrate optional RFC3161 timestamping plus notarization hooks to preempt “evidence fabricated later” claims.
- Target authenticity: pair TLS cert fingerprints with DNSSEC-signed records when available; red teams are often challenged on DNS hijack scenarios.
- Operational ergonomics: provide Burp/ZAP plugins early—CLI-only tooling risks low adoption despite strong crypto story.
- Privacy posture: proactively document data-retention guarantees (for example, zero persistence of raw transcripts unless `--debug`), aligning with GDPR-minded PSIRTs.
- Resistance to abuse: specify that the tool refuses to run against non-authorized domains unless `--force` is used with justification logging; prevents casual misuse.
- Replay defense: embed monotonic clock plus optional witness signature (for example, hardware token) for teams operating under FedRAMP or SOC2 requirements.

## Testing & QA Strategy
- Golden transcript fixtures (plain text) plus expected statements committed under `examples/`.
- Differential testing: compare prover output versus scripted curl pipeline for identical requests.
- Fuzzing: `cargo fuzz` targets for statement parser, artifact decoder, and regex compiler.
- Crypto audits: schedule third-party review before the v1.0 tag; document unresolved findings.

## Risk Register Snapshot
| Risk | Likelihood | Impact | Mitigation |
| --- | --- | --- | --- |
| ZK circuit performance too slow | Medium | High | Prototype circuits with realistic payload sizes early (Phase 3), keep non-ZK fallback path documented. |
| Legal admissibility questioned | Medium | Medium | Produce chain-of-custody guidance plus timestamping integration before field tests. |
| TLS handshake variance (HTTP/2 vs 1.1) | Medium | Medium | Normalize representation, capture ALPN negotiation, write regression tests per protocol. |
| Research dependency churn (Halo2, Arkworks) | High | Medium | Vendor-lock minimal; abstract trait-based interfaces to allow future backend swap. |

## Documentation Backlog
- Threat model including attacker personas (rogue tester, tamper-happy PSIRT, malicious verifier).
- Statement grammar reference and Lark/PEG diagrams.
- Operational guide for blue teams verifying artifacts inside restricted networks.

Revisit this roadmap after each phase retrospective; treat timelines as aggressive but achievable for a two to three person Rust team with crypto expertise.
