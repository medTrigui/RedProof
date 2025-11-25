# Phase 1 – Network Capture & Statement Parser

Goal: transform the scaffolding from Phase 0 into a minimally-functional prover that can fetch unauthenticated HTTPS responses (GET/HEAD), normalize headers/bodies, and parse the statement grammar so we can start generating truthful claims (without yet producing full cryptographic proofs).

## Scope
- Implement a reusable HTTPS capture module in `prover/` using `reqwest`/`hyper-tls` (Rustls preferred) with sane timeouts and redirect policy.
- Normalize response data: canonical header casing, deterministic ordering, optional body truncation limits.
- Integrate the `redproof-statements` parser so CLI inputs like `header:absent:Strict-Transport-Security` produce strongly typed `Statement` values (with helpful error messages).
- Store raw TLS metadata needed later (`protocol`, `cipher`, peer cert fingerprints, ALPN) and expose it via a capture struct.
- Provide a dry-run artifact preview (JSON) so we can inspect captures even before commitments/ZK exist.

## Out of Scope (defer to Phase 2+)
- Cryptographic commitments or proofs.
- Authenticated requests (cookies, headers, tokens).
- POST/PUT/other methods (GET/HEAD only).
- Multi-statement bundles.

## Deliverables
1. `prover/src/capture.rs` (or similar) with unit tests using `wiremock`/`httpmock` fixtures.
2. Statement parser module that turns CLI strings into `Statement` enums; includes fuzz corpus and descriptive errors.
3. CLI updates: `redproof-prover` should run a real GET/HEAD, log TLS metadata, and output a JSON preview (not the final `.red` format yet) behind `--dry-run`.
4. Regression fixtures under `examples/fixtures/phase-1/` containing captured responses from known public targets (e.g., badssl).
5. Docs: `docs/phase-1/runbook.md` describing capture behavior, normalization rules, and troubleshooting.

## Acceptance Criteria
- `cargo test --package redproof-prover` covers capture and parser logic (mocked HTTPS + statement parsing).
- Manual run: `cargo run -p redproof-prover -- --url https://badssl.com --prove header:absent:Strict-Transport-Security --method GET --dry-run` prints a structured JSON block containing TLS context, headers, and parser output.
- Parser rejects malformed statements with actionable error text (e.g., “expected header:absent:<name>”).
- Capture module records at least: TLS version, cipher suite, ALPN, leaf cert fingerprint (SHA-256), UTC timestamp, request method, and normalized headers/body.
- Docs updated to explain how to run captures, what data is stored, and how privacy is maintained.

## Dependencies & Tooling
- Libraries: `reqwest` (with `rustls-tls`), `tokio` runtime, `url`, `http` crate for header utilities.
- Testing: `httpmock` or `wiremock-rs` for deterministic responses; `cargo fuzz` target for the parser (optional but encouraged).
- Logging: `tracing` or `env_logger` to provide debug info without leaking secrets (respect `--quiet`).

## Risks & Mitigations
| Risk | Mitigation |
| --- | --- |
| TLS handshake differences across OSes | Prefer `rustls` backend (cross-platform) and add integration test hitting `https://example.com`. |
| Parser DoS via huge inputs | Cap statement length, use `nom`/manual parsing with explicit size checks. |
| Sensitive data retained on disk | Store captures in memory only during Phase 1; add `--debug-dump` gated flag for writing fixtures. |
| Redirect loops or large bodies | Enforce redirect limit and body size cap (configurable). |

## Testing Strategy
- Unit tests for statement parser (valid/invalid cases, fuzz corpus seeds).
- Integration tests for capture module: mock HTTPS server returning known headers; verify normalization output.
- Manual smoke tests against public endpoints (badssl, example.com) documented in `runbook.md`.
- CI: ensure new crates/features compile on Linux (GitHub Actions) and locally on Windows.

## Next Steps
1. Prototype statement parser API and tests.
2. Build capture module with dependency injection for HTTP client (enable mocking).
3. Wire CLI flags to parser + capture, returning JSON preview.
4. Add documentation + fixtures, then run full test suite.
