# Phase 1 Runbook (Working Draft)

This runbook tracks how to exercise the Phase 1 functionality (HTTPS capture + statement parser) as it is implemented. Update it alongside code changes.

## Prereqs
- Rust toolchain (`rustup` stable) with OpenSSL-independent backend (prefer `rustls`).
- Network access to target sites (e.g., `https://example.com`, `https://badssl.com`).
- Optional: mock server fixture (wiremock/httpmock) for deterministic tests.

## Command Cheat Sheet
```
# Basic capture (GET, dry-run JSON preview)
cargo run -p redproof-prover -- \
  --url https://example.com \
  --method GET \
  --prove header:absent:Strict-Transport-Security \
  --dry-run

# HEAD request with custom CA bundle
cargo run -p redproof-prover -- \
  --url https://internal.example \
  --method HEAD \
  --cafile certs/internal-ca.pem \
  --prove header:present:Server \
  --dry-run
```

Expected JSON preview keys:
- `request`: method, URL, timestamp.
- `tls`: version, cipher, ALPN, cert fingerprints.
- `response`: status, normalized headers, truncated body hash.
- `statement`: parsed form + validation result.

## Troubleshooting
| Symptom | Likely Cause | Action |
| --- | --- | --- |
| `TLS error: invalid certificate` | Target uses self-signed cert | Supply `--cafile` or `--insecure` (if policy allows). |
| `Body truncated` flag set | Response exceeded size cap | Increase `--max-body-kb` (document default 128 KB). |
| Parser error `unknown statement prefix` | User typo | Show usage examples; confirm quoting for regex statements. |

## Verification Steps
1. Run capture against `https://example.com` (GET) and confirm header normalization deterministic (sorted, lowercase names).
2. Run capture against `https://badssl.com` with `header:absent:Strict-Transport-Security`; confirm statement evaluates to true and preview marks it as satisfied.
3. Execute tests: `cargo test -p redproof-prover` and parser fuzz/deterministic tests.

Document real outputs/screenshots here once Phase 1 code lands.
