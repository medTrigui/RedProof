# Phase 0 – CLI UX Mockups

Goal: describe the ergonomics before implementation begins so future phases can test against these expectations.

## Prover (`redproof-prover`)
```
redproof-prover \
  --url https://target.example \
  --prove header:absent:"Strict-Transport-Security" \
  --out hsts-missing.red \
  --tls-version TLS1.3 \
  --policy owasp-a05
```

### Required Flags
- `--url <HTTPS URL>` – GET/HEAD only.
- `--prove <statement>` – grammar defined in `redproof-statements`.

### Optional Flags
- `--out <path>` – defaults to `proof.red`.
- `--method <GET|HEAD>` – defaults to GET.
- `--cafile`, `--insecure` – advanced TLS switches.
- `--policy <name>` – run predefined statement set (future work).
- `--force` – bypass scope guardrails with justification prompt.

### Output Expectations
- Structured JSON log to stdout + friendly summary.
- `--quiet` flag for CI automation.
- Exit codes: `0` success, `2` validation failure (statement false), `3` network error, `4` misuse.

## Verifier (`redproof-verify`)
```
redproof-verify proof.red
# VALID
# Domain: target.example
# Statement: header:absent("Strict-Transport-Security")
# TLS: TLS1.3 TLS_AES_128_GCM_SHA256 SHA256:abcd...
```

### Flags
- `--format {auto,json,cbor}` – artifact decoding strategy.
- `--details` – emit full metadata for audit logs.
- `--expect <statement>` – optional guard to ensure artifact matches a specific claim.

### UX Notes
- If verification fails, show actionable error (schema mismatch vs. invalid proof vs. expired timestamp).
- Provide `--machine` to emit JSON for pipeline integration.
- Avoid network calls unless timestamp validation is explicitly requested.

## Testing Hooks
- Expose `redproof-prover --dry-run` (implemented now) so QA can validate parsing without hitting targets.
- Provide `redproof-verify --sample` to emit sample artifacts for debugging.

These expectations will guide future acceptance tests and docs once implementation moves past scaffolding.
