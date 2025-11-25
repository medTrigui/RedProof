# Phase 2 Runbook (Working Draft)

This runbook outlines how to exercise the commitment + verification workflow once implemented.

## Generating an Artifact
1. Capture target (Phase 1 command) and let prover emit `.red`:
```
cargo run -p redproof-prover -- \
  --url https://example.com \
  --prove header:absent:Strict-Transport-Security \
  --method get \
  --hash-alg blake3 \
  --format json \
  --out examples/phase-2/example.red
```
2. Optional: specify `--format cbor` for binary output; `--hash-alg sha256` for legacy compatibility.

Recent CLI output:
```
[ok] GET https://example.com/ -> examples/phase-2/example.red (statement=true)
```

## Verifying an Artifact
```
cargo run -p redproof-verifier -- examples/phase-2/example.red
VALID
Domain: example.com
Statement: header absent: Strict-Transport-Security
Commitments: Blake3 (witness=true)
```

### Tamper Test
`examples/phase-2/example-tampered.red` is the same artifact with a modified handshake digest. The verifier should fail loudly:
```
cargo run -p redproof-verifier -- examples/phase-2/example-tampered.red
Error: handshake digest mismatch
```

## Troubleshooting
| Symptom | Likely Cause | Resolution |
| --- | --- | --- |
| `unsupported format cbor` | Feature not built | Recompile with `cbor` feature or use JSON. |
| `mismatched algorithm` | Prover/verifier disagree on hash | Ensure verifier supports algorithm recorded in artifact; rerun with common alg. |
| `artifact not deterministic` | Capture changed between runs | Use mock fixtures or ensure deterministic server responses. |
| `warning: no witness included` | Artifact omitted transcript blobs | Re-run prover without `--no-witness` (default includes witness). |

## Checklist Before Merging Phase 2
- [ ] `cargo test -p redproof-prover` and `-p redproof-verifier` pass locally and in CI.
- [ ] Golden artifact fixture included with hash digests documented.
- [ ] Runbook updated with real command transcripts/screenshots.
- [ ] Docs mention limitations (GET/HEAD only, no auth, no ZK).

Update this runbook as soon as the commitment code lands.
