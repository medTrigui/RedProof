# Phase 2 Artifacts

`example.red` is a captured artifact for `https://example.com` proving that `Strict-Transport-Security` is absent. Regenerate it at any time with:

```
cargo run -p redproof-prover -- \
  --url https://example.com \
  --prove header:absent:Strict-Transport-Security \
  --method get \
  --hash-alg blake3 \
  --format json \
  --out examples/phase-2/example.red
```

Verification (expected `VALID`):

```
cargo run -p redproof-verifier -- examples/phase-2/example.red
# VALID
# Domain: example.com
# Statement: header absent: Strict-Transport-Security
# Commitments: Blake3 (witness=true)
```

`example-tampered.red` is the same artifact with `commitments.handshake` modified. The verifier should flag it:

```
cargo run -p redproof-verifier -- examples/phase-2/example-tampered.red
# Error: handshake digest mismatch
```
