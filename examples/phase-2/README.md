# Phase 2 Artifacts

This folder will accumulate deterministic `.red` fixtures generated via:

```
cargo run -p redproof-prover -- \
  --url https://example.com \
  --prove header:absent:Strict-Transport-Security \
  --method GET \
  --hash_alg blake3 \
  --format json \
  --out examples/phase-2/example.red
```

After generating an artifact, run the verifier:

```
cargo run -p redproof-verifier -- examples/phase-2/example.red
```

For tamper tests, edit the JSON file manually (e.g., change the `commitments.handshake` field) and ensure `redproof-verifier` reports `handshake digest mismatch`.
