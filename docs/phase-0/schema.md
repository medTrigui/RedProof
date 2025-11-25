# Phase 0 – Artifact Schema Notes

This document describes the `.red` artifact structure that Phase 1+ code must honor. The canonical JSON Schema lives in `artifact/schema/redproof.schema.json` and is generated via:

```
cargo run -p redproof-artifact --bin schema_dump > artifact/schema/redproof.schema.json
```

## Top-Level Object
| Field | Type | Description |
| --- | --- | --- |
| `version` | string | Artifact spec version (semantic). |
| `domain` | string | FQDN requested by the prover. Required and trimmed. |
| `time_utc` | RFC3339 timestamp | Capture time (UTC). |
| `tls` | object | TLS handshake context (version, cipher, ALPN, cert hashes). |
| `statement` | object | Selective disclosure claim, serialized via `redproof-statements`. |
| `commitments` | object | Base64-encoded commitments to handshake/application data. |
| `proof` | string (base64) | Proof blob (ZK or classical). |
| `meta` | object | Tooling metadata + optional annotations. |

## TLS Context (`tls`)
- `version`: e.g., `TLS1.3`.
- `cipher`: negotiated cipher suite.
- `cert_fingerprints`: one or more SHA-256 (or better) fingerprints prefixed with hash name (`sha256:abcd...`).
- `alpn`: optional ALPN token (e.g., `h2`).

## Statement Grammar
Statements are encoded via tagged enums; the JSON payload contains a `type` discriminator and type-specific fields. Supported variants today:

- `header:present` – `{ "type": "header:present", "target": "Server" }`
- `header:absent` – target header missing.
- `header:eq` – additional `expected` string and optional `case_sensitive` boolean.
- `hash:eq` – `algorithm` (`sha256`, `blake3`) plus `digest` hex string.
- `regex` – `pattern`, optional `scope` (`headers`, `body`, `any`), optional `case_sensitive` flag.

The schema enforces these discriminators so future CLI code can rely on serde to catch malformed statements.

## Commitments
`commitments.handshake` and `commitments.app_data` wrap base64 strings. Validation enforces correct encoding but stays agnostic to the commitment scheme (BLAKE3, SHA-256, etc.). Optional `witness` allows bundling auxiliary commitments (e.g., timestamp proofs).

## Metadata
`meta.tool_version` binds artifacts to prover release lines. `meta.annotations` is an open key/value map for future extension (e.g., policy identifiers, operator IDs). Empty maps are dropped during serialization to keep artifacts minimal.

## Validation Rules
Implemented in `redproof-artifact`:
- Domain must be non-empty.
- At least one certificate fingerprint required.
- Every base64 field (commitments + proof) must decode successfully.
- TLS context validated before verification logic runs.

Failure to meet these preconditions should cause the verifier CLI to reject artifacts before verifying ZK proofs.
