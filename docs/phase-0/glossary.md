# Phase 0 – Glossary

| Term | Definition |
| --- | --- |
| Artifact (`.red`) | Portable file containing metadata, TLS commitments, and selective proofs. |
| Commitment | Binding + hiding cryptographic digest of TLS bytes (BLAKE3/SHA-256). |
| Statement | Structured claim about the response (header, hash, regex). Serialized via `redproof-statements`. |
| Prover | CLI tool operated by red/pentest teams to capture HTTPS responses. |
| Verifier | CLI/lib used by blue teams to validate artifacts offline. |
| Selective Disclosure | Revealing only the truth value of a property, not the underlying data. |
| ZK Circuit | Optional zero-knowledge proof that attests to header equality / regex matches without exposing bytes. |
| TLS Context | Version, cipher, ALPN, and certificate fingerprints captured during the session. |
| Metadata | Operational fields (tool version, annotations) that help with chain-of-custody. |
| Policy Pack | Predefined statement bundle (e.g., "OWASP A05") planned for future usability improvements. |
