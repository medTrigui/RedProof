use std::collections::BTreeMap;

use redproof_statements::{HashAlgorithm, RegexScope, Statement};
use regex::RegexBuilder;
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::capture::{CaptureRecord, HeaderEntry, HttpResponse};

pub type HeaderMap = BTreeMap<String, Vec<String>>;

#[derive(Debug, Serialize)]
pub struct StatementEvaluation {
    pub satisfied: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<String>,
}

pub fn evaluate(statement: &Statement, record: &CaptureRecord) -> StatementEvaluation {
    match statement {
        Statement::HeaderPresent { target } => {
            let key = target.to_ascii_lowercase();
            StatementEvaluation {
                satisfied: record.headers.contains_key(&key),
                details: None,
            }
        }
        Statement::HeaderAbsent { target } => {
            let key = target.to_ascii_lowercase();
            StatementEvaluation {
                satisfied: !record.headers.contains_key(&key),
                details: None,
            }
        }
        Statement::HeaderEquals {
            target,
            expected,
            case_sensitive,
        } => {
            let key = target.to_ascii_lowercase();
            let values = record.headers.get(&key);
            let satisfied = values.map_or(false, |vals| {
                vals.iter()
                    .any(|val| compare_value(val, expected, *case_sensitive))
            });
            StatementEvaluation {
                satisfied,
                details: None,
            }
        }
        Statement::HashEquals { algorithm, digest } => {
            if record.response.body_truncated {
                return StatementEvaluation {
                    satisfied: false,
                    details: Some("response body truncated; hash unverifiable".into()),
                };
            }
            let local = compute_hash(algorithm, &record.response.body);
            StatementEvaluation {
                satisfied: local.eq_ignore_ascii_case(digest),
                details: Some(format!("calculated={local}")),
            }
        }
        Statement::Regex {
            pattern,
            scope,
            case_sensitive,
        } => match build_regex(pattern, *case_sensitive) {
            Ok(re) => {
                let haystack = regex_scope_text(scope, &record.response);
                StatementEvaluation {
                    satisfied: re.is_match(&haystack),
                    details: None,
                }
            }
            Err(err) => StatementEvaluation {
                satisfied: false,
                details: Some(err),
            },
        },
        _ => StatementEvaluation {
            satisfied: false,
            details: Some("statement variant not yet supported".into()),
        },
    }
}

fn compare_value(actual: &str, expected: &str, case_sensitive: Option<bool>) -> bool {
    if case_sensitive.unwrap_or(false) {
        actual.trim() == expected.trim()
    } else {
        actual.trim().eq_ignore_ascii_case(expected.trim())
    }
}

fn compute_hash(algo: &HashAlgorithm, data: &[u8]) -> String {
    match algo {
        HashAlgorithm::Sha256 => {
            let digest = Sha256::digest(data);
            hex_string(digest.as_slice())
        }
        HashAlgorithm::Blake3 => {
            let digest = blake3::hash(data);
            hex_string(digest.as_bytes())
        }
    }
}

fn hex_string(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn build_regex(pattern: &str, case_sensitive: bool) -> Result<regex::Regex, String> {
    RegexBuilder::new(pattern)
        .case_insensitive(!case_sensitive)
        .build()
        .map_err(|err| format!("invalid regex: {err}"))
}

fn regex_scope_text(scope: &RegexScope, response: &HttpResponse) -> String {
    match scope {
        RegexScope::Headers => headers_as_text(&response.headers),
        RegexScope::Body => body_as_text(&response.body),
        RegexScope::Any => format!(
            "{}\n\n{}",
            headers_as_text(&response.headers),
            body_as_text(&response.body)
        ),
    }
}

fn headers_as_text(headers: &[HeaderEntry]) -> String {
    headers
        .iter()
        .map(|h| format!("{}: {}", h.name, h.value))
        .collect::<Vec<_>>()
        .join("\n")
}

fn body_as_text(body: &[u8]) -> String {
    String::from_utf8_lossy(body).to_string()
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::capture::{CaptureRecord, HeaderEntry, HttpResponse, TlsMetadata};
    use chrono::Utc;
    use http::Method;
    use url::Url;

    fn base_record() -> CaptureRecord {
        CaptureRecord {
            requested_url: Url::parse("https://example.com").unwrap(),
            domain: "example.com".into(),
            method: Method::GET,
            captured_at: Utc::now(),
            tls: TlsMetadata {
                version: String::new(),
                cipher: String::new(),
                cert_fingerprints: vec![],
                alpn: None,
            },
            response: HttpResponse {
                http_version: "HTTP/1.1".into(),
                status_code: 200,
                reason: "OK".into(),
                headers: vec![],
                body: b"body".to_vec(),
                body_truncated: false,
            },
            canonical_handshake: vec![],
            canonical_app_data: vec![],
            headers: HeaderMap::new(),
        }
    }

    #[test]
    fn header_present_and_absent_evaluate_correctly() {
        let mut record = base_record();
        record
            .headers
            .entry("server".into())
            .or_default()
            .push("Example".into());

        let present = Statement::HeaderPresent {
            target: "Server".into(),
        };
        assert!(evaluate(&present, &record).satisfied);

        let absent = Statement::HeaderAbsent {
            target: "Strict-Transport-Security".into(),
        };
        assert!(evaluate(&absent, &record).satisfied);
    }

    #[test]
    fn header_equals_respects_case_insensitive_compare() {
        let mut record = base_record();
        record
            .headers
            .entry("server".into())
            .or_default()
            .push("Apache".into());
        let stmt = Statement::HeaderEquals {
            target: "Server".into(),
            expected: "apache".into(),
            case_sensitive: None,
        };
        assert!(evaluate(&stmt, &record).satisfied);
    }

    #[test]
    fn hash_equals_fails_when_truncated() {
        let mut record = base_record();
        record.response.body_truncated = true;
        let stmt = Statement::HashEquals {
            algorithm: HashAlgorithm::Sha256,
            digest: "deadbeef".into(),
        };
        let eval = evaluate(&stmt, &record);
        assert!(!eval.satisfied);
        assert!(eval.details.unwrap().contains("truncated"));
    }

    #[test]
    fn regex_scope_headers_matches() {
        let mut record = base_record();
        record.response.headers = vec![HeaderEntry {
            name: "set-cookie".into(),
            value: "session=abc; HttpOnly".into(),
        }];
        let stmt = Statement::Regex {
            pattern: "session=.*".into(),
            scope: RegexScope::Headers,
            case_sensitive: false,
        };
        assert!(evaluate(&stmt, &record).satisfied);
    }
}
