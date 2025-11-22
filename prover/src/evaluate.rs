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
