use std::str::FromStr;

use thiserror::Error;

use crate::{HashAlgorithm, RegexScope, Statement};

/// Parse a CLI-friendly statement expression into a strongly typed [`Statement`].
pub fn parse_statement(input: &str) -> Result<Statement, StatementParseError> {
    let mut parts = tokenize(input)?;
    if parts.is_empty() {
        return Err(StatementParseError::EmptyExpression);
    }
    let kind = parts.remove(0).to_ascii_lowercase();
    match kind.as_str() {
        "header" => parse_header(parts),
        "hash" => parse_hash(parts),
        "regex" => parse_regex(parts),
        _ => Err(StatementParseError::UnknownKind(kind)),
    }
}

fn parse_header(parts: Vec<String>) -> Result<Statement, StatementParseError> {
    if parts.is_empty() {
        return Err(StatementParseError::MissingValue("header action"));
    }
    let action = parts[0].to_ascii_lowercase();
    match action.as_str() {
        "present" => {
            if parts.len() != 2 {
                return Err(StatementParseError::ExpectedFormat(
                    "header:present:<header-name>",
                ));
            }
            Ok(Statement::HeaderPresent {
                target: require_value(&parts[1], "header name")?,
            })
        }
        "absent" => {
            if parts.len() != 2 {
                return Err(StatementParseError::ExpectedFormat(
                    "header:absent:<header-name>",
                ));
            }
            Ok(Statement::HeaderAbsent {
                target: require_value(&parts[1], "header name")?,
            })
        }
        "eq" => {
            if parts.len() != 3 {
                return Err(StatementParseError::ExpectedFormat(
                    "header:eq:<header-name>:<expected-value>",
                ));
            }
            Ok(Statement::HeaderEquals {
                target: require_value(&parts[1], "header name")?,
                expected: require_value(&parts[2], "expected header value")?,
                case_sensitive: None,
            })
        }
        other => Err(StatementParseError::UnknownHeaderAction(other.to_string())),
    }
}

fn parse_hash(parts: Vec<String>) -> Result<Statement, StatementParseError> {
    if parts.len() != 3 {
        return Err(StatementParseError::ExpectedFormat(
            "hash:eq:<algorithm>:<digest>",
        ));
    }
    if !parts[0].eq_ignore_ascii_case("eq") {
        return Err(StatementParseError::UnsupportedHashOperation(
            parts[0].clone(),
        ));
    }
    let algorithm = HashAlgorithm::from_str(&parts[1])
        .map_err(|_| StatementParseError::UnsupportedHashAlgorithm(parts[1].clone()))?;
    Ok(Statement::HashEquals {
        algorithm,
        digest: require_value(&parts[2], "digest")?,
    })
}

fn parse_regex(parts: Vec<String>) -> Result<Statement, StatementParseError> {
    if parts.is_empty() {
        return Err(StatementParseError::MissingValue("regex pattern"));
    }
    let mut scope = RegexScope::Any;
    let mut case_sensitive = false;

    let mut idx = 0;
    while idx < parts.len() - 1 {
        let token = parts[idx].as_str();
        if let Some(value) = token.strip_prefix("scope=") {
            scope = parse_scope(value)?;
            idx += 1;
            continue;
        }
        if let Some(value) = token.strip_prefix("case_sensitive=") {
            case_sensitive = parse_bool(value)?;
            idx += 1;
            continue;
        }
        if matches_scope_name(token) {
            scope = parse_scope(token)?;
            idx += 1;
            continue;
        }
        break;
    }

    let pattern = parts[idx].clone();
    if pattern.is_empty() {
        return Err(StatementParseError::MissingValue("regex pattern"));
    }

    if idx != parts.len() - 1 {
        return Err(StatementParseError::UnexpectedSegments(
            "regex:<pattern> (optional leading scope/case parameters)",
        ));
    }

    Ok(Statement::Regex {
        pattern,
        scope,
        case_sensitive,
    })
}

fn require_value(value: &str, label: &'static str) -> Result<String, StatementParseError> {
    if value.trim().is_empty() {
        Err(StatementParseError::MissingValue(label))
    } else {
        Ok(value.to_string())
    }
}

fn parse_scope(value: &str) -> Result<RegexScope, StatementParseError> {
    match value.to_ascii_lowercase().as_str() {
        "headers" => Ok(RegexScope::Headers),
        "body" => Ok(RegexScope::Body),
        "any" => Ok(RegexScope::Any),
        other => Err(StatementParseError::InvalidScope(other.to_string())),
    }
}

fn parse_bool(value: &str) -> Result<bool, StatementParseError> {
    match value.to_ascii_lowercase().as_str() {
        "true" | "1" | "yes" => Ok(true),
        "false" | "0" | "no" => Ok(false),
        other => Err(StatementParseError::InvalidBoolean(other.to_string())),
    }
}

fn matches_scope_name(token: &str) -> bool {
    matches!(
        token.to_ascii_lowercase().as_str(),
        "headers" | "body" | "any"
    )
}

fn tokenize(input: &str) -> Result<Vec<String>, StatementParseError> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Ok(Vec::new());
    }
    let mut fields = Vec::new();
    let mut buf = String::new();
    let mut in_quotes = false;
    let mut escaping = false;

    for ch in trimmed.chars() {
        if escaping {
            buf.push(ch);
            escaping = false;
            continue;
        }
        match ch {
            '\\' if in_quotes => {
                escaping = true;
            }
            '"' => {
                in_quotes = !in_quotes;
            }
            ':' if !in_quotes => {
                fields.push(buf.trim().to_string());
                buf.clear();
            }
            _ => buf.push(ch),
        }
    }

    if in_quotes {
        return Err(StatementParseError::UnbalancedQuotes);
    }
    if escaping {
        return Err(StatementParseError::DanglingEscape);
    }
    fields.push(buf.trim().to_string());
    if fields.iter().any(|field| field.is_empty()) {
        Err(StatementParseError::EmptyToken)
    } else {
        Ok(fields)
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum StatementParseError {
    #[error("statement expression is empty")]
    EmptyExpression,
    #[error("statement contains an empty segment")]
    EmptyToken,
    #[error("unbalanced quotes in statement")]
    UnbalancedQuotes,
    #[error("dangling escape sequence in statement")]
    DanglingEscape,
    #[error("unknown statement kind '{0}'")]
    UnknownKind(String),
    #[error("unknown header action '{0}'")]
    UnknownHeaderAction(String),
    #[error("missing {0}")]
    MissingValue(&'static str),
    #[error("unsupported hash operation '{0}'")]
    UnsupportedHashOperation(String),
    #[error("unsupported hash algorithm '{0}'")]
    UnsupportedHashAlgorithm(String),
    #[error("invalid regex scope '{0}'")]
    InvalidScope(String),
    #[error("invalid boolean value '{0}'")]
    InvalidBoolean(String),
    #[error("expected format: {0}")]
    ExpectedFormat(&'static str),
    #[error("unexpected extra segments; expected format: {0}")]
    UnexpectedSegments(&'static str),
}

impl FromStr for HashAlgorithm {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "sha256" => Ok(HashAlgorithm::Sha256),
            "blake3" => Ok(HashAlgorithm::Blake3),
            _ => Err(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_header_absent() {
        let stmt = parse_statement("header:absent:Strict-Transport-Security").unwrap();
        assert_eq!(
            stmt,
            Statement::HeaderAbsent {
                target: "Strict-Transport-Security".into()
            }
        );
    }

    #[test]
    fn parses_header_eq_with_quotes() {
        let stmt = parse_statement(r#"header:eq:Server:"Apache/2.4.49 (Unix)""#).expect("parsed");
        assert_eq!(
            stmt,
            Statement::HeaderEquals {
                target: "Server".into(),
                expected: "Apache/2.4.49 (Unix)".into(),
                case_sensitive: None
            }
        );
    }

    #[test]
    fn parses_hash_eq() {
        let stmt = parse_statement("hash:eq:sha256:deadbeef").expect("parsed hash statement");
        assert_eq!(
            stmt,
            Statement::HashEquals {
                algorithm: HashAlgorithm::Sha256,
                digest: "deadbeef".into()
            }
        );
    }

    #[test]
    fn parses_regex_with_scope_and_case() {
        let stmt =
            parse_statement("regex:scope=headers:case_sensitive=true:\"Set-Cookie: session=.*\"")
                .expect("parsed regex");
        assert_eq!(
            stmt,
            Statement::Regex {
                pattern: "Set-Cookie: session=.*".into(),
                scope: RegexScope::Headers,
                case_sensitive: true
            }
        );
    }

    #[test]
    fn errors_on_unbalanced_quotes() {
        let err = parse_statement(r#"header:absent:"Strict"#).unwrap_err();
        assert!(matches!(err, StatementParseError::UnbalancedQuotes));
    }

    #[test]
    fn errors_on_unknown_kind() {
        let err = parse_statement("foo:bar").unwrap_err();
        assert!(matches!(err, StatementParseError::UnknownKind(kind) if kind == "foo"));
    }
}
