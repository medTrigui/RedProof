use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(tag = "type")]
#[non_exhaustive]
pub enum Statement {
    #[serde(rename = "header:present")]
    HeaderPresent { target: String },
    #[serde(rename = "header:absent")]
    HeaderAbsent { target: String },
    #[serde(rename = "header:eq")]
    HeaderEquals {
        target: String,
        expected: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        case_sensitive: Option<bool>,
    },
    #[serde(rename = "hash:eq")]
    HashEquals {
        algorithm: HashAlgorithm,
        digest: String,
    },
    #[serde(rename = "regex")]
    Regex {
        pattern: String,
        #[serde(default)]
        scope: RegexScope,
        #[serde(default)]
        case_sensitive: bool,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum HashAlgorithm {
    Sha256,
    Blake3,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum RegexScope {
    Headers,
    Body,
    #[default]
    Any,
}

impl Statement {
    pub fn summary(&self) -> String {
        match self {
            Statement::HeaderPresent { target } => format!("header present: {}", target),
            Statement::HeaderAbsent { target } => format!("header absent: {}", target),
            Statement::HeaderEquals {
                target, expected, ..
            } => format!("header {} equals {}", target, expected),
            Statement::HashEquals { algorithm, .. } => {
                format!("hash equals via {:?}", algorithm)
            }
            Statement::Regex { pattern, scope, .. } => {
                format!("regex {:?}: {}", scope, pattern)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serde_round_trip() {
        let statement = Statement::HeaderAbsent {
            target: "Strict-Transport-Security".into(),
        };
        let json = serde_json::to_string(&statement).expect("serialize");
        let back: Statement = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(statement, back);
    }
}
