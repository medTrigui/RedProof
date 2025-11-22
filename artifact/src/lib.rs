use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use chrono::{DateTime, Utc};
use redproof_statements::Statement;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use thiserror::Error;

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq)]
pub struct RedProofArtifact {
    pub version: String,
    pub domain: String,
    pub time_utc: DateTime<Utc>,
    pub tls: TlsProofContext,
    pub statement: Statement,
    pub commitments: CommitmentSet,
    pub proof: EncodedBlob,
    #[serde(default)]
    pub meta: ArtifactMeta,
}

impl RedProofArtifact {
    pub fn validate(&self) -> Result<(), ArtifactValidationError> {
        if self.domain.trim().is_empty() {
            return Err(ArtifactValidationError::MissingDomain);
        }
        self.tls.validate()?;
        self.commitments.validate()?;
        self.proof.ensure_base64("proof")?;
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq)]
pub struct TlsProofContext {
    pub version: String,
    pub cipher: String,
    pub cert_fingerprints: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alpn: Option<String>,
}

impl TlsProofContext {
    pub fn validate(&self) -> Result<(), ArtifactValidationError> {
        if self.cert_fingerprints.is_empty() {
            return Err(ArtifactValidationError::MissingCertFingerprint);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq)]
pub struct CommitmentSet {
    pub algorithm: CommitmentAlgorithm,
    pub handshake: EncodedBlob,
    pub app_data: EncodedBlob,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub witness: Option<CommitmentWitness>,
}

impl CommitmentSet {
    pub fn validate(&self) -> Result<(), ArtifactValidationError> {
        self.handshake.ensure_base64("handshake commitment")?;
        self.app_data.ensure_base64("application-data commitment")?;
        if let Some(witness) = &self.witness {
            witness.handshake.ensure_base64("handshake witness")?;
            witness.app_data.ensure_base64("app-data witness")?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum CommitmentAlgorithm {
    Blake3,
    Sha256,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
pub struct CommitmentWitness {
    pub handshake: EncodedBlob,
    pub app_data: EncodedBlob,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
pub struct ArtifactMeta {
    pub tool_version: String,
    #[serde(default, skip_serializing_if = "Map::is_empty")]
    pub annotations: Map<String, Value>,
}

impl Default for ArtifactMeta {
    fn default() -> Self {
        Self {
            tool_version: "0.0.0".to_string(),
            annotations: Map::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
pub struct EncodedBlob(pub String);

impl EncodedBlob {
    fn ensure_base64(&self, field: &str) -> Result<(), ArtifactValidationError> {
        STANDARD
            .decode(self.0.as_bytes())
            .map(|_| ())
            .map_err(|_| ArtifactValidationError::InvalidBase64(field.to_string()))
    }

    pub fn decode(&self) -> Result<Vec<u8>, ArtifactValidationError> {
        STANDARD
            .decode(self.0.as_bytes())
            .map_err(|_| ArtifactValidationError::InvalidBase64("encoded blob".into()))
    }

    pub fn from_bytes(bytes: &[u8]) -> Self {
        EncodedBlob(STANDARD.encode(bytes))
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ArtifactValidationError {
    #[error("artifact is missing domain")]
    MissingDomain,
    #[error("no certificate fingerprints captured")]
    MissingCertFingerprint,
    #[error("{0} is not valid base64 data")]
    InvalidBase64(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encoded(data: &str) -> EncodedBlob {
        EncodedBlob(STANDARD.encode(data))
    }

    fn sample_artifact() -> RedProofArtifact {
        let statement = Statement::HeaderAbsent {
            target: "Strict-Transport-Security".into(),
        };
        RedProofArtifact {
            version: "1.0".into(),
            domain: "example.com".into(),
            time_utc: Utc::now(),
            tls: TlsProofContext {
                version: "TLS1.3".into(),
                cipher: "TLS_AES_128_GCM_SHA256".into(),
                cert_fingerprints: vec!["sha256:deadbeef".into()],
                alpn: Some("h2".into()),
            },
            statement,
            commitments: CommitmentSet {
                algorithm: CommitmentAlgorithm::Blake3,
                handshake: encoded("handshake"),
                app_data: encoded("app"),
                witness: None,
            },
            proof: encoded("proof"),
            meta: ArtifactMeta {
                tool_version: "0.1.0".into(),
                annotations: Map::new(),
            },
        }
    }

    #[test]
    fn validates_sample() {
        let artifact = sample_artifact();
        artifact.validate().expect("valid artifact");
    }

    #[test]
    fn schema_generation() {
        let schema = schemars::schema_for!(RedProofArtifact);
        assert!(schema.schema.object.is_some());
    }
}
