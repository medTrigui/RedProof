use std::fs;
use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use clap::{Parser, ValueEnum};
use redproof_artifact::{CommitmentAlgorithm, EncodedBlob, RedProofArtifact};
use sha2::{Digest, Sha256};

#[derive(Parser, Debug)]
#[command(
    name = "redproof-verify",
    about = "Verify RedProof artifacts (JSON or CBOR)."
)]
struct Cli {
    /// Path to the artifact file (.red)
    artifact: PathBuf,

    #[arg(long, default_value_t = InputFormat::Auto)]
    format: InputFormat,
}

#[derive(Copy, Clone, Debug, ValueEnum)]
enum InputFormat {
    Auto,
    Json,
    Cbor,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let data = fs::read(&cli.artifact)
        .with_context(|| format!("failed to read {}", cli.artifact.display()))?;
    let artifact = load_artifact(&data, cli.format)?;
    match verify_artifact(&artifact) {
        Ok(()) => {
            println!("VALID");
            println!("Domain: {}", artifact.domain);
            println!("Statement: {}", artifact.statement.summary());
            println!(
                "Commitments: {:?} (witness={})",
                artifact.commitments.algorithm,
                artifact.commitments.witness.is_some()
            );
        }
        Err(err) => {
            println!("INVALID: {err}");
        }
    }
    Ok(())
}

fn load_artifact(data: &[u8], format: InputFormat) -> Result<RedProofArtifact> {
    match format {
        InputFormat::Json => Ok(serde_json::from_slice(data)?),
        InputFormat::Cbor => Ok(serde_cbor::from_slice(data)?),
        InputFormat::Auto => serde_json::from_slice(data)
            .or_else(|_| serde_cbor::from_slice(data))
            .context("unable to parse artifact as JSON or CBOR"),
    }
}

fn verify_artifact(artifact: &RedProofArtifact) -> Result<()> {
    artifact.validate()?;
    if let Some(witness) = &artifact.commitments.witness {
        let handshake = witness.handshake.decode()?;
        let app_data = witness.app_data.decode()?;
        ensure_digest(
            &artifact.commitments.algorithm,
            &handshake,
            &artifact.commitments.handshake,
            "handshake",
        )?;
        ensure_digest(
            &artifact.commitments.algorithm,
            &app_data,
            &artifact.commitments.app_data,
            "app-data",
        )?;
    } else {
        println!("warning: no witness included; commitment verification skipped");
    }
    Ok(())
}

fn ensure_digest(
    algorithm: &CommitmentAlgorithm,
    data: &[u8],
    expected: &EncodedBlob,
    label: &str,
) -> Result<()> {
    let actual = hash_bytes(algorithm, data);
    if actual.0 != expected.0 {
        bail!("{label} digest mismatch");
    }
    Ok(())
}

fn hash_bytes(algo: &CommitmentAlgorithm, data: &[u8]) -> EncodedBlob {
    match algo {
        CommitmentAlgorithm::Blake3 => {
            let digest = blake3::hash(data);
            EncodedBlob::from_bytes(digest.as_bytes())
        }
        CommitmentAlgorithm::Sha256 => {
            let digest = Sha256::digest(data);
            EncodedBlob::from_bytes(&digest)
        }
    }
}
impl std::fmt::Display for InputFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            InputFormat::Auto => "auto",
            InputFormat::Json => "json",
            InputFormat::Cbor => "cbor",
        })
    }
}
