use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Parser;
use redproof_artifact::RedProofArtifact;

#[derive(Parser, Debug)]
#[command(
    name = "redproof-verify",
    about = "Verify RedProof artifacts (JSON/CBOR placeholder)."
)]
struct Cli {
    /// Path to the .red artifact
    artifact: PathBuf,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let data = fs::read_to_string(&cli.artifact)
        .with_context(|| format!("unable to read artifact {:?}", cli.artifact))?;
    let artifact: RedProofArtifact = serde_json::from_str(&data)
        .with_context(|| format!("malformed artifact {:?}", cli.artifact))?;
    artifact.validate()?;
    println!(
        "VALID - domain={} statement={}",
        artifact.domain,
        artifact.statement.summary()
    );
    Ok(())
}
