mod capture;
mod commit;
mod evaluate;

use std::fs;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use chrono::{DateTime, Utc};
use clap::{Parser, ValueEnum};
use redproof_artifact::{
    ArtifactMeta, CommitmentAlgorithm, CommitmentSet, EncodedBlob, RedProofArtifact,
    TlsProofContext,
};
use redproof_statements::{parse_statement, Statement};
use serde::Serialize;
use serde_json::{json, Map, Value};
use url::Url;

use crate::capture::{capture, CaptureOptions, CaptureRecord};
use crate::commit::build_commitments;
use crate::evaluate::{evaluate, StatementEvaluation};

#[derive(Parser, Debug)]
#[command(
    name = "redproof-prover",
    about = "Capture HTTPS responses and emit RedProof artifacts."
)]
struct Cli {
    #[arg(long)]
    url: String,

    #[arg(long)]
    prove: String,

    #[arg(long, default_value = "proof.red")]
    out: PathBuf,

    #[arg(long, default_value_t = MethodArg::Get)]
    method: MethodArg,

    #[arg(long, default_value_t = HashAlgArg::Blake3)]
    hash_alg: HashAlgArg,

    #[arg(long, default_value_t = ArtifactFormat::Json)]
    format: ArtifactFormat,

    #[arg(long, default_value_t = 256)]
    max_body_kb: usize,

    #[arg(long)]
    timeout_secs: Option<u64>,

    #[arg(long)]
    dry_run: bool,
}

#[derive(Copy, Clone, Debug, ValueEnum)]
enum MethodArg {
    Get,
    Head,
}

impl MethodArg {
    fn to_http(self) -> http::Method {
        match self {
            MethodArg::Get => http::Method::GET,
            MethodArg::Head => http::Method::HEAD,
        }
    }
}

#[derive(Copy, Clone, Debug, ValueEnum)]
enum HashAlgArg {
    Blake3,
    Sha256,
}

impl From<HashAlgArg> for CommitmentAlgorithm {
    fn from(value: HashAlgArg) -> Self {
        match value {
            HashAlgArg::Blake3 => CommitmentAlgorithm::Blake3,
            HashAlgArg::Sha256 => CommitmentAlgorithm::Sha256,
        }
    }
}

#[derive(Copy, Clone, Debug, ValueEnum)]
enum ArtifactFormat {
    Json,
    Cbor,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let url = Url::parse(&cli.url).context("invalid URL")?;
    let statement = parse_statement(&cli.prove).context("invalid statement expression")?;
    let method = cli.method.to_http();
    let max_body_bytes = cli
        .max_body_kb
        .checked_mul(1024)
        .ok_or_else(|| anyhow!("max-body-kb overflow"))?;
    let timeout = cli.timeout_secs.map(Duration::from_secs);

    let capture = capture(&CaptureOptions {
        url,
        method,
        max_body_bytes,
        timeout,
    })?;
    let evaluation = evaluate(&statement, &capture);

    if cli.dry_run {
        let preview = CapturePreview::new(&capture, &statement, &evaluation, &cli.prove);
        println!("{}", serde_json::to_string_pretty(&preview)?);
        return Ok(());
    }

    let commitments = build_commitments(&capture.transcript(), cli.hash_alg.into(), true);
    let artifact = build_artifact(&capture, &statement, commitments)?;
    write_artifact(&artifact, cli.format, &cli.out)?;
    println!(
        "[ok] {} {} -> {} (statement={})",
        capture.method.as_str(),
        capture.requested_url,
        cli.out.display(),
        evaluation.satisfied
    );
    Ok(())
}

fn build_artifact(
    capture: &CaptureRecord,
    statement: &Statement,
    commitments: CommitmentSet,
) -> Result<RedProofArtifact> {
    let tls = TlsProofContext {
        version: capture.tls.version.clone(),
        cipher: capture.tls.cipher.clone(),
        cert_fingerprints: capture.tls.cert_fingerprints.clone(),
        alpn: capture.tls.alpn.clone(),
    };

    let mut annotations = Map::new();
    annotations.insert(
        "request_method".into(),
        Value::String(capture.method.as_str().to_string()),
    );
    annotations.insert("status_code".into(), json!(capture.response.status_code));
    annotations.insert(
        "body_truncated".into(),
        Value::Bool(capture.response.body_truncated),
    );
    annotations.insert(
        "http_version".into(),
        Value::String(capture.response.http_version.clone()),
    );

    Ok(RedProofArtifact {
        version: "1.0".into(),
        domain: capture.domain.clone(),
        time_utc: capture.captured_at,
        tls,
        statement: statement.clone(),
        commitments,
        proof: EncodedBlob::from_bytes(b"phase2-naive-proof"),
        meta: ArtifactMeta {
            tool_version: env!("CARGO_PKG_VERSION").into(),
            annotations,
        },
    })
}

fn write_artifact(
    artifact: &RedProofArtifact,
    format: ArtifactFormat,
    path: &PathBuf,
) -> Result<()> {
    let bytes = match format {
        ArtifactFormat::Json => serde_json::to_vec_pretty(artifact)?,
        ArtifactFormat::Cbor => serde_cbor::to_vec(artifact)?,
    };
    fs::write(path, bytes).with_context(|| format!("failed to write {}", path.display()))
}

#[derive(Serialize)]
struct CapturePreview<'a> {
    request: RequestPreview<'a>,
    tls: &'a capture::TlsMetadata,
    response: ResponsePreview<'a>,
    statement: StatementPreview<'a>,
}

#[derive(Serialize)]
struct RequestPreview<'a> {
    method: &'a str,
    url: &'a Url,
    captured_at: DateTime<Utc>,
}

#[derive(Serialize)]
struct ResponsePreview<'a> {
    status_code: u16,
    reason: &'a str,
    headers: &'a [capture::HeaderEntry],
    body_base64: String,
    body_truncated: bool,
}

#[derive(Serialize)]
struct StatementPreview<'a> {
    expression: &'a str,
    summary: String,
    parsed: &'a Statement,
    evaluation: &'a StatementEvaluation,
}

impl<'a> CapturePreview<'a> {
    fn new(
        capture: &'a CaptureRecord,
        statement: &'a Statement,
        evaluation: &'a StatementEvaluation,
        expression: &'a str,
    ) -> Self {
        Self {
            request: RequestPreview {
                method: capture.method.as_str(),
                url: &capture.requested_url,
                captured_at: capture.captured_at,
            },
            tls: &capture.tls,
            response: ResponsePreview {
                status_code: capture.response.status_code,
                reason: &capture.response.reason,
                headers: &capture.response.headers,
                body_base64: B64.encode(&capture.response.body),
                body_truncated: capture.response.body_truncated,
            },
            statement: StatementPreview {
                expression,
                summary: statement.summary(),
                parsed: statement,
                evaluation,
            },
        }
    }
}
impl std::fmt::Display for MethodArg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            MethodArg::Get => "get",
            MethodArg::Head => "head",
        })
    }
}

impl std::fmt::Display for HashAlgArg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            HashAlgArg::Blake3 => "blake3",
            HashAlgArg::Sha256 => "sha256",
        })
    }
}

impl std::fmt::Display for ArtifactFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            ArtifactFormat::Json => "json",
            ArtifactFormat::Cbor => "cbor",
        })
    }
}
