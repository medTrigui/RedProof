use anyhow::Result;
use clap::Parser;

#[derive(Parser, Debug)]
#[command(
    name = "redproof-prover",
    about = "Capture HTTPS responses and emit RedProof artifacts."
)]
struct Cli {
    /// Target URL to probe (GET/HEAD only in Phase 0).
    #[arg(long)]
    url: String,

    /// Statement expression, e.g., header:absent:Strict-Transport-Security
    #[arg(long)]
    prove: String,

    /// Output artifact path (.red)
    #[arg(long, default_value = "proof.red")]
    out: String,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    println!(
        "[dry-run] redproof prover would connect to {} and assert {} -> {}",
        cli.url, cli.prove, cli.out
    );
    Ok(())
}
