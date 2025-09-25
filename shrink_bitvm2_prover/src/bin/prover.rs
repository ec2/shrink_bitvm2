use anyhow::{Context, Result};
use borsh::BorshDeserialize;
use clap::Parser;
use risc0_zkvm::{ReceiptClaim, SuccinctReceipt};
use shrink_bitvm2_prover::shrink_wrap;
use std::{fs, path::PathBuf};

#[derive(Parser)]
#[command(name = "prover")]
#[command(about = "A CLI tool to call shrink and write proofs")]
struct Args {
    #[arg(help = "Path to the input succinct receipt file")]
    input: PathBuf,

    #[arg(help = "Path to the output proof file")]
    output: PathBuf,

    #[arg(help = "Journal data in hex format")]
    journal: String,
}

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    let args = Args::parse();

    if let Err(e) = run(args) {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}

fn run(args: Args) -> Result<()> {
    tracing::info!("Starting prover...");
    let journal = hex::decode(&args.journal)
        .with_context(|| format!("Failed to decode journal hex: {}", args.journal))?;

    if journal.len() != 32 {
        return Err(anyhow::anyhow!(
            "Journal must be 32 bytes, got {} bytes",
            journal.len()
        ));
    }
    let p254_receipt_bytes = fs::read(&args.input)
        .with_context(|| format!("Failed to read input file: {:?}", args.input))?;

    let p254_receipt = SuccinctReceipt::<ReceiptClaim>::try_from_slice(&p254_receipt_bytes)
        .with_context(|| format!("Failed to parse JSON from input file: {:?}", args.input))?;

    let proof_json = shrink_wrap(&p254_receipt, &journal)?;
    fs::write(&args.output, serde_json::to_string_pretty(&proof_json)?)?;

    Ok(())
}
