use std::{fs, path::Path};

use anyhow::{Context, Result, bail};
use hex::FromHex;
use risc0_groth16::{ProofJson as Groth16ProofJson, Seal as Groth16Seal};
use risc0_zkvm::{
    Digest, Groth16Receipt, MaybePruned, Receipt, ReceiptClaim, SuccinctReceipt, digest,
};
use std::process::{Command, Stdio};
mod receipt_claim;
pub use receipt_claim::*;

pub const BN254_IDENTITY_CONTROL_ID: Digest =
    digest!("c07a65145c3cb48b6101962ea607a4dd93c753bb26975cb47feb00d3666e4404");

#[cfg(feature = "prove")]
pub fn succinct_to_bitvm2(
    succinct_receipt: &SuccinctReceipt<ReceiptClaim>,
    journal: &[u8],
) -> Result<Receipt> {
    let p254_receipt: SuccinctReceipt<ReceiptClaim> =
        risc0_zkvm::recursion::identity_p254(succinct_receipt).unwrap();
    let receipt_claim = p254_receipt.claim.clone();
    let seal = shrink_wrap_gpu(&p254_receipt, journal)?;
    finalize(journal.to_vec(), receipt_claim, &seal.try_into()?)
}

pub fn shrink_wrap_gpu(
    p254_receipt: &SuccinctReceipt<ReceiptClaim>,
    journal: &[u8],
) -> Result<Groth16ProofJson> {
    tracing::info!("shrink_wrap_gpu!!!");
    if !is_docker_installed() {
        bail!("Please install docker first.")
    }

    let tmp_dir = tempfile::tempdir().context("failed to create temporary directory")?;
    let work_dir = std::env::var("SHRINK_BVM2_WORK_DIR");
    let work_dir = work_dir.as_ref().map(Path::new).unwrap_or(tmp_dir.path());

    let input_path = work_dir.join("identity_p256.r0");
    let proof_path = work_dir.join("proof.json");

    let identity_receipt_bytes = borsh::to_vec(p254_receipt)?;
    fs::write(&input_path, identity_receipt_bytes)?;

    let volume = format!("{}:/mnt", work_dir.display());
    println!("Journal: {:?}", hex::encode(journal));
    let mut command = Command::new("docker");
    command
        .args([
            "run",
            "--rm",
            "-e",
            "RUST_LOG=info",
            "-e",
            "RUST_BACKTRACE=1",
            "-v",
            &volume,
            "gpu-prover:latest",
            "/mnt/identity_p256.r0",
            "/mnt/proof.json",
            hex::encode(journal).as_str(),
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    println!("Running command: {:?}", command);
    let output = command.output()?;
    println!("Output: {:?}", output);

    anyhow::ensure!(
        output.status.success(),
        "gpu-g16-bvm2:latest failed: {:?}",
        output.status.code()
    );

    let proof_content = std::fs::read_to_string(proof_path)?;
    let proof_json: Groth16ProofJson = serde_json::from_str(&proof_content)?;

    Ok(proof_json)
}

pub fn shrink_wrap_cpu(
    _p254_receipt: &SuccinctReceipt<ReceiptClaim>,
    _journal: &[u8],
) -> Result<Groth16ProofJson> {
    unimplemented!();
    // if !is_docker_installed() {
    //     bail!("Please install docker first.")
    // }
    // let seal_path = work_dir.join("input.json");
    // let proof_path = work_dir.join("proof.json");
    // write_seal(identity_seal_json, &seal_path)?;

    // let volume = format!("{}:/mnt", work_dir.display());
    // let status = Command::new("docker")
    //     .args([
    //         "run",
    //         "--rm",
    //         "-v",
    //         &volume,
    //         "ozancw/risc0-to-bitvm2-groth16-prover",
    //     ])
    //     .status()?;

    // anyhow::ensure!(
    //     status.success(),
    //     "ozancw/risc0-to-bitvm2-groth16-prover failed: {:?}",
    //     status.code()
    // );

    // let proof_content = std::fs::read_to_string(proof_path)?;
    // let proof_json: Groth16ProofJson = serde_json::from_str(&proof_content)?;

    // Ok(proof_json)
}

pub fn finalize(
    journal_bytes: Vec<u8>,
    receipt_claim: MaybePruned<ReceiptClaim>,
    seal: &Groth16Seal,
) -> Result<Receipt> {
    let verifier_parameters_digest =
        Digest::from_hex("b72859b60cfe0bb13cbde70859fbc67ef9dbd5410bbe66bdb7be64a3dcf6814e")
            .unwrap(); // TODO(ec2): dont hardcode this (actually not sure if this is ever even used, so could be digest zero)
    let groth16_receipt =
        Groth16Receipt::new(seal.to_vec(), receipt_claim, verifier_parameters_digest);
    let receipt = Receipt::new(
        risc0_zkvm::InnerReceipt::Groth16(groth16_receipt),
        journal_bytes,
    );
    Ok(receipt)
}

fn is_docker_installed() -> bool {
    Command::new("docker")
        .arg("--version")
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}
