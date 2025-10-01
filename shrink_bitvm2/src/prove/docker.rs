use std::path::Path;

use anyhow::Result;
use anyhow::bail;
use risc0_groth16::ProofJson as Groth16ProofJson;
use std::process::Command;
// #!/bin/bash

// set -eoux

// # ulimit -s 67108864
// ./calc-witness /app/verify_for_guest_graph.bin /mnt/input.json output.wtns
// rapidsnark verify_for_guest_final.zkey output.wtns /mnt/proof.json /mnt/public.json
pub fn shrink_wrap(
    work_dir: &Path,
    identity_seal_json: serde_json::Value,
) -> Result<Groth16ProofJson> {
    if !is_docker_installed() {
        bail!("Please install docker first.")
    }
    let seal_path = work_dir.join("input.json");
    let proof_path = work_dir.join("proof.json");
    write_seal(identity_seal_json, &seal_path)?;

    let volume = format!("{}:/mnt", work_dir.display());
    let status = Command::new("docker")
        .args([
            "run",
            "--rm",
            "-v",
            &volume,
            "ozancw/risc0-to-bitvm2-groth16-prover:latest",
        ])
        .status()?;

    anyhow::ensure!(
        status.success(),
        "ozancw/risc0-to-bitvm2-groth16-prover failed: {:?}",
        status.code()
    );

    let proof_content = std::fs::read_to_string(proof_path)?;
    let proof_json: Groth16ProofJson = serde_json::from_str(&proof_content)?;

    Ok(proof_json)
}

fn write_seal(seal_json: serde_json::Value, seal_path: &Path) -> Result<()> {
    std::fs::write(seal_path, serde_json::to_string_pretty(&seal_json)?)?;
    Ok(())
}

fn is_docker_installed() -> bool {
    Command::new("docker")
        .arg("--version")
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}
