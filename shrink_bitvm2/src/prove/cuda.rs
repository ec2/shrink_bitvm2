// Copyright 2025 RISC Zero, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::path::Path;

use anyhow::{Context as _, Result};
use risc0_groth16_sys::{ProverParams, SetupParams, WitnessParams};

use crate::prove::witgen::calculate_witness;
use risc0_groth16::ProofJson as Groth16ProofJson;

pub fn shrink_wrap(
    work_dir: &Path,
    identity_seal_json: serde_json::Value,
) -> Result<Groth16ProofJson> {
    tracing::info!("cuda_shrink_wrap");
    let root_dir = std::env::var("RISC0_BVM2_SETUP_DIR");
    let root_dir = root_dir
        .as_ref()
        .map(Path::new)
        .expect("must provide RISC0_BVM2_SETUP_DIR");

    let mut setup_params =
        SetupParams::new(root_dir).context("failed to create groth16 work directories")?;
    setup_params.srs_path = root_dir.join("verify_for_guest_final.zkey").try_into()?;

    let mut witness_params = WitnessParams::new(root_dir);
    witness_params.graph_path = root_dir.join("verify_for_guest_graph.bin");
    tracing::info!("graph path: {:?}", witness_params.graph_path);

    let witness = calculate_witness(
        &witness_params.graph_path,
        identity_seal_json.to_string().as_str(),
    )?;

    tracing::info!("gpu prove start");
    {
        let _lock = risc0_zkp::hal::cuda::singleton().lock();

        let prover_params = ProverParams::new(work_dir, witness.as_ptr())
            .context("failed to create groth16 prover parameters")?;
        risc0_groth16_sys::prove(&prover_params, &setup_params)
            .context("failed to run groth16 prove operation")?;
        tracing::info!("prover done");

        let contents = std::fs::read_to_string(prover_params.proof_path.as_path())
            .context("failed to read groth16 prove output file")?;
        serde_json::from_str(&contents).context("failed to decode groth16 prove output file JSON")
    }
}
