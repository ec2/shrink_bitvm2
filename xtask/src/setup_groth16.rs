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

use risc0_groth16_sys::{SetupParams, WitnessParams};
use rlimit::{INFINITY, Resource, setrlimit};
use std::path::Path;
use xshell::{Shell, cmd};

const CIRCOM_WITNESSCALC_URL: &str = "https://github.com/iden3/circom-witnesscalc.git";
const CIRCOM_WITNESSCALC_COMMIT: &str = "b7ff0ffd9c72c8f60896ce131ee98a35aba96009"; // 0.2.1

const RISC0_TO_BITVM2_URL: &str = "https://github.com/ec2/risc0-to-bitvm2-boundless.git";
const RISC0_TO_BITVM2_COMMIT: &str = "b47483ae7ff2bbfbf6d4448bac76aa26afc80e47";

const CIRCOMLIB_URL: &str = "https://github.com/iden3/circomlib.git";
const CIRCOMLIB_COMMIT: &str = "35e54ea21da3e8762557234298dbb553c175ea8d";

pub struct SetupGroth16;
const CIRCUIT_FILES: &[&str] = &[
    "blake3_common.circom",
    "blake3_compression.circom",
    "risc0.circom",
    "stark_verify.circom",
    "verify_for_guest.circom",
];

fn download_circuits(sh: &Shell) {
    if !sh.path_exists("risc0-to-bitvm2") {
        cmd!(sh, "git clone {RISC0_TO_BITVM2_URL} risc0-to-bitvm2")
            .run()
            .unwrap();
    }
    {
        let _cd = sh.push_dir("risc0-to-bitvm2");
        cmd!(sh, "git checkout {RISC0_TO_BITVM2_COMMIT}")
            .run()
            .unwrap();
        cmd!(sh, "git lfs pull").run().unwrap();
    }
    sh.create_dir("groth16_proof").unwrap();
    sh.create_dir("groth16_proof/circuits").unwrap();
    // Copy circuit files every time because we modify verify_for_guest.circom
    for file in CIRCUIT_FILES {
        let src = format!("risc0-to-bitvm2/groth16_proof/circuits/{file}");
        let dst = format!("groth16_proof/circuits/{file}");
        if !sh.path_exists(&dst) {
            sh.copy_file(&src, &dst).unwrap();
        }
    }
    // Delete the last line of stark_verify.circom so that we only use its template
    cmd!(
        sh,
        "sed -i $d ./groth16_proof/circuits/verify_for_guest.circom"
    )
    .run()
    .unwrap();
}

impl SetupGroth16 {
    pub fn run() {
        setrlimit(Resource::STACK, INFINITY, INFINITY).unwrap();

        let sh = Shell::new().unwrap();
        let setup_dir = std::env::var("RISC0_BVM2_SETUP_DIR");
        let setup_dir = setup_dir
            .as_ref()
            .map(Path::new)
            .expect("must provide RISC0_BVM2_SETUP_DIR");
        println!("RISC0_BVM2_SETUP_DIR: {}", setup_dir.display());

        sh.change_dir(sh.create_dir(setup_dir).unwrap());

        download_circuits(&sh);

        let mut setup_params = SetupParams::new(setup_dir).unwrap();
        setup_params.srs_path = setup_dir
            .join("verify_for_guest_final.zkey")
            .try_into()
            .unwrap();

        let mut witness_params = WitnessParams::new(setup_dir);
        witness_params.graph_path = setup_dir.join("verify_for_guest_graph.bin");

        if !sh.path_exists(setup_params.srs_path.as_path()) {
            let zkey_path = setup_params.srs_path.as_path().to_path_buf();
            let url = "https://static.testnet.citrea.xyz/conf/verify_for_guest_final.zkey";
            cmd!(sh, "curl -o {zkey_path} {url}").run().unwrap();
        }

        if !sh.path_exists("circom-witnesscalc") {
            cmd!(sh, "git clone {CIRCOM_WITNESSCALC_URL}")
                .run()
                .unwrap();
        }

        if !sh.path_exists("circomlib") {
            cmd!(sh, "git clone {CIRCOMLIB_URL}").run().unwrap();
        }
        {
            let _cd = sh.push_dir("circomlib");
            cmd!(sh, "git checkout {CIRCOMLIB_COMMIT}").run().unwrap();
        }

        let build_circuit = "circom-witnesscalc/target/release/build-circuit";
        if !sh.path_exists(build_circuit) {
            let _cd = sh.push_dir("circom-witnesscalc");
            cmd!(sh, "git checkout {CIRCOM_WITNESSCALC_COMMIT}")
                .run()
                .unwrap();
            cmd!(sh, "cargo build --release -p build-circuit")
                .run()
                .unwrap();
        }

        let stark_verify_circom = setup_dir.join("groth16_proof/circuits/verify_for_guest.circom");
        if !sh.path_exists(&stark_verify_circom) {
            panic!(
                "Run from top of workspace. Could not find: {}",
                stark_verify_circom.display()
            );
        }

        // // verify_for_guest.circom -> verify_for_guest_graph.bin
        let graph_path = &witness_params.graph_path;
        if !sh.path_exists(graph_path) {
            cmd!(sh, "{build_circuit} {stark_verify_circom} {graph_path}")
                .run()
                .unwrap();
        }

        // stark_verify_final.zkey -> (fuzzed_msm_results.bin, preprocessed_coeffs.bin)
        risc0_groth16_sys::setup(&setup_params).unwrap();
    }
}
