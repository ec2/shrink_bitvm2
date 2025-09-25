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

use clap::{Parser, Subcommand};
use risc0_groth16_sys::{SetupParams, WitnessParams};
use rlimit::{INFINITY, Resource, setrlimit};
use std::path::Path;
use xshell::{Shell, cmd};

// TODO: Pull from env vars
const CIRCOM_WITNESSCALC_URL: &str = "https://github.com/iden3/circom-witnesscalc.git";
const CIRCOM_WITNESSCALC_COMMIT: &str = "b7ff0ffd9c72c8f60896ce131ee98a35aba96009"; // 0.2.1
const VERIFY_FOR_GUEST_ZKEY_URL: &str =
    "https://static.testnet.citrea.xyz/conf/verify_for_guest_final.zkey";

#[derive(Parser)]
#[command(name = "setup")]
#[command(about = "Setup tool for RISC0 BitVM2 dependencies")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    #[command(about = "Download all dependencies")]
    Download,
    #[command(about = "Run risc0_groth16_sys::setup")]
    Setup,
}

pub fn main() {
    let cli = Cli::parse();
    setrlimit(Resource::STACK, INFINITY, INFINITY).unwrap();

    match cli.command {
        Commands::Download => download_dependencies(),
        Commands::Setup => run_setup(),
    }
}

fn get_setup_context() -> (Shell, std::path::PathBuf, SetupParams, WitnessParams) {
    let sh = Shell::new().unwrap();
    let setup_dir = std::env::var("RISC0_BVM2_SETUP_DIR");
    let setup_dir = setup_dir
        .as_ref()
        .map(Path::new)
        .expect("must provide RISC0_BVM2_SETUP_DIR");
    println!("RISC0_BVM2_SETUP_DIR: {}", setup_dir.display());

    sh.change_dir(sh.create_dir(&setup_dir).unwrap());

    let mut setup_params = SetupParams::new(&setup_dir).unwrap();
    setup_params.srs_path = setup_dir
        .join("verify_for_guest_final.zkey")
        .try_into()
        .unwrap();

    let mut witness_params = WitnessParams::new(&setup_dir);
    witness_params.graph_path = setup_dir
        .join("verify_for_guest_graph.bin")
        .try_into()
        .unwrap();

    (sh, setup_dir.to_path_buf(), setup_params, witness_params)
}

fn download_dependencies() {
    let (sh, _setup_dir, setup_params, witness_params) = get_setup_context();

    if !sh.path_exists(setup_params.srs_path.as_path()) {
        let zkey_path = setup_params.srs_path.as_path().to_path_buf();
        cmd!(sh, "curl -o {zkey_path} {VERIFY_FOR_GUEST_ZKEY_URL}")
            .run()
            .unwrap();
    }

    if !sh.path_exists("circom-witnesscalc") {
        cmd!(sh, "git clone {CIRCOM_WITNESSCALC_URL}")
            .run()
            .unwrap();
    }

    if !sh.path_exists("circomlib") {
        cmd!(sh, "git clone https://github.com/iden3/circomlib.git")
            .run()
            .unwrap();
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

    let stark_verify_circom = std::env::current_dir()
        .unwrap()
        .join("groth16_proof/circuits/verify_for_guest.circom");
    if !sh.path_exists(&stark_verify_circom) {
        panic!(
            "Run from top of workspace. Could not find: {}",
            stark_verify_circom.display()
        );
    }

    let graph_path = &witness_params.graph_path;
    if !sh.path_exists(graph_path) {
        cmd!(sh, "{build_circuit} {stark_verify_circom} {graph_path}")
            .run()
            .unwrap();
    }

    println!("All dependencies downloaded successfully!");
}

fn run_setup() {
    let (sh, _setup_dir, setup_params, witness_params) = get_setup_context();

    let graph_path = &witness_params.graph_path;
    if !sh.path_exists(graph_path) {
        panic!(
            "Graph file not found: {}. Run 'download' command first.",
            graph_path.display()
        );
    }

    if !sh.path_exists(setup_params.srs_path.as_path()) {
        let zkey_path = setup_params.srs_path.as_path().to_path_buf();
        panic!(
            "SRS file not found: {}. Run 'download' command first.",
            zkey_path.display()
        );
    }

    risc0_groth16_sys::setup(&setup_params).unwrap();
    println!("Setup completed successfully!");
}
