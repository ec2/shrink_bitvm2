#[cfg(feature = "setup-groth16")]
mod setup_groth16;

fn main() {
    #[cfg(feature = "setup-groth16")]
    setup_groth16::SetupGroth16::run();
}
