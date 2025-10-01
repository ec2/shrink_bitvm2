use std::path::Path;

use anyhow::{Context, Result};
use hex::FromHex;
pub use receipt_claim::*;
use risc0_groth16::{ProofJson as Groth16ProofJson, Seal as Groth16Seal};
use risc0_zkvm::sha::Digestible;
use risc0_zkvm::{
    Digest, Groth16Receipt, MaybePruned, Receipt, ReceiptClaim, SuccinctReceipt, digest,
};
use tempfile::tempdir;

#[cfg(feature = "prove")]
mod prove;
mod receipt_claim;
pub mod verify;

use prove::identity_seal_json;
use verify::verify_proof;

// TODO(ec2): Is there a better way of handling this?
pub const BN254_IDENTITY_CONTROL_ID: Digest =
    digest!("c07a65145c3cb48b6101962ea607a4dd93c753bb26975cb47feb00d3666e4404");

pub fn succinct_to_bitvm2(
    succinct_receipt: &SuccinctReceipt<ReceiptClaim>,
    journal: &[u8],
) -> Result<Receipt> {
    #[cfg(feature = "prove")]
    {
        let p254_receipt: SuccinctReceipt<ReceiptClaim> =
            risc0_zkvm::recursion::identity_p254(succinct_receipt).unwrap();
        let receipt_claim = p254_receipt.claim.clone();
        let seal = shrink_wrap(&p254_receipt, journal)?;
        finalize(journal.to_vec(), receipt_claim, &seal.try_into()?)
    }
    #[cfg(not(feature = "prove"))]
    {
        bail!("succinct_to_bitvm2 called without the 'prove' feature enabled");
    }
}

pub fn shrink_wrap(
    p254_receipt: &SuccinctReceipt<ReceiptClaim>,
    journal: &[u8],
) -> Result<Groth16ProofJson> {
    #[cfg(not(feature = "prove"))]
    {
        bail!("shrink_wrap called without the 'prove' feature enabled");
    }

    let image_id = p254_receipt.claim.as_value()?.pre.digest();
    let seal_json = identity_seal_json(journal, p254_receipt)?;

    let tmp_dir = tempdir().context("failed to create temporary directory")?;
    let work_dir = std::env::var("SHRINK_BVM2_WORK_DIR");
    let work_dir = work_dir.as_ref().map(Path::new).unwrap_or(tmp_dir.path());

    #[cfg(feature = "cuda")]
    let proof_json = prove::cuda::shrink_wrap(work_dir, seal_json)?;
    #[cfg(not(feature = "cuda"))]
    let proof_json = prove::docker::shrink_wrap(work_dir, seal_json)?;

    let bvm2_claim_digest: [u8; 32] = ShrinkBitvm2ReceiptClaim::ok(image_id, journal.to_vec())
        .digest()
        .into();

    let seal: Groth16Seal = proof_json.clone().try_into()?;

    verify_proof(&seal, &bvm2_claim_digest)?;
    Ok(proof_json)
}

fn finalize(
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

#[cfg(test)]
mod tests {
    use super::*;
    use guest::ECHO_ELF;
    #[cfg(feature = "prove")]
    use risc0_zkvm::{ExecutorEnv, ProverOpts, default_prover};
    #[cfg(feature = "prove")]
    #[test]
    fn test_succinct_to_bitvm2() {
        tracing_subscriber::fmt()
            .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
            .init();
        let input = [3u8; 32];

        let env = ExecutorEnv::builder()
            // Send a & b to the guest
            .write_slice(&input)
            .build()
            .unwrap();

        // Obtain the default prover.
        let prover = default_prover();

        // Produce a receipt by proving the specified ELF binary.
        let receipt = prover
            .prove_with_opts(env, ECHO_ELF, &ProverOpts::succinct())
            .unwrap()
            .receipt;
        let succinct_receipt = receipt.inner.succinct().unwrap();

        succinct_to_bitvm2(succinct_receipt, &input).unwrap();
    }

    // #[cfg(feature = "prove")]
    // #[test]
    // fn test_invalid_input_size() {
    //     let input = [3u8; 33];

    //     let env = ExecutorEnv::builder()
    //         // Send a & b to the guest
    //         .write_slice(&input)
    //         .build()
    //         .unwrap();

    //     // Obtain the default prover.
    //     let prover = default_prover();

    //     // Produce a receipt by proving the specified ELF binary.
    //     let receipt = prover
    //         .prove_with_opts(env, ECHO_ELF, &ProverOpts::succinct())
    //         .unwrap()
    //         .receipt;
    //     let succinct_receipt = receipt.inner.succinct().unwrap();

    //     assert!(
    //         succinct_to_bitvm2(succinct_receipt, &input).is_err(),
    //         "Should fail because shrink_bitvm2 only supports 32-byte journals"
    //     );
    // }
}
