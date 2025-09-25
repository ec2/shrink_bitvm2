use std::path::Path;

use hex::FromHex;
use risc0_zkvm::{
    Digest, Groth16Receipt, MaybePruned, Receipt, ReceiptClaim, SuccinctReceipt, digest,
    sha::Digestible,
};

use risc0_groth16::{ProofJson, Seal as Groth16Seal, prove::to_json as seal_to_json};

use anyhow::{Context, Result, ensure};
use num_bigint::BigUint;
use num_traits::Num;

pub const BN254_IDENTITY_CONTROL_ID: Digest =
    digest!("c07a65145c3cb48b6101962ea607a4dd93c753bb26975cb47feb00d3666e4404");

pub mod cuda;
pub mod rapidsnark;

pub mod receipt_claim;
use receipt_claim::ShrinkBitvm2ReceiptClaim;
use tempfile::tempdir;

pub fn shrink_wrap(
    p254_receipt: &SuccinctReceipt<ReceiptClaim>,
    journal: &[u8],
) -> Result<ProofJson> {
    let image_id = p254_receipt.claim.as_value()?.pre.digest();
    let seal_json = identity_seal_json(journal, p254_receipt)?;

    let tmp_dir = tempdir().context("failed to create temporary directory")?;
    let work_dir = std::env::var("SHRINK_BVM2_WORK_DIR");
    let work_dir = work_dir.as_ref().map(Path::new).unwrap_or(tmp_dir.path());

    let proof_json = cuda::shrink_wrap(work_dir, seal_json)?;

    let bvm2_claim_digest: [u8; 32] = ShrinkBitvm2ReceiptClaim::ok(image_id, journal.to_vec())
        .digest()
        .into();

    let seal: Groth16Seal = proof_json.clone().try_into()?;

    verify_proof(&seal, &bvm2_claim_digest)?;
    Ok(proof_json)
}

pub fn succinct_to_bitvm2(
    succinct_receipt: &SuccinctReceipt<ReceiptClaim>,
    journal: &[u8],
) -> Result<ProofJson> {
    let p254_receipt: SuccinctReceipt<ReceiptClaim> =
        risc0_zkvm::recursion::identity_p254(succinct_receipt).unwrap();
    shrink_wrap(&p254_receipt, journal)
}

fn identity_seal_json(
    journal_bytes: &[u8],
    p254_receipt: &SuccinctReceipt<ReceiptClaim>,
) -> Result<serde_json::Value> {
    let seal_bytes = p254_receipt.get_seal_bytes();
    let seal_json = seal_to_json(seal_bytes.as_slice())?; // TODO(ec2): This is currently using a local version of risc0 which exposes this method
    let mut seal_json: serde_json::Value = serde_json::from_str(&seal_json)?;

    let mut journal_bits = Vec::new();
    for byte in journal_bytes {
        for i in 0..8 {
            journal_bits.push((byte >> (7 - i)) & 1);
        }
    }
    let receipt_claim = p254_receipt.claim.as_value().unwrap();
    let pre_state_digest_bits: Vec<_> = receipt_claim
        .pre
        .digest()
        .as_bytes()
        .iter()
        .flat_map(|&byte| (0..8).rev().map(move |i| ((byte >> i) & 1).to_string()))
        .collect();

    let post_state_digest_bits: Vec<_> = receipt_claim
        .post
        .digest()
        .as_bytes()
        .iter()
        .flat_map(|&byte| (0..8).rev().map(move |i| ((byte >> i) & 1).to_string()))
        .collect();

    let mut id_bn254_fr_bits: Vec<String> = p254_receipt
        .control_id
        .as_bytes()
        .iter()
        .flat_map(|&byte| (0..8).rev().map(move |i| ((byte >> i) & 1).to_string()))
        .collect();
    // remove 248th and 249th bits
    id_bn254_fr_bits.remove(248);
    id_bn254_fr_bits.remove(248);

    let mut succinct_control_root_bytes: [u8; 32] =
        risc0_zkvm::SuccinctReceiptVerifierParameters::default()
            .control_root
            .as_bytes()
            .try_into()?;

    succinct_control_root_bytes.reverse();
    let succinct_control_root_hex = hex::encode(succinct_control_root_bytes);

    let a1_str = succinct_control_root_hex[0..32].to_string();
    let a0_str = succinct_control_root_hex[32..64].to_string();
    let a0_dec = to_decimal(&a0_str).context("a0_str returned None")?;
    let a1_dec = to_decimal(&a1_str).context("a1_str returned None")?;

    let control_root = vec![a0_dec, a1_dec];

    seal_json["journal_digest_bits"] = journal_bits.into();
    seal_json["pre_state_digest_bits"] = pre_state_digest_bits.into();
    seal_json["post_state_digest_bits"] = post_state_digest_bits.into();
    seal_json["id_bn254_fr_bits"] = id_bn254_fr_bits.into();
    seal_json["control_root"] = control_root.into();

    Ok(seal_json)
}

fn write_seal(seal_json: serde_json::Value, seal_path: &Path) -> Result<()> {
    std::fs::write(seal_path, serde_json::to_string_pretty(&seal_json)?)?;
    Ok(())
}

fn to_decimal(s: &str) -> Option<String> {
    let int = BigUint::from_str_radix(s, 16).ok();
    int.map(|n| n.to_str_radix(10))
}

pub fn verify_proof(seal: &Groth16Seal, output_bytes: &[u8]) -> Result<()> {
    use ark_ff::PrimeField;

    let ark_proof = from_seal(&seal.to_vec());
    let public_input_scalar = ark_bn254::Fr::from_be_bytes_mod_order(output_bytes);
    let ark_vk = get_ark_verifying_key();
    let ark_pvk = ark_groth16::prepare_verifying_key(&ark_vk);
    let res = ark_groth16::Groth16::<ark_bn254::Bn254>::verify_proof(
        &ark_pvk,
        &ark_proof,
        &[public_input_scalar],
    )
    .unwrap();
    ensure!(res, "proof verification failed");
    Ok(())
}

pub fn get_ark_verifying_key() -> ark_groth16::VerifyingKey<ark_bn254::Bn254> {
    use ark_bn254::{Fq, Fq2, G1Affine, G2Affine};
    use std::str::FromStr;

    let alpha_g1 = G1Affine::new(
        Fq::from_str(
            "20491192805390485299153009773594534940189261866228447918068658471970481763042",
        )
        .unwrap(),
        Fq::from_str(
            "9383485363053290200918347156157836566562967994039712273449902621266178545958",
        )
        .unwrap(),
    );

    let beta_g2 = G2Affine::new(
        Fq2::new(
            Fq::from_str(
                "6375614351688725206403948262868962793625744043794305715222011528459656738731",
            )
            .unwrap(),
            Fq::from_str(
                "4252822878758300859123897981450591353533073413197771768651442665752259397132",
            )
            .unwrap(),
        ),
        Fq2::new(
            Fq::from_str(
                "10505242626370262277552901082094356697409835680220590971873171140371331206856",
            )
            .unwrap(),
            Fq::from_str(
                "21847035105528745403288232691147584728191162732299865338377159692350059136679",
            )
            .unwrap(),
        ),
    );

    let gamma_g2 = G2Affine::new(
        Fq2::new(
            Fq::from_str(
                "10857046999023057135944570762232829481370756359578518086990519993285655852781",
            )
            .unwrap(),
            Fq::from_str(
                "11559732032986387107991004021392285783925812861821192530917403151452391805634",
            )
            .unwrap(),
        ),
        Fq2::new(
            Fq::from_str(
                "8495653923123431417604973247489272438418190587263600148770280649306958101930",
            )
            .unwrap(),
            Fq::from_str(
                "4082367875863433681332203403145435568316851327593401208105741076214120093531",
            )
            .unwrap(),
        ),
    );

    let delta_g2 = G2Affine::new(
        Fq2::new(
            Fq::from_str(
                "19928663713463533589216209779412278386769407450988172849262535478593422929698",
            )
            .unwrap(),
            Fq::from_str(
                "19916519943909223643323234301580053157586699704876134064841182937085943926141",
            )
            .unwrap(),
        ),
        Fq2::new(
            Fq::from_str(
                "4584600978911428195337731119171761277167808711062125916470525050324985708782",
            )
            .unwrap(),
            Fq::from_str(
                "903010326261527050999816348900764705196723158942686053018929539519969664840",
            )
            .unwrap(),
        ),
    );

    let gamma_abc_g1 = vec![
        G1Affine::new(
            Fq::from_str(
                "6698887085900109660417671413804888867145870700073340970189635830129386206569",
            )
            .unwrap(),
            Fq::from_str(
                "10431087902009508261375793061696708147989126018612269070732549055898651692604",
            )
            .unwrap(),
        ),
        G1Affine::new(
            Fq::from_str(
                "20225609417084538563062516991929114218412992453664808591983416996515711931386",
            )
            .unwrap(),
            Fq::from_str(
                "3236310410959095762960658876334609343091075204896196791007975095263664214628",
            )
            .unwrap(),
        ),
    ];

    ark_groth16::VerifyingKey {
        alpha_g1,
        beta_g2,
        gamma_g2,
        delta_g2,
        gamma_abc_g1,
    }
}

pub fn get_r0_verifying_key() -> risc0_groth16::VerifyingKey {
    let json_content = std::fs::read_to_string("/home/etu/risc0-to-bitvm2/vkey_guest.json")
        .expect("Failed to read verification key JSON file");
    let vk_json: risc0_groth16::VerifyingKeyJson =
        serde_json::from_str(&json_content).expect("Failed to parse verification key JSON");

    vk_json.verifying_key().unwrap()
}

pub fn from_seal(seal_bytes: &[u8]) -> ark_groth16::Proof<ark_bn254::Bn254> {
    use ark_bn254::{Fq, Fq2, G1Affine, G2Affine};
    use ark_ff::{Field, PrimeField};

    let a = G1Affine::new(
        Fq::from_be_bytes_mod_order(&seal_bytes[0..32]),
        Fq::from_be_bytes_mod_order(&seal_bytes[32..64]),
    );

    let b = G2Affine::new(
        Fq2::from_base_prime_field_elems([
            Fq::from_be_bytes_mod_order(&seal_bytes[96..128]),
            Fq::from_be_bytes_mod_order(&seal_bytes[64..96]),
        ])
        .unwrap(),
        Fq2::from_base_prime_field_elems([
            Fq::from_be_bytes_mod_order(&seal_bytes[160..192]),
            Fq::from_be_bytes_mod_order(&seal_bytes[128..160]),
        ])
        .unwrap(),
    );

    let c = G1Affine::new(
        Fq::from_be_bytes_mod_order(&seal_bytes[192..224]),
        Fq::from_be_bytes_mod_order(&seal_bytes[224..256]),
    );

    ark_groth16::Proof { a, b, c }
}
