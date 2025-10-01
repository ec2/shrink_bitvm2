use anyhow::{Result, ensure};
use risc0_groth16::Seal as Groth16Seal;
use risc0_zkvm::{Digest, sha::Digestible};

use crate::ShrinkBitvm2ReceiptClaim;

pub fn verify_integrity(seal: &Groth16Seal, output_bytes: &[u8]) -> Result<()> {
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

pub fn verify_proof(
    seal: &Groth16Seal,
    image_id: impl Into<Digest>,
    journal: Vec<u8>,
) -> Result<()> {
    let bvm2_claim_digest: [u8; 32] = ShrinkBitvm2ReceiptClaim::ok(image_id, journal)
        .digest()
        .into();

    verify_integrity(seal, &bvm2_claim_digest)
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

fn from_seal(seal_bytes: &[u8]) -> ark_groth16::Proof<ark_bn254::Bn254> {
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
