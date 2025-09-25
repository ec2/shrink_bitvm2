use risc0_zkvm::{Digest, MaybePruned, SystemState, sha::Digestible};

use serde::Serialize;

#[derive(Clone, Debug, Serialize)]
pub struct ShrinkBitvm2ReceiptClaim {
    control_root: Digest,
    pre: MaybePruned<SystemState>,
    post: MaybePruned<SystemState>,
    control_id: Digest,
    // Note: This journal has to be exactly 32 bytes
    journal: Vec<u8>,
}

impl ShrinkBitvm2ReceiptClaim {
    pub fn ok(
        image_id: impl Into<Digest>,
        journal: impl Into<Vec<u8>>,
    ) -> ShrinkBitvm2ReceiptClaim {
        let verifier_params = risc0_zkvm::SuccinctReceiptVerifierParameters::default();
        let control_root = verifier_params.control_root;
        Self {
            control_root,
            pre: MaybePruned::Pruned(image_id.into()),
            post: MaybePruned::Value(SystemState {
                pc: 0,
                merkle_root: Digest::ZERO,
            }),
            control_id: crate::BN254_IDENTITY_CONTROL_ID,
            journal: journal.into(),
        }
    }
}

impl Digestible for ShrinkBitvm2ReceiptClaim {
    fn digest(&self) -> Digest {
        use sha2::{Digest as _, Sha256};

        let mut control_root_bytes: [u8; 32] = self.control_root.as_bytes().try_into().unwrap();
        for byte in &mut control_root_bytes {
            *byte = byte.reverse_bits();
        }
        let mut hasher = Sha256::new();
        hasher.update(control_root_bytes);
        hasher.update(self.pre.digest());
        hasher.update(self.post.digest());
        hasher.update(self.control_id.as_bytes());

        let output_prefix = hasher.finalize();

        // final blake3 hash
        let mut hasher = blake3::Hasher::new();
        hasher.update(&output_prefix);
        hasher.update(&self.journal);

        let mut digest_bytes: [u8; 32] = hasher.finalize().into();
        // trim to 31 bytes
        digest_bytes[31] = 0;
        // shift because of endianness
        digest_bytes.rotate_right(1);
        digest_bytes.into()
    }
}
