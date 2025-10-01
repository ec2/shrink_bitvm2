use anyhow::{Result, anyhow};
use std::{io::Cursor, path::Path};

pub(crate) struct CalcWitness {
    witness: Vec<wtns_file::FieldElement<32>>,
}

impl CalcWitness {
    pub(crate) fn as_ptr(&self) -> *const u8 {
        self.witness.as_ptr() as *const u8
    }
}

pub fn calculate_witness(graph_path: &Path, inputs: &str) -> Result<CalcWitness> {
    let witness_encoded = calculate_witness_encoded(graph_path, inputs)?;
    let wtns_f = wtns_file::WtnsFile::read(Cursor::new(witness_encoded))?;
    Ok(CalcWitness {
        witness: wtns_f.witness.0,
    })
}

pub fn calculate_witness_encoded(graph_path: &Path, inputs: &str) -> Result<Vec<u8>> {
    tracing::info!("calculate_witness");
    let graph = std::fs::read(graph_path)?;
    let witness_encoded = circom_witnesscalc::calc_witness(inputs, &graph)
        .map_err(|err| anyhow!("witness failure: {err}"))?;
    Ok(witness_encoded)
}
