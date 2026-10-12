// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::traits::Provable;
use crate::{error::ZkError, prover::ZkProver};
use e3_events::{CircuitName, Proof};
use e3_fhe_params::{lbfv_crs_seed, BfvPreset};
use e3_zk_helpers::threshold::pk_generation::{
    LbfvPkGenerationCircuit, LbfvPkGenerationCircuitData, LbfvPkGenerationInputs,
};

impl Provable for LbfvPkGenerationCircuit {
    type Params = BfvPreset;
    type Input = LbfvPkGenerationCircuitData;
    type Inputs = LbfvPkGenerationInputs;

    fn circuit(&self) -> CircuitName {
        CircuitName::LbfvPkGeneration
    }
}

/// Prove one l-BFV public-key row, all CRT limbs in one recursive-target proof.
pub fn prove_lbfv_pk_generation_row(
    prover: &ZkProver,
    preset: BfvPreset,
    row: &LbfvPkGenerationCircuitData,
    e3_id: &str,
    artifacts_dir: &str,
) -> Result<Proof, ZkError> {
    if lbfv_crs_seed(preset).is_none() {
        return Err(ZkError::InvalidInput(format!(
            "l-BFV public-key generation is not enabled for {preset:?}"
        )));
    }
    LbfvPkGenerationCircuit.prove(
        prover,
        &preset,
        row,
        &format!("{e3_id}-lbfv-pk-row-{}", row.row_index),
        artifacts_dir,
    )
}
