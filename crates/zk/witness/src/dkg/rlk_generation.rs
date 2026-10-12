// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::traits::Provable;
use crate::{error::ZkError, prover::ZkProver};
use e3_events::{CircuitName, Proof};
use e3_fhe_params::{lbfv_crs_seed, lbfv_urs_seed, BfvPreset};
use e3_zk_helpers::threshold::rlk_generation::{
    RlkGenerationCircuit, RlkGenerationCircuitData, RlkGenerationInputs,
};

impl Provable for RlkGenerationCircuit {
    type Params = BfvPreset;
    type Input = RlkGenerationCircuitData;
    type Inputs = RlkGenerationInputs;

    fn circuit(&self) -> CircuitName {
        CircuitName::RlkGeneration
    }
}

/// Prove one RLK row, all CRT limbs in one recursive-target proof.
pub fn prove_rlk_generation_row(
    prover: &ZkProver,
    preset: BfvPreset,
    row: &RlkGenerationCircuitData,
    e3_id: &str,
    artifacts_dir: &str,
) -> Result<Proof, ZkError> {
    if lbfv_crs_seed(preset).is_none() || lbfv_urs_seed(preset).is_none() {
        return Err(ZkError::InvalidInput(format!(
            "RLK generation is not enabled for {preset:?}"
        )));
    }
    RlkGenerationCircuit.prove(
        prover,
        &preset,
        row,
        &format!("{e3_id}-rlk-row-{}", row.row_index),
        artifacts_dir,
    )
}
