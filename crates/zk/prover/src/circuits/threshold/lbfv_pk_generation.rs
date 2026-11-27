// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::traits::Provable;
use crate::{error::ZkError, prover::ZkProver};
use e3_events::{CircuitName, Proof};
use e3_zk_witness::threshold::pk_generation::{
    LbfvPkGenerationCircuitData, LbfvPkGenerationInputs,
};

#[derive(Debug)]
pub struct LbfvPkGenerationCircuit;

impl Provable for LbfvPkGenerationCircuit {
    type Config = e3_zk_config::threshold::pk_generation::Configs;
    type Input = LbfvPkGenerationCircuitData;
    fn build_inputs(
        &self,
        config: &Self::Config,
        input: &Self::Input,
    ) -> Result<noirc_abi::InputMap, crate::ZkError> {
        let inputs = LbfvPkGenerationInputs::compute(config, input)
            .map_err(|e| crate::ZkError::InputsGenerationFailed(e.to_string()))?;
        crate::circuits::utils::inputs_json_to_input_map(&inputs.to_json())
    }

    fn circuit(&self) -> CircuitName {
        CircuitName::LbfvPkGeneration
    }
}

/// Prove one l-BFV public-key row, all CRT limbs in one recursive-target proof.
pub fn prove_lbfv_pk_generation_row(
    prover: &ZkProver,
    config: &e3_zk_config::threshold::pk_generation::Configs,
    row: &LbfvPkGenerationCircuitData,
    e3_id: &str,
    artifacts_dir: &str,
) -> Result<Proof, ZkError> {
    LbfvPkGenerationCircuit.prove(
        prover,
        config,
        row,
        &format!("{e3_id}-lbfv-pk-row-{}", row.row_index),
        artifacts_dir,
    )
}
