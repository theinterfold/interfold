// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::traits::Provable;
use crate::{error::ZkError, prover::ZkProver};
use e3_events::{CircuitName, Proof};
use e3_fhe_params::{lbfv_crs_seed, lbfv_urs_seed};
use e3_zk_witness::threshold::rlk_generation::{RlkGenerationCircuitData, RlkGenerationInputs};

#[derive(Debug)]
pub struct RlkGenerationCircuit;

impl Provable for RlkGenerationCircuit {
    type Config = e3_zk_config::threshold::rlk_generation::RlkGenerationConfigs;
    type Input = RlkGenerationCircuitData;
    fn build_inputs(
        &self,
        config: &Self::Config,
        input: &Self::Input,
    ) -> Result<noirc_abi::InputMap, crate::ZkError> {
        let inputs = RlkGenerationInputs::compute(config, input)
            .map_err(|e| crate::ZkError::InputsGenerationFailed(e.to_string()))?;
        let json = inputs
            .to_json()
            .map_err(|e| crate::ZkError::SerializationError(e.to_string()))?;
        crate::circuits::utils::inputs_json_to_input_map(&json)
    }

    fn circuit(&self) -> CircuitName {
        CircuitName::RlkGeneration
    }
}

/// Prove one RLK row, all CRT limbs in one recursive-target proof.
pub fn prove_rlk_generation_row(
    prover: &ZkProver,
    config: &e3_zk_config::threshold::rlk_generation::RlkGenerationConfigs,
    row: &RlkGenerationCircuitData,
    e3_id: &str,
    artifacts_dir: &str,
) -> Result<Proof, ZkError> {
    let preset = config.preset;
    if lbfv_crs_seed(preset).is_none() || lbfv_urs_seed(preset).is_none() {
        return Err(ZkError::InvalidInput(format!(
            "RLK generation is not enabled for {preset:?}"
        )));
    }
    RlkGenerationCircuit.prove(
        prover,
        config,
        row,
        &format!("{e3_id}-rlk-row-{}", row.row_index),
        artifacts_dir,
    )
}
