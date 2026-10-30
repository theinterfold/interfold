// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::traits::Provable;
use crate::{error::ZkError, prover::ZkProver};
use e3_events::{CircuitName, Proof};
use e3_fhe_params::lbfv_crs_seed;
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
        let json = inputs
            .to_json()
            .map_err(|e| crate::ZkError::SerializationError(e.to_string()))?;
        crate::circuits::utils::inputs_json_to_input_map(&json)
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
    let preset = config.preset;
    if lbfv_crs_seed(preset).is_none() {
        return Err(ZkError::InvalidInput(format!(
            "l-BFV public-key generation is not enabled for {preset:?}"
        )));
    }
    LbfvPkGenerationCircuit.prove(
        prover,
        config,
        row,
        &format!("{e3_id}-lbfv-pk-row-{}", row.row_index),
        artifacts_dir,
    )
}
