// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::traits::Provable;
use e3_events::CircuitName;
use e3_zk_witness::threshold::rlk_aggregation::{RlkAggregationCircuitData, RlkAggregationInputs};

#[derive(Debug)]
pub struct RlkAggregationCircuit;

impl Provable for RlkAggregationCircuit {
    type Config = e3_zk_config::threshold::rlk_aggregation::RlkAggregationConfigs;
    type Input = RlkAggregationCircuitData;
    fn build_inputs(
        &self,
        config: &Self::Config,
        input: &Self::Input,
    ) -> Result<noirc_abi::InputMap, crate::ZkError> {
        let inputs = RlkAggregationInputs::compute(config, input)
            .map_err(|e| crate::ZkError::InputsGenerationFailed(e.to_string()))?;
        let json = inputs
            .to_json()
            .map_err(|e| crate::ZkError::SerializationError(e.to_string()))?;
        crate::circuits::utils::inputs_json_to_input_map(&json)
    }

    fn circuit(&self) -> CircuitName {
        CircuitName::RlkAggregation
    }
}
