// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE

use crate::traits::Provable;
use e3_events::CircuitName;
use e3_zk_witness::dkg::share_encryption::{Inputs, ShareEncryptionCircuitData};

use crate::ZkError;

#[derive(Debug)]
pub struct ShareEncryptionCircuit;

impl Provable for ShareEncryptionCircuit {
    fn build_inputs(
        &self,
        config: &Self::Config,
        input: &Self::Input,
    ) -> Result<noirc_abi::InputMap, ZkError> {
        let inputs = Inputs::compute(config, input)
            .map_err(|e| ZkError::InputsGenerationFailed(e.to_string()))?;
        crate::circuits::utils::inputs_json_to_input_map(&inputs.to_json())
    }

    type Config = e3_zk_config::dkg::share_encryption::Configs;
    type Input = ShareEncryptionCircuitData;

    fn circuit(&self) -> CircuitName {
        CircuitName::ShareEncryption
    }
}
