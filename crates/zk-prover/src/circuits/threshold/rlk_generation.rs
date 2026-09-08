// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::traits::Provable;
use e3_events::CircuitName;
use e3_fhe_params::BfvPreset;
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
