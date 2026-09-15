// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY

use crate::traits::Provable;
use e3_events::CircuitName;
use e3_fhe_params::BfvPreset;
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
