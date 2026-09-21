// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::traits::Provable;
use e3_events::CircuitName;
use e3_fhe_params::BfvPreset;
use e3_zk_helpers::threshold::pk_generation::{
    LbfvPartySecretsCircuit, LbfvPartySecretsCircuitData, LbfvPartySecretsInputs,
};

impl Provable for LbfvPartySecretsCircuit {
    type Params = BfvPreset;
    type Input = LbfvPartySecretsCircuitData;
    type Inputs = LbfvPartySecretsInputs;

    fn circuit(&self) -> CircuitName {
        CircuitName::LbfvPartySecrets
    }
}
