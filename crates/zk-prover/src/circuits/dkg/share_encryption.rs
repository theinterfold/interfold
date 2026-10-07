// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE

use crate::traits::Provable;
use e3_events::CircuitName;
use e3_fhe_params::BfvPreset;
use e3_zk_helpers::dkg::share_encryption::{
    Inputs, ShareEncryptionCircuit, ShareEncryptionCircuitData,
};

impl Provable for ShareEncryptionCircuit {
    type Params = BfvPreset;
    type Input = ShareEncryptionCircuitData;
    type Inputs = Inputs;

    fn circuit(&self) -> CircuitName {
        CircuitName::ShareEncryption
    }

    /// The l-BFV path proves C3 with its chunk-root variant.
    fn resolve_circuit_name(&self, params: &Self::Params, _input: &Self::Input) -> CircuitName {
        if e3_fhe_params::is_lbfv_path(*params) {
            CircuitName::ShareEncryptionChunked
        } else {
            CircuitName::ShareEncryption
        }
    }

    fn valid_circuits(&self) -> Vec<CircuitName> {
        vec![
            CircuitName::ShareEncryption,
            CircuitName::ShareEncryptionChunked,
        ]
    }
}
