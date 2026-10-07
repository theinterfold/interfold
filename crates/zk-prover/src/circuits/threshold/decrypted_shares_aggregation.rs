// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE

use crate::traits::Provable;
use e3_events::CircuitName;
use e3_fhe_params::BfvPreset;
use e3_zk_helpers::circuits::threshold::decrypted_shares_aggregation::circuit::{
    DecryptedSharesAggregationCircuit, DecryptedSharesAggregationCircuitData,
};
use e3_zk_helpers::circuits::threshold::decrypted_shares_aggregation::computation::Inputs;

impl Provable for DecryptedSharesAggregationCircuit {
    type Params = BfvPreset;
    type Input = DecryptedSharesAggregationCircuitData;
    type Inputs = Inputs;

    fn circuit(&self) -> CircuitName {
        CircuitName::DecryptedSharesAggregation
    }

    /// The l-BFV path's modulus is wider than the bounded C7 supports, so it proves the same
    /// statement with `decrypted_shares_aggregation_wide`.
    fn resolve_circuit_name(&self, params: &Self::Params, _input: &Self::Input) -> CircuitName {
        if e3_fhe_params::is_lbfv_path(*params) {
            CircuitName::DecryptedSharesAggregationWide
        } else {
            CircuitName::DecryptedSharesAggregation
        }
    }

    fn valid_circuits(&self) -> Vec<CircuitName> {
        vec![
            CircuitName::DecryptedSharesAggregation,
            CircuitName::DecryptedSharesAggregationWide,
        ]
    }
}
