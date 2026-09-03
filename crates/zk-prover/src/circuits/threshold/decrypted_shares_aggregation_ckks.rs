// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE

use crate::traits::Provable;
use e3_events::CircuitName;
use e3_zk_helpers::circuits::threshold::decrypted_shares_aggregation_ckks::{
    DecryptedSharesAggregationCkksCircuit, DecryptedSharesAggregationCkksCircuitData, Inputs,
};
use e3_zk_helpers::circuits::threshold::user_data_encryption_ckks::CkksPreset;

impl Provable for DecryptedSharesAggregationCkksCircuit {
    type Params = CkksPreset;
    type Input = DecryptedSharesAggregationCkksCircuitData;
    type Inputs = Inputs;

    fn circuit(&self) -> CircuitName {
        CircuitName::DecryptedSharesAggregationCkks
    }

    /// Per-param-set artifact (see `share_decryption_ckks.rs`).
    fn resolve_circuit_name(&self, params: &Self::Params, _input: &Self::Input) -> CircuitName {
        super::ckks_circuit_for_params(
            &params.params,
            CircuitName::decrypted_shares_aggregation_ckks,
        )
        .unwrap_or(CircuitName::DecryptedSharesAggregationCkks)
    }

    fn valid_circuits(&self) -> Vec<CircuitName> {
        CircuitName::all_decrypted_shares_aggregation_ckks().to_vec()
    }
}
