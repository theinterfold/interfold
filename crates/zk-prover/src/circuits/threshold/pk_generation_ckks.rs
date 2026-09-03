// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE

use crate::traits::Provable;
use e3_events::CircuitName;
use e3_zk_helpers::circuits::threshold::pk_generation_ckks::{
    CkksPkGenerationCircuit, CkksPkGenerationData, Inputs,
};
use e3_zk_helpers::circuits::threshold::user_data_encryption_ckks::CkksPreset;

/// C1-CKKS (`pk_generation_ckks_ps<N>`): the pk-share well-formedness
/// proof the aggregator verifies before summing (rogue-key gate).
impl Provable for CkksPkGenerationCircuit {
    type Params = CkksPreset;
    type Input = CkksPkGenerationData;
    type Inputs = Inputs;

    fn circuit(&self) -> CircuitName {
        CircuitName::PkGenerationCkksPs0
    }

    fn resolve_circuit_name(&self, params: &Self::Params, _input: &Self::Input) -> CircuitName {
        super::ckks_circuit_for_params(&params.params, CircuitName::pk_generation_ckks)
            .unwrap_or(CircuitName::PkGenerationCkksPs0)
    }

    fn valid_circuits(&self) -> Vec<CircuitName> {
        CircuitName::all_pk_generation_ckks().to_vec()
    }
}
