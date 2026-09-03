// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE

use crate::traits::Provable;
use e3_events::CircuitName;
use e3_zk_helpers::circuits::threshold::share_decryption_ckks::{
    CkksShareDecryptionCircuit, CkksShareDecryptionData, Inputs,
};
use e3_zk_helpers::circuits::threshold::user_data_encryption_ckks::CkksPreset;

impl Provable for CkksShareDecryptionCircuit {
    type Params = CkksPreset;
    type Input = CkksShareDecryptionData;
    type Inputs = Inputs;

    fn circuit(&self) -> CircuitName {
        CircuitName::ThresholdShareDecryptionCkks
    }

    /// Per-param-set artifact: `share_decryption_ckks` for set 0,
    /// `share_decryption_ckks_ps<N>` otherwise. Unknown params keep the
    /// canonical name and fail at artifact resolution.
    fn resolve_circuit_name(&self, params: &Self::Params, _input: &Self::Input) -> CircuitName {
        super::ckks_circuit_for_params(&params.params, CircuitName::share_decryption_ckks)
            .unwrap_or(CircuitName::ThresholdShareDecryptionCkks)
    }

    fn valid_circuits(&self) -> Vec<CircuitName> {
        CircuitName::all_share_decryption_ckks().to_vec()
    }
}
