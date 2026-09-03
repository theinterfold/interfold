// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

mod decrypted_shares_aggregation;
mod decrypted_shares_aggregation_ckks;
mod pk_aggregation;
mod pk_generation;
mod pk_generation_ckks;
mod relin_round1_hybrid_ckks;
pub use relin_round1_hybrid_ckks::CkksHybridRelinRound1DigitData;
mod share_decryption;
mod share_decryption_ckks;

/// Resolve the per-param-set CKKS circuit for `params` through one of the
/// `CircuitName::*_ckks(param_set)` mappers. `None` when the params match
/// no known on-chain set (the caller fails closed at artifact lookup).
pub fn ckks_circuit_for_params(
    params: &fhe::ckks::CkksParameters,
    mapper: fn(u8) -> Option<e3_events::CircuitName>,
) -> Option<e3_events::CircuitName> {
    let set = e3_fhe_params::ckks_presets::ckks_on_chain_param_set_for(params).ok()?;
    mapper(set)
}
