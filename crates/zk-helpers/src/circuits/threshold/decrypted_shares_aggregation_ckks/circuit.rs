// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::computation::DkgInputType;
use crate::registry::Circuit;
use e3_fhe_params::ParameterType;
use fhe_math::rq::{Poly, PowerBasis};

/// Circuit identifier for CKKS threshold decrypted-shares aggregation
/// (Noir circuit `decrypted_shares_aggregation_ckks`).
#[derive(Debug)]
pub struct DecryptedSharesAggregationCkksCircuit;

impl Circuit for DecryptedSharesAggregationCkksCircuit {
    const NAME: &'static str = "decrypted-shares-aggregation-ckks";
    const PREFIX: &'static str = "DECRYPTED_SHARES_AGGREGATION_CKKS";
    const SUPPORTED_PARAMETER: ParameterType = ParameterType::THRESHOLD;
    const DKG_INPUT_TYPE: Option<DkgInputType> = None;
}

/// Raw input: T+1 CKKS decryption-share polynomials (RNS form, at the
/// ciphertext's level), 1-based party IDs, and the committee threshold.
///
/// Unlike BFV there is no `message_vec`: the reconstructed `u_global` IS the
/// public result (scale division happens off-circuit).
#[derive(Debug, Clone)]
pub struct DecryptedSharesAggregationCkksCircuitData {
    /// Committee threshold `t` (t+1 shares reconstruct).
    pub threshold: usize,
    /// Decryption shares from T+1 parties (Poly in RNS PowerBasis form).
    pub d_share_polys: Vec<Poly<PowerBasis>>,
    /// Party IDs (1-based) for the reconstructing parties.
    pub reconstructing_parties: Vec<usize>,
    /// E3 decryption domain, high 128 bits (public input). Same derivation
    /// as C6-CKKS: `decryption_domain_limbs(chain_id, e3_id, ctx, keccak(ct))`.
    /// Binds the proof to one E3 / committee / ciphertext (anti-replay).
    pub domain_hi: u128,
    /// E3 decryption domain, low 128 bits (public input).
    pub domain_lo: u128,
}
