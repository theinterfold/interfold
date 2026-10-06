// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::computation::DkgInputType;
use crate::registry::Circuit;
use crate::CiphernodesCommittee;
use e3_fhe_params::ParameterType;
use fhe_math::rq::{Poly, PowerBasis};

/// Circuit identifier for threshold decrypted-shares aggregation (Noir circuit 7).
#[derive(Debug)]
pub struct DecryptedSharesAggregationCircuit;

impl Circuit for DecryptedSharesAggregationCircuit {
    const NAME: &'static str = "decrypted-shares-aggregation";
    const PREFIX: &'static str = "DECRYPTED_SHARES_AGGREGATION";
    const SUPPORTED_PARAMETER: ParameterType = ParameterType::THRESHOLD;
    const DKG_INPUT_TYPE: Option<DkgInputType> = None;
}

/// Raw input for circuit input computation: decryption share polynomials from T+1 parties,
/// party IDs (1-based), ciphertext component `c0`, and the decoded message.
/// Inputs::compute adds `c0` to the sum of the shares, then runs CRT.
#[derive(Debug, Clone)]
pub struct DecryptedSharesAggregationCircuitData {
    pub committee: CiphernodesCommittee,
    /// Decryption shares from T+1 parties (Poly in RNS form).
    pub d_share_polys: Vec<Poly<PowerBasis>>,
    /// Party IDs (1-based: 1, 2, ..., T+1) for the reconstructing parties.
    pub reconstructing_parties: Vec<usize>,
    /// Decoded message polynomial coefficients.
    pub message_vec: Vec<u64>,
    /// Ciphertext component `b` (`c0`). Final decryption adds it once.
    pub ct0: Poly<PowerBasis>,
}
