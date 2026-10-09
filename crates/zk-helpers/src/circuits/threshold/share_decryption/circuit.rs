// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Circuit type and input for threshold share decryption.

use crate::computation::DkgInputType;
use crate::metadata::Circuit;
use e3_fhe_params::ParameterType;
use e3_polynomial::CrtPolynomial;
use fhe::bfv::{Ciphertext, PublicKey};

/// Threshold share decryption circuit (PVSS #6).
///
/// Verifies correct computation of a party's decryption share with respect to
/// committed aggregated secret and smudging-error shares.
#[derive(Debug)]
pub struct ShareDecryptionCircuit;

/// Input to the share decryption circuit: ciphertext, public key, and the party's
/// aggregated secret share (s), smudging error (e), and computed decryption share (d_share).
pub struct ShareDecryptionCircuitData {
    pub ciphertext: Ciphertext,
    pub public_key: PublicKey,
    pub s: CrtPolynomial,
    pub e: CrtPolynomial,
    pub d_share: CrtPolynomial,
    /// High and low 128-bit limbs of the E3 decryption domain.
    pub domain_hi: u128,
    pub domain_lo: u128,
}

impl Circuit for ShareDecryptionCircuit {
    const NAME: &'static str = "threshold-share-decryption";
    const PREFIX: &'static str = "THRESHOLD_SHARE_DECRYPTION";
    const SUPPORTED_PARAMETER: ParameterType = ParameterType::THRESHOLD;
    const DKG_INPUT_TYPE: Option<DkgInputType> = None;
}
