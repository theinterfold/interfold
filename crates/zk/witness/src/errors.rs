// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Errors from witness preparation, conversion, and commitment encoding.

use e3_fhe_params::utils::K0Error;
use e3_polynomial::CrtPolynomialError;
use thiserror::Error;

/// Errors from witness preparation and its upstream operations.
#[derive(Error, Debug)]
pub enum WitnessError {
    #[error(transparent)]
    Config(#[from] e3_zk_config::ConfigError),
    #[error("BFV error: {0}")]
    Fhe(#[from] fhe::Error),
    #[error(transparent)]
    K0(#[from] K0Error),
    #[error("CRT polynomial error: {0}")]
    CrtPolynomial(#[from] CrtPolynomialError),
    #[error(transparent)]
    Polynomial(#[from] e3_polynomial::PolynomialError),
    #[error("Conversion error: {0}")]
    ConversionError(String),
    #[error("Commitment too long: {0}")]
    CommitmentTooLong(usize),
    /// Extra ciphertext components would share a commitment with the two-component prefix.
    #[error(
        "Expected 2 ciphertext components, got {0}; the commitment covers c[0] and c[1] only, so \
         additional components would share a commitment with the two-component prefix"
    )]
    UnexpectedCiphertextComponents(usize),
    #[error("Sample error: {0}")]
    Sample(String),
    #[error("Unexpected error: {0}")]
    Other(String),
}
