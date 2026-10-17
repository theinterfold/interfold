// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Static circuit configuration and public-input layout contracts.

pub mod committee;
pub mod dkg;
pub mod field;
pub mod metadata;
pub mod output_layout;
mod parameters;
pub mod threshold;

pub use metadata::CircuitMetadata;
pub use output_layout::{
    CircuitInputLayout, CircuitOutputLayout, OutputField, DKG_SHARE_DECRYPTION_OUTPUTS,
    FIELD_BYTE_LEN, PK_AGGREGATION_OUTPUTS, PK_BFV_OUTPUTS, PK_GENERATION_OUTPUTS,
    SHARE_ENCRYPTION_INPUTS, SHARE_ENCRYPTION_OUTPUTS, THRESHOLD_SHARE_DECRYPTION_INPUTS,
    THRESHOLD_SHARE_DECRYPTION_OUTPUTS,
};

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Clone, Copy, PartialEq, Eq, Debug, Deserialize, Serialize, Hash)]
pub enum DkgInputType {
    SecretKey,
    SmudgingNoise,
}

pub const MAX_MSG_NON_ZERO_COEFFS: usize = 50;

#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("BFV error: {0}")]
    Fhe(#[from] fhe::Error),
    #[error(transparent)]
    K0(#[from] e3_fhe_params::utils::K0Error),
    #[error("CRT polynomial error: {0}")]
    CrtPolynomial(#[from] e3_polynomial::CrtPolynomialError),
    #[error("Sample error: {0}")]
    Sample(String),
    #[error("Unexpected error: {0}")]
    Other(String),
}
