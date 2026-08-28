// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use anyhow::{Context as _, Result};
use e3_utils::utility_types::ArcBytes;
use fhe::ckks::CkksParameters;
use fhe_traits::Deserialize as FheDeserialize;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Threshold CKKS configuration: serialized parameters plus the committee
/// shape. The analogue of `e3_trbfv::TrBFVConfig`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct TrCkksConfig {
    /// Serialized CKKS parameters (`CkksParameters::to_bytes`).
    params: ArcBytes,
    /// Number of ciphernodes.
    num_parties: u64,
    /// Threshold (t+1 parties reconstruct).
    threshold: u64,
}

impl TrCkksConfig {
    /// Create a new config.
    pub fn new(params: ArcBytes, num_parties: u64, threshold: u64) -> Self {
        Self {
            params,
            num_parties,
            threshold,
        }
    }

    /// Decode the CKKS parameters.
    pub fn params(&self) -> Result<Arc<CkksParameters>> {
        Ok(Arc::new(
            CkksParameters::try_deserialize(&self.params)
                .context("failed to decode CKKS params")?,
        ))
    }

    pub fn num_parties(&self) -> u64 {
        self.num_parties
    }

    pub fn threshold(&self) -> u64 {
        self.threshold
    }
}

/// The dev/insecure CKKS parameter preset: N=512, two 45-bit moduli, scale
/// 2^40. Matches the shape of the BFV `insecure-512` preset. NOT SECURE.
pub fn insecure_512_params() -> Result<Arc<CkksParameters>> {
    fhe::ckks::CkksParametersBuilder::new()
        .set_degree(512)
        .set_moduli_sizes(&[45, 45])
        .set_scale(2f64.powi(40))
        .build_arc()
        .context("failed to build insecure CKKS params")
}

/// Three-limb variant for circuits with one multiplication level (auction
/// masking, statistics sum-of-squares). NOT SECURE.
pub fn insecure_512_mul_params() -> Result<Arc<CkksParameters>> {
    fhe::ckks::CkksParametersBuilder::new()
        .set_degree(512)
        .set_moduli_sizes(&[45, 45, 45])
        .set_scale(2f64.powi(40))
        .build_arc()
        .context("failed to build insecure CKKS mul params")
}
