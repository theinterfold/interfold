// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use e3_fhe_params::decode_bfv_params_arc;
use e3_utils::utility_types::ArcBytes;
use fhe::bfv::BfvParameters;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Convenience struct for holding threshold BFV configuration parameters
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TrBFVConfig {
    /// BFV Params
    params: ArcBytes,
    /// Number of ciphernodes
    num_parties: u64,
    /// Threshold required
    threshold: u64,
}

impl TrBFVConfig {
    /// Constructor for the TrBFVConfig
    pub fn new(params: ArcBytes, num_parties: u64, threshold: u64) -> Self {
        Self {
            params,
            num_parties,
            threshold,
        }
    }

    pub fn params(&self) -> Arc<BfvParameters> {
        decode_bfv_params_arc(&self.params).expect("Failed to decode BFV params")
    }

    pub fn num_parties(&self) -> u64 {
        self.num_parties
    }

    pub fn threshold(&self) -> u64 {
        self.threshold
    }
}
