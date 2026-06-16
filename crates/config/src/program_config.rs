// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Program execution configuration (RISC Zero / Boundless).
//!
//! Extracted from [`AppConfig`] — these types configure external program
//! execution, not the ciphernode itself.

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct BoundlessConfig {
    pub rpc_url: String,
    pub private_key: String,
    #[serde(default)]
    pub pinata_jwt: Option<String>,
    #[serde(default)]
    pub program_url: Option<String>,
    #[serde(default = "default_true")]
    pub onchain: bool,
    // --- Offer params (all optional, fall back to defaults in build_offer_params) ---
    /// Minimum price in ETH (default: 0.00005)
    #[serde(default)]
    pub min_price_eth: Option<f64>,
    /// Maximum price in ETH (default: 0.002)
    #[serde(default)]
    pub max_price_eth: Option<f64>,
    /// Total timeout in seconds (default: 600 = 10 min)
    #[serde(default)]
    pub timeout_secs: Option<u64>,
    /// Lock timeout in seconds (default: 300 = 5 min)
    #[serde(default)]
    pub lock_timeout_secs: Option<u64>,
    /// Ramp-up period in seconds (default: 60 = 1 min)
    #[serde(default)]
    pub ramp_up_secs: Option<u64>,
    /// Lock collateral in ZKC (default: 2.0)
    #[serde(default)]
    pub lock_collateral_zkc: Option<f64>,
}

fn default_true() -> bool {
    true
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct Risc0Config {
    #[serde(default = "default_risc0_dev_mode")]
    pub risc0_dev_mode: u8,
    #[serde(default)]
    pub boundless: Option<BoundlessConfig>,
}

fn default_risc0_dev_mode() -> u8 {
    1
}

impl Default for Risc0Config {
    fn default() -> Self {
        Risc0Config {
            risc0_dev_mode: 1,
            boundless: None,
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct ProgramConfig {
    risc0: Option<Risc0Config>,
    dev: Option<bool>,
}

impl ProgramConfig {
    pub fn risc0(&self) -> Option<&Risc0Config> {
        self.risc0.as_ref()
    }

    pub fn dev(&self) -> bool {
        self.dev.unwrap_or(false)
    }
}
