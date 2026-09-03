// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use config::{Config as ConfigManager, ConfigError};
use dotenvy::dotenv;
use once_cell::sync::Lazy;
use serde::Deserialize;

/// Server configuration from the environment (`server/.env`).
///
/// Not `Debug`: it holds the round-opener private key.
#[derive(Deserialize)]
pub struct Config {
    /// Round-opener key: requests E3s, sets balance roots, publishes the evaluated ciphertext.
    /// It NEVER sees a bid — bids are sent by bidders from their own wallets.
    pub private_key: String,
    pub http_rpc_url: String,
    pub ws_rpc_url: String,
    pub chain_id: u64,
    pub interfold_address: String,
    /// `CkksAuctionE3Program` — the three-leg gate every bid must pass.
    pub e3_program_address: String,
    pub ciphernode_registry_address: String,
    pub fee_token_address: String,
    /// Seconds the bidding window stays open once the committee key is published.
    #[serde(default = "default_duration")]
    pub e3_duration: u64,
    /// 0=Minimum, 1=Micro, 2=Small.
    #[serde(default)]
    pub e3_committee_size: u8,
    /// Where the ciphernodes write joint relin-ceremony keys. Keys for an E3 live at
    /// `<dir>/<chain_id>:<e3_id>/rlk_level_{level}.bin`. Any honest node's directory works.
    pub ckks_relin_key_dir: String,
    /// Bid bound B (sign-extraction normalisation). Must be ≥ every possible bid.
    #[serde(default = "default_bound")]
    pub bid_bound: f64,
    #[serde(default = "default_bind")]
    pub bind_addr: String,
}

fn default_duration() -> u64 {
    300
}
fn default_bound() -> f64 {
    1000.0
}
fn default_bind() -> String {
    "0.0.0.0:8090".to_string()
}

impl Config {
    pub fn from_env() -> Result<Self, ConfigError> {
        let server_env_path = std::path::Path::new("server/.env");
        if server_env_path.exists() {
            dotenvy::from_path(server_env_path).ok();
        } else {
            dotenv().ok();
        }
        ConfigManager::builder()
            .add_source(config::Environment::default())
            .build()?
            .try_deserialize()
    }
}

pub static CONFIG: Lazy<Config> =
    Lazy::new(|| Config::from_env().expect("Failed to load configuration"));
