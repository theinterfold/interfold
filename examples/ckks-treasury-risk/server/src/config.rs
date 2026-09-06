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
    /// Round-opener key: requests E3s, registers the weights + DAO list, publishes the
    /// evaluated ciphertext. It NEVER sees an exposure vector or a mask — submissions are sent
    /// by each DAO from its own wallet and the plaintexts never leave the browser.
    pub private_key: String,
    pub http_rpc_url: String,
    pub ws_rpc_url: String,
    pub chain_id: u64,
    pub interfold_address: String,
    /// `CkksTreasuryE3Program` — the seven-leg gate every submission must pass.
    pub e3_program_address: String,
    pub ciphernode_registry_address: String,
    pub fee_token_address: String,
    /// Where the ciphernodes write the joint relin key
    /// (`<dir>/<chain_id>:<e3_id>/rlk_level_0.bin`). Set the same
    /// `CKKS_RELIN_KEY_DIR` for the nodes, or point this at one node's
    /// `<data dir>/<node>/ckks/relin-keys`.
    pub relin_key_dir: String,
    /// Seconds the submission window stays open once the committee key is published.
    #[serde(default = "default_duration")]
    pub e3_duration: u64,
    /// 0=Minimum, 1=Micro, 2=Small.
    #[serde(default)]
    pub e3_committee_size: u8,
    #[serde(default = "default_bind")]
    pub bind_addr: String,
}

fn default_duration() -> u64 {
    300
}
fn default_bind() -> String {
    "0.0.0.0:8094".to_string()
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
