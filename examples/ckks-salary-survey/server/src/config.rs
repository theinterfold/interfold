// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Server configuration (environment / `server/.env`, like CRISP).

use config::{Config as ConfigManager, ConfigError};
use dotenvy::dotenv;
use once_cell::sync::Lazy;
use serde::Deserialize;

fn default_bind() -> String {
    "0.0.0.0:8091".to_string()
}
fn default_cap() -> u64 {
    500_000
}
fn default_duration() -> u64 {
    120
}
fn default_db() -> String {
    "database/server".to_string()
}

// Do not derive `Debug`: this structure owns the relayer private key.
#[derive(Deserialize, Clone)]
pub struct Config {
    /// Relayer / admin key. Pays gas for every relayed submission and
    /// requests rounds. On anvil: account #0.
    pub private_key: String,
    pub http_rpc_url: String,
    pub ws_rpc_url: String,
    pub chain_id: u64,
    pub interfold_address: String,
    pub ciphernode_registry_address: String,
    pub fee_token_address: String,
    /// `CkksSalaryE3Program` (three-leg Greco + validity gate).
    pub e3_program_address: String,
    /// Where the ciphernodes write the joint relin key
    /// (`<dir>/<chain_id>:<e3_id>/rlk_level_0.bin`). Set the same
    /// `CKKS_RELIN_KEY_DIR` for the nodes, or point this at one node's
    /// `<data dir>/<node>/ckks/relin-keys`.
    pub relin_key_dir: String,
    /// Public normalization cap (must equal the program's `salaryCap`).
    #[serde(default = "default_cap")]
    pub salary_cap: u64,
    /// Input window length in seconds for rounds created by the admin route.
    #[serde(default = "default_duration")]
    pub e3_duration: u64,
    /// 0=Minimum, 1=Micro, 2=Small.
    #[serde(default)]
    pub e3_committee_size: u8,
    #[serde(default = "default_bind")]
    pub bind_addr: String,
    #[serde(default = "default_db")]
    pub database_path: String,
    /// Shared secret for admin routes (`x-admin-key` header). Empty = open
    /// (dev only).
    #[serde(default)]
    pub admin_key: String,
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
