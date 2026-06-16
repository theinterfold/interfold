// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use config::{Config as ConfigManager, ConfigError};
use dotenvy::dotenv;
use once_cell::sync::Lazy;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct Config {
    pub program_server_url: String,
    pub interfold_server_url: String,
    pub private_key: String,
    pub http_rpc_url: String,
    pub ws_rpc_url: String,
    pub interfold_address: String,
    pub e3_program_address: String,
    pub ciphernode_registry_address: String,
    pub fee_token_address: String,
    /// Eligibility token for CRISP rounds (`MockVotingToken` on localhost). Falls back to
    /// `packages/crisp-contracts/deployed_contracts.json` when CLI init uses `0x0`.
    #[serde(default)]
    pub crisp_voting_token: Option<String>,
    pub chain_id: u64,
    pub cron_api_key: String,
    // E3 parameters
    #[serde(default)]
    pub e3_proof_aggregation_enabled: bool,
    pub e3_committee_size: u8, // 0=Minimum, 1=Micro, 2=Small
    pub e3_duration: u64,
    pub e3_compute_provider_name: String,
    pub e3_compute_provider_parallel: bool,
    pub e3_compute_provider_batch_size: u32,
    pub etherscan_api_key: String,
}

impl Config {
    /// Base URL for outbound HTTP clients (program-server webhooks, CLI, cron).
    ///
    /// `0.0.0.0` / `::` are bind addresses only; connecting to them fails (e.g. macOS `EADDRNOTAVAIL`).
    pub fn interfold_server_url_for_clients(&self) -> String {
        Self::client_connectable_url(&self.interfold_server_url)
    }

    fn client_connectable_url(url: &str) -> String {
        url.replace("0.0.0.0", "127.0.0.1").replace("[::]", "[::1]")
    }

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
