// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use config::{Config as ConfigManager, ConfigError, Environment};
use dotenvy::dotenv;
use once_cell::sync::Lazy;
use serde::Deserialize;

const AVAIL_FINALIZATION_WINDOW_SECONDS: u64 = 10_800;
const DEFAULT_DA_PENDING_BYTES: u64 = 1024 * 1024 * 1024;

// Do not derive `Debug`: this structure owns private keys and other secrets.
#[derive(Deserialize)]
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
    /// `mock` for deterministic local tests or `avail` for VectorX-backed publication.
    #[serde(default)]
    pub data_availability_mode: Option<String>,
    #[serde(default)]
    pub avail_rpc_url: Option<String>,
    #[serde(default)]
    pub avail_bridge_api_url: Option<String>,
    #[serde(default)]
    pub avail_app_id: Option<u32>,
    /// Minimum time that must remain before the Ethereum input deadline when an Avail
    /// publication starts. VectorX range proofs are asynchronous, so production must configure
    /// enough headroom for its current bridge cadence and operating margin.
    #[serde(default)]
    pub avail_proof_lead_seconds: Option<u64>,
    /// Avail signer URI. This field is intentionally excluded from debug output with the rest of
    /// this configuration.
    #[serde(default)]
    pub avail_seed: Option<String>,
    /// Maximum bytes the service accepts for unfinished availability jobs.
    #[serde(default = "default_da_pending_bytes")]
    pub data_availability_max_pending_bytes: u64,
    pub cron_api_key: String,
    // E3 parameters
    pub e3_param_set: u8,      // 0=InsecureThreshold512, 1=SecureThreshold8192
    pub e3_committee_size: u8, // 0=Minimum, 1=Micro, 2=Small
    pub e3_duration: u64,
    pub e3_compute_provider_name: String,
    pub e3_compute_provider_parallel: bool,
    pub e3_compute_provider_batch_size: u32,
    /// Optional on localhost and on deployments that do not use Etherscan-backed holder lookup.
    #[serde(default)]
    pub etherscan_api_key: String,
    /// Block to start indexing from on a FRESH database. Absent means "start at the chain head",
    /// which is what this server did before backfill existed — set it to the deployment block of
    /// the watched contracts to build a complete index. Ignored once a cursor is stored: a
    /// restart always resumes from the cursor, replaying exactly the gap.
    #[serde(default)]
    pub index_start_block: Option<u64>,
    /// `eth_getLogs` window for backfill. Lower it if the provider rejects the range.
    #[serde(default)]
    pub index_chunk_size: Option<u64>,
    /// Comma-separated contract addresses the `/chain/*` routes will serve. Empty (the default)
    /// denies every request: a misconfigured deployment must fail closed rather than quietly
    /// become an open RPC endpoint for the whole chain.
    #[serde(default)]
    pub index_contracts: Option<String>,
    /// Whether to believe `Forwarded` / `X-Forwarded-For` when identifying a caller.
    ///
    /// OFF by default, because actix's `realip_remote_addr` implements no trust-proxy logic: it
    /// takes the header at face value. Both rate limiters key their per-caller window on that
    /// value, so with no proxy stripping the header a caller can mint a fresh identity per
    /// request and the window stops bounding anything.
    ///
    /// Set it ONLY when every request reaches this server through a proxy that overwrites those
    /// headers — a CDN or load balancer you control. Behind such a proxy it must be set, or every
    /// caller shares the proxy's address and therefore one window between them.
    #[serde(default)]
    pub trust_proxy_headers: bool,

    /// Comma-separated subset of `INDEX_CONTRACTS` whose LOGS are indexed into the store.
    ///
    /// Separate from the read allowlist on purpose. Serving `eth_call` for a contract is cheap;
    /// retaining every log it emits is not. A high-volume ERC-20 emits thousands of `Transfer`
    /// events per thousand blocks, and indexing those costs storage and write amplification for
    /// data no client queries — the frontends want `DelegateChanged` and `ProposalCreated`, not
    /// transfers. List only the contracts whose event history is actually read; everything else
    /// stays readable but has its (rare) log queries forwarded upstream.
    ///
    /// Empty means no log indexing, which is the safe default: correctness is unaffected, only
    /// latency.
    #[serde(default)]
    pub index_log_contracts: Option<String>,
}

impl Config {
    pub fn data_availability_mode(&self) -> String {
        self.data_availability_mode.clone().unwrap_or_else(|| {
            if matches!(self.chain_id, 1_337 | 31_337) {
                "mock".to_owned()
            } else {
                "avail".to_owned()
            }
        })
    }

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
        let config: Self = ConfigManager::builder()
            // Example files leave optional settings blank. Treat a blank optional value as unset
            // instead of trying to deserialize an empty string as `u32` or `u64`.
            .add_source(Environment::default().ignore_empty(true))
            .build()?
            .try_deserialize()?;
        Self::validate_e3_param_set(config.chain_id, config.e3_param_set)?;
        Self::validate_data_availability(
            config.chain_id,
            &config.data_availability_mode(),
            config
                .avail_proof_lead_seconds
                .unwrap_or(AVAIL_FINALIZATION_WINDOW_SECONDS),
            config.data_availability_max_pending_bytes,
        )?;
        Ok(config)
    }

    fn validate_data_availability(
        chain_id: u64,
        mode: &str,
        proof_lead: u64,
        max_pending_bytes: u64,
    ) -> Result<(), ConfigError> {
        if mode == "mock" {
            if !matches!(chain_id, 1_337 | 31_337) {
                return Err(ConfigError::Message(
                    "DATA_AVAILABILITY_MODE=mock is allowed only on local development chains"
                        .to_owned(),
                ));
            }
            return Ok(());
        }
        if mode != "avail" {
            return Err(ConfigError::Message(format!(
                "unsupported DATA_AVAILABILITY_MODE '{mode}'"
            )));
        }
        if proof_lead == 0 {
            return Err(ConfigError::Message(
                "AVAIL_PROOF_LEAD_SECONDS must be greater than zero".to_owned(),
            ));
        }
        if max_pending_bytes < e3_data_availability::MAX_OBJECT_BYTES as u64 {
            return Err(ConfigError::Message(format!(
                "DATA_AVAILABILITY_MAX_PENDING_BYTES must be at least {}",
                e3_data_availability::MAX_OBJECT_BYTES
            )));
        }
        Ok(())
    }

    fn validate_e3_param_set(chain_id: u64, param_set: u8) -> Result<(), ConfigError> {
        if param_set > 1 {
            return Err(ConfigError::Message(format!(
                "E3_PARAM_SET must be 0 (insecure-512) or 1 (secure-8192), got {param_set}"
            )));
        }
        if chain_id == 1 && param_set != 1 {
            return Err(ConfigError::Message(
                "Ethereum mainnet requires E3_PARAM_SET=1 (secure-8192)".to_owned(),
            ));
        }
        Ok(())
    }
}

const fn default_da_pending_bytes() -> u64 {
    DEFAULT_DA_PENDING_BYTES
}

pub static CONFIG: Lazy<Config> =
    Lazy::new(|| Config::from_env().expect("Failed to load configuration"));

#[cfg(test)]
mod tests {
    use super::Config;
    use config::{Config as ConfigManager, Environment};
    use serde_json::json;
    use std::collections::HashMap;

    #[derive(serde::Deserialize)]
    struct OptionalAvailConfig {
        avail_app_id: Option<u32>,
    }

    #[test]
    fn accepts_both_testnet_parameter_sets() {
        assert!(Config::validate_e3_param_set(11_155_111, 0).is_ok());
        assert!(Config::validate_e3_param_set(11_155_111, 1).is_ok());
    }

    #[test]
    fn requires_secure_parameters_on_mainnet() {
        assert!(Config::validate_e3_param_set(1, 1).is_ok());
        assert!(Config::validate_e3_param_set(1, 0).is_err());
    }

    #[test]
    fn rejects_unknown_parameter_sets() {
        assert!(Config::validate_e3_param_set(31_337, 2).is_err());
    }

    #[test]
    fn avail_requires_a_nonzero_proof_lead() {
        assert!(Config::validate_data_availability(31_337, "mock", 0, 0).is_ok());
        assert!(Config::validate_data_availability(1, "avail", 10_800, 1024 * 1024).is_ok());
        assert!(Config::validate_data_availability(1, "avail", 0, 1024 * 1024).is_err());
        assert!(Config::validate_data_availability(1, "avail", 10_800, 1024).is_err());
    }

    #[test]
    fn mock_data_availability_is_local_only() {
        assert!(Config::validate_data_availability(1, "mock", 0, 0).is_err());
        assert!(Config::validate_data_availability(11_155_111, "mock", 0, 0).is_err());
        assert!(Config::validate_data_availability(1_337, "mock", 0, 0).is_ok());
        assert!(Config::validate_data_availability(31_337, "mock", 0, 0).is_ok());
    }

    #[test]
    fn blank_optional_environment_value_is_unset() {
        let source = Environment::default()
            .ignore_empty(true)
            .source(Some(HashMap::from([(
                "AVAIL_APP_ID".to_owned(),
                String::new(),
            )])));
        let config: OptionalAvailConfig = ConfigManager::builder()
            .add_source(source)
            .build()
            .unwrap()
            .try_deserialize()
            .unwrap();
        assert_eq!(config.avail_app_id, None);
    }

    #[test]
    fn etherscan_key_defaults_to_empty() {
        let config: Config = serde_json::from_value(json!({
            "program_server_url": "http://127.0.0.1:3000",
            "interfold_server_url": "http://127.0.0.1:4000",
            "private_key": "test-key",
            "http_rpc_url": "http://127.0.0.1:8545",
            "ws_rpc_url": "ws://127.0.0.1:8545",
            "interfold_address": "0x1",
            "e3_program_address": "0x2",
            "ciphernode_registry_address": "0x3",
            "fee_token_address": "0x4",
            "chain_id": 31_337,
            "cron_api_key": "test-cron-key",
            "e3_param_set": 0,
            "e3_committee_size": 0,
            "e3_duration": 3_600,
            "e3_compute_provider_name": "test",
            "e3_compute_provider_parallel": false,
            "e3_compute_provider_batch_size": 1
        }))
        .unwrap();

        assert!(config.etherscan_api_key.is_empty());
    }
}
