// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use std::path::Path;
use std::sync::LazyLock;

use alloy::primitives::{
    utils::{ParseUnits, Unit},
    Address, U256,
};
use alloy::providers::Provider;
use config::{Config as ConfigManager, ConfigError, Environment};
use log::warn;
use serde::Deserialize;

use crate::server::rpc;

/// Default for `AVAIL_PROOF_LEAD_SECONDS`: the Avail finalization window.
const AVAIL_FINALIZATION_WINDOW_SECONDS: u64 = 10_800;

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
    /// Eligibility token for CRISP rounds (`MockVotingToken` on localhost); the CLI falls back to
    /// `deployed_contracts.json` when it is unset.
    #[serde(default)]
    pub crisp_voting_token: Option<String>,
    pub chain_id: u64,
    /// `mock` (local chains only) or `avail`. Defaults by chain.
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
    /// enough headroom for its bridge cadence.
    #[serde(default)]
    pub avail_proof_lead_seconds: Option<u64>,
    /// Avail signer URI.
    #[serde(default)]
    pub avail_seed: Option<String>,
    /// Maximum bytes the service accepts for unfinished availability jobs.
    #[serde(default = "default_da_pending_bytes")]
    pub data_availability_max_pending_bytes: u64,
    /// Shared secret for the round-scheduler endpoint. Absent disables the endpoint.
    #[serde(default)]
    pub cron_api_key: Option<String>,
    // E3 parameters
    pub e3_param_set: u8,      // 0=InsecureThreshold512, 2=SecureThreshold8192
    pub e3_committee_size: u8, // 0=Minimum, 1=Micro, 2=Small
    pub e3_duration: u64,
    /// Time allowed for the E3 request transaction to be mined before voting can start.
    #[serde(default = "default_voting_start_buffer_seconds")]
    pub voting_start_buffer_seconds: u64,
    pub e3_compute_provider_name: String,
    pub e3_compute_provider_parallel: bool,
    pub e3_compute_provider_batch_size: u32,
    /// Optional on localhost and on deployments that do not use Etherscan-backed holder lookup.
    #[serde(default)]
    pub etherscan_api_key: String,
    /// Block to start indexing from on a fresh database; absent starts at the chain head. A
    /// stored cursor wins on restart.
    #[serde(default)]
    pub index_start_block: Option<u64>,
    /// `eth_getLogs` window for backfill. Lower it if the provider rejects the range.
    #[serde(default)]
    pub index_chunk_size: Option<u64>,
    /// Comma-separated contract addresses the `/chain/*` routes serve. Empty denies every
    /// request: a misconfigured deployment fails closed instead of becoming an open RPC endpoint.
    #[serde(default)]
    pub index_contracts: Option<String>,
    /// Whether to believe `Forwarded` / `X-Forwarded-For` when identifying a caller.
    ///
    /// Off by default: actix takes the header at face value, so without a proxy that overwrites
    /// it a caller can mint a fresh identity per request and the per-caller rate windows bound
    /// nothing. Set it only when every request passes through such a proxy; behind one it must
    /// be set, or every caller shares the proxy's address and one window.
    #[serde(default)]
    pub trust_proxy_headers: bool,

    /// Comma-separated subset of `INDEX_CONTRACTS` whose logs are indexed into the store.
    ///
    /// Serving `eth_call` for a contract is cheap, retaining every log is not: list only the
    /// contracts whose event history clients read. Other contracts stay readable and their log
    /// queries go upstream. Empty means no log indexing; correctness is unaffected.
    #[serde(default)]
    pub index_log_contracts: Option<String>,

    /// Relay input commitments on Ethereum mainnet. Off by default; other chains always relay.
    #[serde(default)]
    pub mainnet_relay: bool,
    /// Relayed input commitments per voting slot per round. Zero turns the relay off.
    #[serde(default = "default_relay_max_inputs_per_slot")]
    pub relay_max_inputs_per_slot: u32,
    /// Relayed input commitments per round. Absent means no limit; zero turns the relay off.
    #[serde(default)]
    pub relay_max_inputs_per_round: Option<u32>,
    /// Stop relaying while the server key holds less than this ETH amount, so that the key keeps
    /// funds for `finalizeInput`. Absent or zero means no floor; `validate_relay` limits both.
    #[serde(default)]
    pub relay_min_balance_eth: Option<String>,
}

impl Config {
    pub fn data_availability_mode(&self) -> String {
        self.data_availability_mode.clone().unwrap_or_else(|| {
            if self.is_local_chain() {
                "mock"
            } else {
                "avail"
            }
            .to_owned()
        })
    }

    /// Whether `CHAIN_ID` is a local development chain.
    pub fn is_local_chain(&self) -> bool {
        is_local_chain_id(self.chain_id)
    }

    /// `AVAIL_PROOF_LEAD_SECONDS`, or the Avail finalization window when it is unset.
    pub fn avail_proof_lead(&self) -> u64 {
        self.avail_proof_lead_seconds
            .unwrap_or(AVAIL_FINALIZATION_WINDOW_SECONDS)
    }

    /// The `INDEX_CONTRACTS` read allowlist. `from_env` refuses a malformed entry.
    pub fn index_contracts(&self) -> Vec<Address> {
        parse_addresses("INDEX_CONTRACTS", self.index_contracts.as_deref()).unwrap_or_default()
    }

    /// The `INDEX_LOG_CONTRACTS` log-index list. `from_env` refuses a malformed entry.
    pub fn index_log_contracts(&self) -> Vec<Address> {
        parse_addresses("INDEX_LOG_CONTRACTS", self.index_log_contracts.as_deref())
            .unwrap_or_default()
    }

    /// Base URL for outbound HTTP clients (program-server webhooks, CLI, cron). `0.0.0.0` and
    /// `::` are bind addresses only; connecting to them fails (for example `EADDRNOTAVAIL` on
    /// macOS).
    pub fn interfold_server_url_for_clients(&self) -> String {
        self.interfold_server_url
            .replace("0.0.0.0", "127.0.0.1")
            .replace("[::]", "[::1]")
    }

    pub fn from_env() -> Result<Self, ConfigError> {
        let server_env_path = Path::new("server/.env");
        let loaded = if server_env_path.exists() {
            dotenvy::from_path(server_env_path)
        } else {
            dotenvy::dotenv().map(drop)
        };
        if let Err(e) = loaded {
            if !e.not_found() {
                warn!("Ignoring a malformed .env file: {e}");
            }
        }

        let config: Self = ConfigManager::builder()
            // Example files leave optional settings blank: a blank value is unset, not an empty
            // string to deserialize as a number.
            .add_source(Environment::default().ignore_empty(true))
            .build()?
            .try_deserialize()?;
        Self::validate_e3_param_set(config.chain_id, config.e3_param_set)?;
        if config.e3_committee_size > 2 {
            return Err(invalid(format!(
                "E3_COMMITTEE_SIZE must be 0 (Minimum), 1 (Micro) or 2 (Small), got {}",
                config.e3_committee_size
            )));
        }
        parse_addresses("INDEX_CONTRACTS", config.index_contracts.as_deref())?;
        parse_addresses("INDEX_LOG_CONTRACTS", config.index_log_contracts.as_deref())?;
        Self::validate_data_availability(
            config.chain_id,
            &config.data_availability_mode(),
            config.avail_proof_lead(),
            config.data_availability_max_pending_bytes,
        )?;
        Self::validate_relay(
            config.chain_id,
            config.mainnet_relay,
            config.relay_max_inputs_per_round,
            config.relay_min_balance()?,
        )?;
        Ok(config)
    }

    /// Refuse an `HTTP_RPC_URL` that serves a chain other than `CHAIN_ID`.
    ///
    /// The chain rules of this server (the mainnet relay flag, the secure parameter set, the
    /// local-only mock data availability) read `CHAIN_ID`, while every transaction goes to the
    /// chain of the RPC. For example, `CHAIN_ID=11155111` with a mainnet RPC would relay on
    /// mainnet without `MAINNET_RELAY`.
    pub async fn validate_rpc_chain(&self) -> anyhow::Result<()> {
        let provider = rpc::http_provider(&self.http_rpc_url).map_err(anyhow::Error::msg)?;
        let rpc_chain_id = provider.get_chain_id().await?;
        anyhow::ensure!(
            rpc_chain_id == self.chain_id,
            "CHAIN_ID ({}) does not match the chain of HTTP_RPC_URL ({rpc_chain_id})",
            self.chain_id
        );
        Ok(())
    }

    /// The relay balance floor in wei, from `RELAY_MIN_BALANCE_ETH`.
    pub fn relay_min_balance(&self) -> Result<Option<U256>, ConfigError> {
        Self::parse_relay_min_balance(self.relay_min_balance_eth.as_deref())
    }

    /// Parse a non-negative ETH amount into wei. `parse_ether` alone is not enough: it returns the
    /// absolute value of a negative amount.
    fn parse_relay_min_balance(value: Option<&str>) -> Result<Option<U256>, ConfigError> {
        let Some(value) = value else {
            return Ok(None);
        };
        match ParseUnits::parse_units(value.trim(), Unit::ETHER) {
            Ok(ParseUnits::U256(wei)) => Ok(Some(wei)),
            _ => Err(invalid(format!(
                "RELAY_MIN_BALANCE_ETH must be a non-negative ETH amount, got '{value}'"
            ))),
        }
    }

    /// Refuse a relay without an explicit balance floor outside local chains, and a mainnet relay
    /// that has no round limit or no floor above zero.
    ///
    /// The relay key also pays for `finalizeInput`, so the operator chooses its floor; zero relays
    /// without one. Mainnet relay spends real funds, and the slot limit alone does not bound the
    /// spend of one round.
    fn validate_relay(
        chain_id: u64,
        mainnet_relay: bool,
        max_inputs_per_round: Option<u32>,
        min_balance: Option<U256>,
    ) -> Result<(), ConfigError> {
        if min_balance.is_none() && chain_id != 1 && !is_local_chain_id(chain_id) {
            return Err(invalid(
                "RELAY_MIN_BALANCE_ETH is required outside local chains; set 0 to relay without a floor",
            ));
        }
        if chain_id != 1 || !mainnet_relay {
            return Ok(());
        }
        if max_inputs_per_round.is_none() {
            return Err(invalid(
                "MAINNET_RELAY=true requires RELAY_MAX_INPUTS_PER_ROUND",
            ));
        }
        if min_balance.is_none_or(|floor| floor.is_zero()) {
            return Err(invalid(
                "MAINNET_RELAY=true requires RELAY_MIN_BALANCE_ETH greater than zero",
            ));
        }
        Ok(())
    }

    fn validate_data_availability(
        chain_id: u64,
        mode: &str,
        proof_lead: u64,
        max_pending_bytes: u64,
    ) -> Result<(), ConfigError> {
        match mode {
            "mock" if is_local_chain_id(chain_id) => return Ok(()),
            "mock" => {
                return Err(invalid(
                    "DATA_AVAILABILITY_MODE=mock is allowed only on local development chains",
                ))
            }
            "avail" => {}
            _ => {
                return Err(invalid(format!(
                    "unsupported DATA_AVAILABILITY_MODE '{mode}'"
                )))
            }
        }
        if proof_lead == 0 {
            return Err(invalid(
                "AVAIL_PROOF_LEAD_SECONDS must be greater than zero",
            ));
        }
        if max_pending_bytes < e3_data_availability::MAX_OBJECT_BYTES as u64 {
            return Err(invalid(format!(
                "DATA_AVAILABILITY_MAX_PENDING_BYTES must be at least {}",
                e3_data_availability::MAX_OBJECT_BYTES
            )));
        }
        Ok(())
    }

    fn validate_e3_param_set(chain_id: u64, param_set: u8) -> Result<(), ConfigError> {
        if param_set != 0 && param_set != 2 {
            return Err(invalid(format!(
                "E3_PARAM_SET must be 0 (insecure-512) or 2 (secure-8192), got {param_set}"
            )));
        }
        if chain_id == 1 && param_set != 2 {
            return Err(invalid(
                "Ethereum mainnet requires E3_PARAM_SET=2 (secure-8192)",
            ));
        }
        Ok(())
    }
}

const fn is_local_chain_id(chain_id: u64) -> bool {
    matches!(chain_id, 1_337 | 31_337)
}

fn invalid(message: impl Into<String>) -> ConfigError {
    ConfigError::Message(message.into())
}

/// A comma-separated address list. Blank entries are ignored.
fn parse_addresses(name: &str, list: Option<&str>) -> Result<Vec<Address>, ConfigError> {
    list.unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .map(|entry| {
            entry
                .parse()
                .map_err(|_| invalid(format!("{name} entry '{entry}' is not an address")))
        })
        .collect()
}

const fn default_da_pending_bytes() -> u64 {
    1024 * 1024 * 1024
}

const fn default_voting_start_buffer_seconds() -> u64 {
    120
}

const fn default_relay_max_inputs_per_slot() -> u32 {
    3
}

/// Loaded on first use; a missing or invalid setting stops the process with its message.
pub static CONFIG: LazyLock<Config> =
    LazyLock::new(|| Config::from_env().expect("Failed to load configuration"));

#[cfg(test)]
mod tests {
    use super::Config;
    use config::{Config as ConfigManager, Environment};
    use std::collections::HashMap;

    #[derive(serde::Deserialize)]
    struct OptionalAvailConfig {
        avail_app_id: Option<u32>,
    }

    #[test]
    fn param_sets_are_limited_and_mainnet_requires_the_secure_one() {
        assert!(Config::validate_e3_param_set(11_155_111, 0).is_ok());
        assert!(Config::validate_e3_param_set(11_155_111, 2).is_ok());
        assert!(Config::validate_e3_param_set(1, 2).is_ok());
        assert!(Config::validate_e3_param_set(1, 0).is_err());
        assert!(Config::validate_e3_param_set(31_337, 1).is_err());
        assert!(Config::validate_e3_param_set(31_337, 3).is_err());
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
    fn relay_needs_a_round_limit_on_mainnet_and_a_chosen_floor_off_local_chains() {
        let floor = Some(alloy::primitives::U256::from(1));
        assert!(Config::validate_relay(1, true, None, floor).is_err());
        assert!(Config::validate_relay(1, true, Some(500), None).is_err());
        // A zero floor never stops the relay, so it is not a floor.
        assert!(
            Config::validate_relay(1, true, Some(500), Some(alloy::primitives::U256::ZERO))
                .is_err()
        );
        assert!(Config::validate_relay(1, true, Some(500), floor).is_ok());
        // Without the flag, mainnet does not relay, so it needs no round limit and no floor.
        assert!(Config::validate_relay(1, false, None, None).is_ok());
        // Other chains relay without the flag and can leave the round unlimited, but the operator
        // must choose the floor: zero relays without one. Local chains need no floor.
        assert!(Config::validate_relay(11_155_111, false, None, None).is_err());
        let no_floor = Some(alloy::primitives::U256::ZERO);
        assert!(Config::validate_relay(11_155_111, false, None, no_floor).is_ok());
        assert!(Config::validate_relay(31_337, false, None, None).is_ok());
    }

    #[test]
    fn relay_balance_floor_is_a_non_negative_eth_amount() {
        assert_eq!(Config::parse_relay_min_balance(None).unwrap(), None);
        assert_eq!(
            Config::parse_relay_min_balance(Some("0.5")).unwrap(),
            Some(alloy::primitives::U256::from(500_000_000_000_000_000_u128))
        );
        // `parse_ether` alone would read this as a floor of 1 ETH.
        assert!(Config::parse_relay_min_balance(Some("-1")).is_err());
        assert!(Config::parse_relay_min_balance(Some("half")).is_err());
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

    /// Localhost and deployments without Etherscan discovery or the round scheduler set only the
    /// required keys; every other key must stay optional.
    #[test]
    fn only_the_required_keys_must_be_set() {
        let config: Config = serde_json::from_value(serde_json::json!({
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
            "e3_param_set": 0,
            "e3_committee_size": 0,
            "e3_duration": 3_600,
            "e3_compute_provider_name": "test",
            "e3_compute_provider_parallel": false,
            "e3_compute_provider_batch_size": 1
        }))
        .unwrap();

        assert!(config.etherscan_api_key.is_empty());
        assert_eq!(config.cron_api_key, None);
        assert_eq!(config.voting_start_buffer_seconds, 120);
        assert_eq!(config.relay_max_inputs_per_slot, 3);
    }
}
