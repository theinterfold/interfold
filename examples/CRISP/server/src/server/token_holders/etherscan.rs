// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::server::models::TokenHolder;
use alloy::primitives::{Address, U256};
use alloy::providers::ProviderBuilder;
use alloy::sol;
use eyre::{eyre, Context, Result}; // Add this import
use reqwest;
use serde::Deserialize;
use std::collections::{HashMap, HashSet};
use tokio::time::{sleep, Duration};

// Define the Votes contract interface for getPastVotes
sol! {
    #[derive(Debug)]
    #[sol(rpc)]
    contract ERC20Votes {
        function getPastVotes(address account, uint256 timepoint) external view returns (uint256);
        function balanceOf(address account) external view returns (uint256);
        function decimals() external view returns (uint8);
    }
}

// Config
pub const ETHERSCAN_API_URL: &str = "https://api.etherscan.io/v2/api";
const ZERO_ADDRESS: Address = Address::ZERO;

// Response types
#[derive(Debug, Deserialize)]
struct EtherscanResponse<T> {
    status: String,
    message: String,
    result: Option<T>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ContractCreation {
    block_number: String,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct TransferLog {
    pub address: String,
    pub topics: Vec<String>,
    pub data: String,
    pub block_number: String,
    pub transaction_hash: String,
    pub transaction_index: String,
    pub block_hash: String,
    pub log_index: String,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct DelegateVotesChangedLog {
    pub address: String,
    pub topics: Vec<String>,
    pub data: String,
    pub block_number: String,
    pub transaction_hash: String,
    pub transaction_index: String,
    pub block_hash: String,
    pub log_index: String,
}

/// Represents an address that may have voting power
#[derive(Debug, Clone)]
pub struct PotentialVoter {
    pub address: Address,
    pub token_balance: U256,
    pub has_delegation: bool,
}

/// Client for querying token holder data from Etherscan API.
pub struct EtherscanClient {
    client: reqwest::Client,
    api_key: String,
    chain_id: u64,
}

impl EtherscanClient {
    /// Create a new EtherscanClient instance
    pub fn new(api_key: String, chain_id: u64) -> Self {
        Self {
            client: reqwest::Client::new(),
            api_key,
            chain_id,
        }
    }

    /// Get the deployment block number for a contract
    pub async fn get_deployment_block(&self, token: &str) -> Result<u64> {
        let url = format!(
            "{}?module=contract&action=getcontractcreation&contractaddresses={}&chainid={}&apikey={}",
            ETHERSCAN_API_URL, token, self.chain_id, self.api_key
        );

        let response = self
            .client
            .get(&url)
            .send()
            .await
            .context("Failed to send request to Etherscan")?;
        let data: EtherscanResponse<Vec<ContractCreation>> = response
            .json()
            .await
            .context("Failed to parse Etherscan response")?;

        if data.status != "1" {
            return Err(eyre!("Deployment block not found: {}", data.message));
        }

        let result = data
            .result
            .and_then(|r| r.into_iter().next())
            .ok_or_else(|| eyre!("No deployment data found"))?;

        // Parse block number (could be hex or decimal)
        let block_number = if result.block_number.starts_with("0x") {
            u64::from_str_radix(&result.block_number[2..], 16)
                .context("Failed to parse hex block number")?
        } else {
            result
                .block_number
                .parse::<u64>()
                .context("Failed to parse decimal block number")?
        };

        Ok(block_number)
    }

    /// Get transfer logs for a token
    pub async fn get_transfer_logs(
        &self,
        token: &str,
        from_block: u64,
        to_block: u64,
    ) -> Result<Vec<TransferLog>> {
        let mut all_logs = Vec::new();
        let mut page = 1;

        // ERC20 Transfer event signature
        let transfer_topic = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";

        loop {
            let url = format!(
                "{}?module=logs&action=getLogs&address={}&fromBlock={}&toBlock={}&topic0={}&page={}&offset=10000&chainid={}&apikey={}",
                ETHERSCAN_API_URL, token, from_block, to_block, transfer_topic, page, self.chain_id, self.api_key
            );

            let response = self
                .client
                .get(&url)
                .send()
                .await
                .context("Failed to fetch transfer logs")?;
            let data: EtherscanResponse<Vec<TransferLog>> = response
                .json()
                .await
                .context("Failed to parse transfer logs response")?;

            // Break if request failed
            if data.status != "1" {
                if data.message.eq_ignore_ascii_case("No records found") {
                    break;
                }

                return Err(eyre!(
                    "Etherscan getLogs failed on page {}: {}",
                    page,
                    data.message
                ));
            }

            // Break if no results
            let logs = match data.result {
                Some(logs) if !logs.is_empty() => logs,
                _ => break,
            };

            let log_count = logs.len();
            all_logs.extend(logs);

            // Break if we got less than the max page size
            if log_count < 10000 {
                break;
            }

            page += 1;

            // Rate limiting - wait 100ms between requests
            sleep(Duration::from_millis(100)).await;
        }

        Ok(all_logs)
    }

    /// Get DelegateVotesChanged logs for a token
    pub async fn get_delegate_votes_changed_logs(
        &self,
        token: &str,
        from_block: u64,
        to_block: u64,
    ) -> Result<Vec<DelegateVotesChangedLog>> {
        let mut all_logs = Vec::new();
        let mut page = 1;

        // DelegateVotesChanged event signature
        let delegate_votes_changed_topic =
            "0xdec2bacdd2f05b59de34da9b523dff8be42e5e38e8af2ade71e1ddfc5c9f0e6f";

        loop {
            let url = format!(
                "{}?module=logs&action=getLogs&address={}&fromBlock={}&toBlock={}&topic0={}&page={}&offset=10000&chainid={}&apikey={}",
                ETHERSCAN_API_URL, token, from_block, to_block, delegate_votes_changed_topic, page, self.chain_id, self.api_key
            );

            let response = self
                .client
                .get(&url)
                .send()
                .await
                .context("Failed to fetch delegation logs")?;
            let data: EtherscanResponse<Vec<DelegateVotesChangedLog>> = response
                .json()
                .await
                .context("Failed to parse delegation logs response")?;

            // Break if request failed
            if data.status != "1" {
                if data.message.eq_ignore_ascii_case("No records found") {
                    break;
                }

                return Err(eyre!(
                    "Etherscan getLogs failed on page {}: {}",
                    page,
                    data.message
                ));
            }

            // Break if no results
            let logs = match data.result {
                Some(logs) if !logs.is_empty() => logs,
                _ => break,
            };

            let log_count = logs.len();
            all_logs.extend(logs);

            // Break if we got less than the max page size
            if log_count < 10000 {
                break;
            }

            page += 1;

            // Rate limiting - wait 100ms between requests
            sleep(Duration::from_millis(100)).await;
        }

        Ok(all_logs)
    }

    /// Get all potential voters by combining token holders and delegates
    pub fn get_potential_voters(
        &self,
        transfer_logs: &[TransferLog],
        delegation_logs: &[DelegateVotesChangedLog],
    ) -> Vec<PotentialVoter> {
        let balances = Self::compute_balances_from_logs(transfer_logs);
        let delegates: HashSet<Address> = Self::extract_delegates(delegation_logs)
            .into_iter()
            .collect();

        let mut potential_voters = HashMap::new();

        // Add all token holders
        for (address, balance) in balances.iter() {
            if *address != ZERO_ADDRESS {
                potential_voters.insert(
                    *address,
                    PotentialVoter {
                        address: *address,
                        token_balance: *balance,
                        has_delegation: delegates.contains(address),
                    },
                );
            }
        }

        // Add any delegates who might not have tokens themselves
        for delegate in delegates.iter() {
            if *delegate != ZERO_ADDRESS {
                potential_voters.entry(*delegate).or_insert(PotentialVoter {
                    address: *delegate,
                    token_balance: U256::ZERO,
                    has_delegation: true,
                });
            }
        }

        potential_voters.into_values().collect()
    }

    /// Verify voting power for multiple addresses
    pub async fn verify_voting_power(
        &self,
        token_address: Address,
        potential_voters: &[PotentialVoter],
        block_number: u64,
        rpc_url: &str,
        threshold: U256,
    ) -> Result<Vec<TokenHolder>> {
        let mut token_holders: Vec<TokenHolder> = Vec::new();

        let decimals = Self::get_decimals(token_address, rpc_url).await?;

        // we want to keep some precision.
        let half_decimals = decimals / 2;

        let scale_factor = U256::from(10u128.pow(half_decimals as u32));

        for voter in potential_voters {
            match Self::get_past_votes(token_address, voter.address, block_number, rpc_url).await {
                Ok(votes) => {
                    if votes >= threshold {
                        let scaled_votes = votes / scale_factor;

                        token_holders.push(TokenHolder {
                            address: voter.address.to_string(),
                            balance: scaled_votes.to_string(),
                        });
                    }
                }
                Err(e) => {
                    log::warn!("Failed to get votes for {}: {}", voter.address, e);
                }
            }

            // Rate limiting - small delay between RPC calls
            sleep(Duration::from_millis(50)).await;
        }

        Ok(token_holders)
    }

    /// Extract unique addresses from transfer logs
    #[cfg(test)]
    fn extract_addresses(logs: &[TransferLog]) -> Vec<Address> {
        let mut addresses = HashSet::new();

        for log in logs {
            if log.topics.len() >= 3 {
                if let Ok(from) = Self::parse_address_from_topic(&log.topics[1]) {
                    if from != ZERO_ADDRESS {
                        addresses.insert(from);
                    }
                }

                if let Ok(to) = Self::parse_address_from_topic(&log.topics[2]) {
                    if to != ZERO_ADDRESS {
                        addresses.insert(to);
                    }
                }
            }
        }

        addresses.into_iter().collect()
    }

    /// Extract delegate addresses from DelegateVotesChanged logs
    fn extract_delegates(logs: &[DelegateVotesChangedLog]) -> Vec<Address> {
        let mut delegates = HashSet::new();

        for log in logs {
            if log.topics.len() >= 2 {
                if let Ok(delegate) = Self::parse_address_from_topic(&log.topics[1]) {
                    if delegate != ZERO_ADDRESS {
                        delegates.insert(delegate);
                    }
                }
            }
        }

        delegates.into_iter().collect()
    }

    /// Compute token balances from transfer logs
    fn compute_balances_from_logs(logs: &[TransferLog]) -> HashMap<Address, U256> {
        let mut balances: HashMap<Address, U256> = HashMap::new();

        // Sort logs by block number
        let mut sorted_logs = logs.to_vec();
        sorted_logs.sort_by(|a, b| {
            let block_a = Self::parse_block_number(&a.block_number);
            let block_b = Self::parse_block_number(&b.block_number);
            block_a.cmp(&block_b)
        });

        for log in sorted_logs {
            if log.topics.len() < 3 {
                continue;
            }

            let from = match Self::parse_address_from_topic(&log.topics[1]) {
                Ok(addr) => addr,
                Err(_) => continue,
            };

            let to = match Self::parse_address_from_topic(&log.topics[2]) {
                Ok(addr) => addr,
                Err(_) => continue,
            };

            let value = Self::parse_transfer_value(&log.data);

            // Update balances
            if from != ZERO_ADDRESS {
                let balance = balances.entry(from).or_insert(U256::ZERO);
                *balance = balance.saturating_sub(value);
            }

            if to != ZERO_ADDRESS {
                let balance = balances.entry(to).or_insert(U256::ZERO);
                *balance = balance.saturating_add(value);
            }
        }

        balances
    }

    /// Verify actual voting power for an address at a specific block
    async fn get_past_votes(
        token_address: Address,
        voter_address: Address,
        block_number: u64,
        rpc_url: &str,
    ) -> Result<U256> {
        let url = rpc_url.parse().context("Failed to parse RPC URL")?;
        let provider = ProviderBuilder::new().connect_http(url);
        let token = ERC20Votes::new(token_address, provider);

        match token
            .getPastVotes(voter_address, U256::from(block_number))
            .call()
            .await
        {
            Ok(votes) => Ok(votes),
            Err(_) => {
                // Fallback to balanceOf if getPastVotes fails
                let balance = token
                    .balanceOf(voter_address)
                    .call()
                    .await
                    .context("Failed to call balanceOf")?;
                Ok(balance)
            }
        }
    }

    /// Get the token decimals
    async fn get_decimals(token_address: Address, rpc_url: &str) -> Result<u8> {
        let url = rpc_url.parse().context("Failed to parse RPC URL")?;
        let provider = ProviderBuilder::new().connect_http(url);
        let token = ERC20Votes::new(token_address, provider);

        let decimals = token
            .decimals()
            .call()
            .await
            .context("Failed to call decimals")?;

        Ok(decimals)
    }

    /// Parse address from 32-byte topic (last 20 bytes)
    fn parse_address_from_topic(topic: &str) -> Result<Address, String> {
        let hex = topic.strip_prefix("0x").unwrap_or(topic);

        if hex.len() >= 40 {
            let addr_hex = &hex[hex.len() - 40..];
            addr_hex
                .parse::<Address>()
                .map_err(|e| format!("Failed to parse address: {}", e))
        } else {
            Err("Topic too short".to_string())
        }
    }

    /// Parse block number from hex or decimal string
    fn parse_block_number(block_number: &str) -> u64 {
        if let Some(hex) = block_number.strip_prefix("0x") {
            u64::from_str_radix(hex, 16).unwrap_or(0)
        } else {
            block_number.parse::<u64>().unwrap_or(0)
        }
    }

    /// Parse transfer value from hex data string
    fn parse_transfer_value(data: &str) -> U256 {
        let hex_data = data.strip_prefix("0x").unwrap_or(data);
        U256::from_str_radix(hex_data, 16).unwrap_or(U256::ZERO)
    }

    /// Get all token holders with voting power at a specific block
    pub async fn get_token_holders_with_voting_power(
        &self,
        token_address: Address,
        snapshot_block: u64,
        rpc_url: &str,
        threshold: U256,
    ) -> Result<Vec<TokenHolder>> {
        log::info!("Starting token holder discovery for {}", token_address);

        // Step 1: Determine starting block
        let start_block = self
            .get_deployment_block(&token_address.to_string())
            .await
            .context("Failed to get deployment block")?;
        log::info!("Token deployed at block: {}", start_block);

        // Step 2: Fetch transfer logs
        log::info!(
            "Fetching transfer logs from block {} to {}...",
            start_block,
            snapshot_block
        );
        let transfer_logs = self
            .get_transfer_logs(&token_address.to_string(), start_block, snapshot_block)
            .await
            .context("Failed to fetch transfer logs")?;
        log::info!("Found {} transfer events", transfer_logs.len());

        // Step 3: Fetch delegation logs
        log::info!("Fetching delegation logs...");
        let delegation_logs = self
            .get_delegate_votes_changed_logs(
                &token_address.to_string(),
                start_block,
                snapshot_block,
            )
            .await
            .context("Failed to fetch delegation logs")?;
        log::info!("Found {} delegation events", delegation_logs.len());

        // Step 4: Identify potential voters
        log::info!("Identifying potential voters...");
        let potential_voters = self.get_potential_voters(&transfer_logs, &delegation_logs);
        log::info!("Found {} potential voters", potential_voters.len());

        // Step 5: Verify actual voting power
        log::info!("Verifying voting power at block {}...", snapshot_block);
        let token_holders = self
            .verify_voting_power(
                token_address,
                &potential_voters,
                snapshot_block,
                rpc_url,
                threshold,
            )
            .await
            .context("Failed to verify voting power")?;

        log::info!(
            "Discovery complete: {} addresses with voting power above threshold",
            token_holders.len()
        );

        Ok(token_holders)
    }

    /// Get all token holders with a constant balance
    /// Returns all addresses that either have a token balance or have delegation,
    /// with their balance set to the provided constant value.
    /// No RPC verification - eligibility is based purely on log analysis.
    pub async fn get_token_holders_with_constant_balance(
        &self,
        token_address: Address,
        snapshot_block: u64,
        balance: U256,
    ) -> Result<Vec<TokenHolder>> {
        log::info!(
            "Starting token holder discovery (constant balance) for {}",
            token_address
        );

        // Step 1: Determine starting block
        let start_block = self
            .get_deployment_block(&token_address.to_string())
            .await
            .context("Failed to get deployment block")?;
        log::info!("Token deployed at block: {}", start_block);

        // Step 2: Fetch transfer logs
        log::info!(
            "Fetching transfer logs from block {} to {}...",
            start_block,
            snapshot_block
        );
        let transfer_logs = self
            .get_transfer_logs(&token_address.to_string(), start_block, snapshot_block)
            .await
            .context("Failed to fetch transfer logs")?;
        log::info!("Found {} transfer events", transfer_logs.len());

        // Step 3: Fetch delegation logs
        log::info!("Fetching delegation logs...");
        let delegation_logs = self
            .get_delegate_votes_changed_logs(
                &token_address.to_string(),
                start_block,
                snapshot_block,
            )
            .await
            .context("Failed to fetch delegation logs")?;
        log::info!("Found {} delegation events", delegation_logs.len());

        // Step 4: Identify potential voters
        log::info!("Identifying potential voters...");
        let potential_voters = self.get_potential_voters(&transfer_logs, &delegation_logs);
        log::info!("Found {} potential voters", potential_voters.len());

        // Step 5: Convert to token holders with constant balance
        let token_holders: Vec<TokenHolder> = potential_voters
            .into_iter()
            .filter(|v| v.token_balance > U256::ZERO || v.has_delegation)
            .map(|v| TokenHolder {
                address: v.address.to_string(),
                balance: balance.to_string(),
            })
            .collect();

        log::info!(
            "Discovery complete: {} eligible addresses",
            token_holders.len()
        );

        Ok(token_holders)
    }
}

/// Convenience function to get mocked token holder data for testing.
pub fn get_mock_token_holders() -> Vec<TokenHolder> {
    vec![
        TokenHolder {
            address: "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266".to_string(),
            balance: "1".to_string(),
        },
        TokenHolder {
            address: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8".to_string(),
            balance: "1".to_string(),
        },
        TokenHolder {
            address: "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC".to_string(),
            balance: "1".to_string(),
        },
        TokenHolder {
            address: "0x90F79bf6EB2c4f870365E785982E1f101E93b906".to_string(),
            balance: "1".to_string(),
        },
        TokenHolder {
            address: "0x15d34AAf54267DB7D7c367839AAf71A00a2C6A65".to_string(),
            balance: "1".to_string(),
        },
        TokenHolder {
            address: "0x9965507D1a55bcC2695C58ba16FB37d819B0A4dc".to_string(),
            balance: "1".to_string(),
        },
        TokenHolder {
            address: "0x976EA74026E726554dB657fA54763abd0C3a0aa9".to_string(),
            balance: "1".to_string(),
        },
        TokenHolder {
            address: "0x14dC79964da2C08b23698B3D3cc7Ca32193d9955".to_string(),
            balance: "1".to_string(),
        },
        TokenHolder {
            address: "0x23618e81E3f5cdF7f54C3d65f7FBc0aBf5B21E8f".to_string(),
            balance: "1".to_string(),
        },
        TokenHolder {
            address: "0xa0Ee7A142d267C1f36714E4a8F75612F20a79720".to_string(),
            balance: "1".to_string(),
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::CONFIG;

    #[test]
    fn test_extract_addresses() {
        let logs = vec![TransferLog {
            address: "0xtoken".to_string(),
            topics: vec![
                "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef".to_string(),
                "0x000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48".to_string(),
                "0x000000000000000000000000dac17f958d2ee523a2206206994597c13d831ec7".to_string(),
            ],
            data: "0x0000000000000000000000000000000000000000000000000000000000000064".to_string(),
            block_number: "0x1".to_string(),
            transaction_hash: "0xhash".to_string(),
            transaction_index: "0x0".to_string(),
            block_hash: "0xblockhash".to_string(),
            log_index: "0x0".to_string(),
        }];

        let addresses = EtherscanClient::extract_addresses(&logs);
        assert_eq!(addresses.len(), 2);

        let addr1: Address = "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"
            .parse()
            .unwrap();
        let addr2: Address = "0xdac17f958d2ee523a2206206994597c13d831ec7"
            .parse()
            .unwrap();

        assert!(addresses.contains(&addr1));
        assert!(addresses.contains(&addr2));
    }

    #[test]
    fn test_extract_delegates() {
        let logs = vec![
            DelegateVotesChangedLog {
                address: "0xtoken".to_string(),
                topics: vec![
                    "0xdec2bacdd2f05b59de34da9b523dff8be42e5e38e8af2ade71e1ddfc5c9f0e6f".to_string(),
                    "0x000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48".to_string(),
                ],
                data: "0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000064".to_string(),
                block_number: "0x1".to_string(),
                transaction_hash: "0xhash".to_string(),
                transaction_index: "0x0".to_string(),
                block_hash: "0xblockhash".to_string(),
                log_index: "0x0".to_string(),
            },
        ];

        let delegates = EtherscanClient::extract_delegates(&logs);
        assert_eq!(delegates.len(), 1);

        let addr: Address = "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"
            .parse()
            .unwrap();
        assert!(delegates.contains(&addr));
    }

    #[test]
    fn test_compute_balances() {
        let logs = vec![
            TransferLog {
                address: "0xtoken".to_string(),
                topics: vec![
                    "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
                        .to_string(),
                    "0x0000000000000000000000000000000000000000000000000000000000000000"
                        .to_string(), // from: zero address (mint)
                    "0x000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"
                        .to_string(), // to: address A
                ],
                data: "0x0000000000000000000000000000000000000000000000000000000000000064"
                    .to_string(), // 100 tokens
                block_number: "0x1".to_string(),
                transaction_hash: "0xhash1".to_string(),
                transaction_index: "0x0".to_string(),
                block_hash: "0xblock1".to_string(),
                log_index: "0x0".to_string(),
            },
            TransferLog {
                address: "0xtoken".to_string(),
                topics: vec![
                    "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
                        .to_string(),
                    "0x000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"
                        .to_string(), // from: address A
                    "0x000000000000000000000000dac17f958d2ee523a2206206994597c13d831ec7"
                        .to_string(), // to: address B
                ],
                data: "0x0000000000000000000000000000000000000000000000000000000000000032"
                    .to_string(), // 50 tokens
                block_number: "0x2".to_string(),
                transaction_hash: "0xhash2".to_string(),
                transaction_index: "0x0".to_string(),
                block_hash: "0xblock2".to_string(),
                log_index: "0x0".to_string(),
            },
        ];

        let balances = EtherscanClient::compute_balances_from_logs(&logs);

        let addr_a: Address = "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"
            .parse()
            .unwrap();
        let addr_b: Address = "0xdac17f958d2ee523a2206206994597c13d831ec7"
            .parse()
            .unwrap();

        // Address A: received 100, sent 50 = 50
        assert_eq!(balances.get(&addr_a), Some(&U256::from(50)));

        // Address B: received 50
        assert_eq!(balances.get(&addr_b), Some(&U256::from(50)));
    }

    #[test]
    fn test_get_potential_voters() {
        let client = EtherscanClient::new("test_key".to_string(), 1);

        let transfer_logs = vec![TransferLog {
            address: "0xtoken".to_string(),
            topics: vec![
                "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef".to_string(),
                "0x0000000000000000000000000000000000000000000000000000000000000000".to_string(),
                "0x000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48".to_string(),
            ],
            data: "0x0000000000000000000000000000000000000000000000000000000000000064".to_string(),
            block_number: "0x1".to_string(),
            transaction_hash: "0xhash1".to_string(),
            transaction_index: "0x0".to_string(),
            block_hash: "0xblock1".to_string(),
            log_index: "0x0".to_string(),
        }];

        let delegation_logs = vec![
            DelegateVotesChangedLog {
                address: "0xtoken".to_string(),
                topics: vec![
                    "0xdec2bacdd2f05b59de34da9b523dff8be42e5e38e8af2ade71e1ddfc5c9f0e6f".to_string(),
                    "0x000000000000000000000000dac17f958d2ee523a2206206994597c13d831ec7".to_string(), // delegate B
                ],
                data: "0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000064".to_string(),
                block_number: "0x2".to_string(),
                transaction_hash: "0xhash2".to_string(),
                transaction_index: "0x0".to_string(),
                block_hash: "0xblock2".to_string(),
                log_index: "0x0".to_string(),
            },
        ];

        let potential_voters = client.get_potential_voters(&transfer_logs, &delegation_logs);

        // Should have 2 voters: A (token holder) and B (delegate, may not have tokens)
        assert_eq!(potential_voters.len(), 2);

        let addr_a: Address = "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"
            .parse()
            .unwrap();
        let addr_b: Address = "0xdac17f958d2ee523a2206206994597c13d831ec7"
            .parse()
            .unwrap();

        let voter_a = potential_voters
            .iter()
            .find(|v| v.address == addr_a)
            .unwrap();
        assert_eq!(voter_a.token_balance, U256::from(100));
        assert!(!voter_a.has_delegation); // A is not a delegate

        let voter_b = potential_voters
            .iter()
            .find(|v| v.address == addr_b)
            .unwrap();
        assert!(voter_b.has_delegation); // B is a delegate
    }

    #[test]
    fn test_parse_address_from_topic() {
        let topic = "0x000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48";
        let addr = EtherscanClient::parse_address_from_topic(topic).unwrap();
        let expected: Address = "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"
            .parse()
            .unwrap();
        assert_eq!(addr, expected);
    }

    #[test]
    fn test_parse_transfer_value() {
        assert_eq!(
            EtherscanClient::parse_transfer_value("0x64"),
            U256::from(100)
        );
        assert_eq!(EtherscanClient::parse_transfer_value("0x0"), U256::ZERO);
        assert_eq!(
            EtherscanClient::parse_transfer_value(
                "0x0000000000000000000000000000000000000000000000000000000000000064"
            ),
            U256::from(100)
        );
    }

    // Integration tests (requires valid API key)
    #[tokio::test]
    #[ignore]
    async fn test_get_deployment_block() {
        let token = "0xb0BE360719f84c5351621590B7FfBD8EB0B46B5d";
        let chain_id = 11155111;
        let api_key = &CONFIG.etherscan_api_key;

        let client = EtherscanClient::new(api_key.to_string(), chain_id);
        let result = client.get_deployment_block(token).await;
        println!("Deployment block: {:?}", result);
        assert!(result.is_ok());
    }

    #[tokio::test]
    #[ignore]
    async fn test_get_transfer_logs() {
        let token = "0xC18360217D8F7Ab5e7c516566761Ea12Ce7F9D72";
        let from_block = 23680346;
        let to_block = 23682281;
        let chain_id = 1;
        let api_key = &CONFIG.etherscan_api_key;

        let client = EtherscanClient::new(api_key.to_string(), chain_id);
        let result = client.get_transfer_logs(token, from_block, to_block).await;
        println!("Transfer logs: {:?}", result);
        assert!(result.is_ok());
    }

    #[tokio::test]
    #[ignore]
    async fn test_get_delegate_votes_changed_logs() {
        let token = "0xC18360217D8F7Ab5e7c516566761Ea12Ce7F9D72";
        let from_block = 23680346;
        let to_block = 23682281;
        let chain_id = 1;
        let api_key = &CONFIG.etherscan_api_key;

        let client = EtherscanClient::new(api_key.to_string(), chain_id);
        let result = client
            .get_delegate_votes_changed_logs(token, from_block, to_block)
            .await;
        println!("Delegation logs: {:?}", result);
        assert!(result.is_ok());
    }

    #[tokio::test]
    #[ignore]
    async fn test_get_token_holders_with_voting_power() {
        let token = "0xb0BE360719f84c5351621590B7FfBD8EB0B46B5d";
        let token_address: Address = token.parse().unwrap();
        let chain_id = CONFIG.chain_id;
        let api_key = &CONFIG.etherscan_api_key;
        let rpc_url = &CONFIG.http_rpc_url;
        let threshold = U256::ZERO;
        let snapshot_block = 9564734;

        let client = EtherscanClient::new(api_key.to_string(), chain_id);
        let res = client
            .get_token_holders_with_voting_power(token_address, snapshot_block, rpc_url, threshold)
            .await
            .unwrap();

        assert!(res.len() == 2);
    }
}
