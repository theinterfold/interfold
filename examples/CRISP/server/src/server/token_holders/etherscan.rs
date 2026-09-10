// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::server::models::TokenHolder;
use alloy::eips::BlockNumberOrTag;
use alloy::primitives::{Address, U256};
use alloy::providers::{Provider, ProviderBuilder};
use alloy::sol;
use alloy::transports::RpcError;
use eyre::{eyre, Context, Result}; // Add this import
use reqwest;
use serde::Deserialize;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::time::{sleep, Duration, Instant};

// Define the Votes contract interface for getPastVotes
sol! {
    #[derive(Debug)]
    #[sol(rpc)]
    contract ERC20Votes {
        function getPastVotes(address account, uint256 timepoint) external view returns (uint256);
        function balanceOf(address account) external view returns (uint256);
        function decimals() external view returns (uint8);
        function CLOCK_MODE() external view returns (string);
    }

    /// The `BondedVotes` adapter, which sums wallet voting power and bonded collateral.
    /// @dev A pure view: it emits nothing itself, so candidate discovery has to follow these
    /// three references to the contracts that do emit.
    #[sol(rpc)]
    contract BondedVotes {
        function token() external view returns (address);
        function checkpoints() external view returns (address);
        function registry() external view returns (address);
    }
}

/// Where a round's voting power is emitted from, resolved from the token the round names.
#[derive(Debug, Clone)]
pub struct VotingPowerSources {
    /// The ERC20Votes token whose `DelegateVotesChanged` logs carry wallet voting power. Equal to
    /// the round's token for a plain token, or the adapter's underlying one.
    pub token: Address,
    /// The bonding registry emitting `BondOwnerSet`. `None` when the round's token is not an
    /// adapter, in which case there is no bonded power to find.
    pub registry: Option<Address>,
    /// The checkpoint contract emitting `BondedCheckpointed`, when one is configured.
    pub checkpoints: Option<Address>,
}

/// Which unit a census token's `getPastVotes` timepoint is denominated in.
///
/// Set by the census token itself, per EIP-6372 — not by Interfold. The census token is
/// requester-supplied, and OpenZeppelin's `ERC20Votes` defaults to block numbers, so this
/// must be read per token rather than assumed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClockMode {
    BlockNumber,
    Timestamp,
}

/// What a `decimals()` read on a census token found.
///
/// `decimals()` is optional on an ERC20. A token without it is a supported census token, so the
/// two outcomes are separate values rather than an error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenDecimals {
    /// The token answered with its decimals.
    Reported(u8),
    /// The token has no usable `decimals()`. The node evaluated the call, and the token refused
    /// it or answered with data that is not a `uint8`.
    Absent,
}

/// The largest `decimals` a default divisor can be derived from.
///
/// `10 ** 77` is the last power of ten that fits in 256 bits, so 78 decimals is the last value
/// `10 ** (decimals - 1)` supports. Mirrors `MAX_DERIVABLE_DECIMALS` in `CRISPProgram.sol`.
const MAX_DERIVABLE_DECIMALS: u8 = 78;

/// The divisor to apply to raw voting power when the round names none.
///
/// Mirrors `CRISPProgram._defaultVotingPowerDivisor`, so an ONCHAIN round and a Merkle round over
/// the same token encode ballots in identical units: 1 for 0 or 1 decimals, and
/// `10 ** (decimals - 1)` for 2 through 78 decimals.
///
/// The exponentiation happens in `U256`. A 128-bit intermediate overflows at 40 decimals, and the
/// contract accepts decimals through 78, so a narrower type would disagree with the chain over
/// exactly that range — and it would disagree by a panic, which discovery does not catch.
fn default_voting_power_divisor(decimals: u8) -> Result<U256> {
    if decimals > MAX_DERIVABLE_DECIMALS {
        return Err(eyre!(
            "The token reports {} decimals, and a default divisor is derivable through {}. \
             Request the round with an explicit voting-power divisor.",
            decimals,
            MAX_DERIVABLE_DECIMALS
        ));
    }

    // One ballot unit per token unit. The contract makes the same exception, because
    // `10 ** (0 - 1)` has no meaning.
    if decimals <= 1 {
        return Ok(U256::from(1));
    }

    U256::from(10)
        .checked_pow(U256::from(decimals - 1))
        .ok_or_else(|| {
            eyre!(
                "A divisor for {} decimals does not fit in 256 bits. Request the round with an \
                 explicit voting-power divisor.",
                decimals
            )
        })
}

/// True when the node evaluated a metadata call and the token refused it.
///
/// The two failure kinds must stay separate. A revert, or an answer that does not decode, shows
/// that the token has no usable `decimals()` — which is permitted on an ERC20, and which the
/// contract answers with divisor 1. A timeout or a transport failure judged nothing about the
/// token, and must not silently change the divisor.
fn is_metadata_revert(error: &alloy::contract::Error) -> bool {
    match error {
        // The call succeeded and returned nothing, so the method is absent. A call to an address
        // with no code takes this path as well.
        alloy::contract::Error::ZeroData(..) => true,
        // The node answered, and the answer is not a `uint8`.
        alloy::contract::Error::AbiError(_) => true,
        alloy::contract::Error::TransportError(RpcError::ErrorResp(payload)) => {
            payload.as_revert_data().is_some() || payload.message.to_lowercase().contains("revert")
        }
        _ => false,
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

/// A log reduced to what candidate discovery needs: which contract, and its indexed topics.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TopicLog {
    pub address: String,
    pub topics: Vec<String>,
}

/// Represents an address that may have voting power
#[derive(Debug, Clone)]
pub struct PotentialVoter {
    pub address: Address,
    pub token_balance: U256,
    pub has_delegation: bool,
}

/// Minimum spacing between Etherscan requests.
///
/// Etherscan enforces a per-second call ceiling — 3/sec on the free tier — and rejects
/// the excess outright rather than queueing it, so requests are spaced client-side.
/// 500ms leaves headroom under that ceiling for retries and for concurrent rounds
/// sharing the key. Raise the rate with {with_min_request_interval} on a higher plan.
const MIN_REQUEST_INTERVAL: Duration = Duration::from_millis(500);

/// How many times a rate-limited request is retried before giving up.
const RATE_LIMIT_RETRIES: u32 = 5;

/// Client for querying token holder data from Etherscan API.
pub struct EtherscanClient {
    client: reqwest::Client,
    api_key: String,
    chain_id: u64,
    /// Completion time of the last request, shared so that every call through this
    /// client observes one spacing schedule.
    last_request: Arc<Mutex<Option<Instant>>>,
    min_interval: Duration,
}

impl EtherscanClient {
    /// Create a new EtherscanClient instance
    pub fn new(api_key: String, chain_id: u64) -> Self {
        Self {
            client: reqwest::Client::new(),
            api_key,
            chain_id,
            last_request: Arc::new(Mutex::new(None)),
            min_interval: MIN_REQUEST_INTERVAL,
        }
    }

    /// Override the spacing between requests, for a plan with a different ceiling.
    pub fn with_min_request_interval(mut self, interval: Duration) -> Self {
        self.min_interval = interval;
        self
    }

    /// Block until enough time has passed since the previous request.
    ///
    /// The lock is held across the wait so concurrent callers queue behind one another
    /// rather than all observing the same stale timestamp and firing together.
    async fn throttle(&self) {
        let mut last = self.last_request.lock().await;
        if let Some(previous) = *last {
            let elapsed = previous.elapsed();
            if elapsed < self.min_interval {
                sleep(self.min_interval - elapsed).await;
            }
        }
        *last = Some(Instant::now());
    }

    /// Resolve an EIP-6372 timestamp timepoint to the highest block mined at or before it.
    ///
    /// The E3 census snapshot is a timepoint, not a block height: `Interfold.request`
    /// assigns `block.timestamp` to `E3.requestBlock` regardless of the census token.
    /// Log queries address blocks, so the timepoint must be converted before it can
    /// bound a `getLogs` range.
    ///
    /// Resolved over RPC by binary search rather than through Etherscan's
    /// `getblocknobytime`, which is a Pro-tier endpoint and fails on free API keys.
    /// The search also pins the boundary exactly — the greatest block whose timestamp
    /// is `<= timestamp`, including every block that contributes to voting power at the
    /// timepoint and none that follow it.
    pub async fn get_block_by_timestamp(timestamp: u64, rpc_url: &str) -> Result<u64> {
        let url = rpc_url.parse().context("Failed to parse RPC URL")?;
        let provider = ProviderBuilder::new().connect_http(url);

        let block_timestamp = |number: u64| {
            let provider = provider.clone();
            async move {
                provider
                    .get_block_by_number(BlockNumberOrTag::Number(number))
                    .await
                    .with_context(|| format!("Failed to fetch block {}", number))?
                    .map(|block| block.header.timestamp)
                    .ok_or_else(|| eyre!("Block {} not found", number))
            }
        };

        let latest = provider
            .get_block_number()
            .await
            .context("Failed to fetch latest block number")?;

        // A timepoint at or beyond the head means the whole chain qualifies. This is
        // reachable normally: the census is built moments after the request is mined.
        if block_timestamp(latest).await? <= timestamp {
            return Ok(latest);
        }

        if block_timestamp(0).await? > timestamp {
            return Err(eyre!(
                "Timestamp {} predates the genesis block; it is not a valid timepoint",
                timestamp
            ));
        }

        // Invariant: `lo` is always at or before the timepoint, `hi` always after it.
        let (mut lo, mut hi) = (0u64, latest);
        while hi - lo > 1 {
            let mid = lo + (hi - lo) / 2;
            if block_timestamp(mid).await? <= timestamp {
                lo = mid;
            } else {
                hi = mid;
            }
        }

        Ok(lo)
    }

    /// Get the deployment block number for a contract
    pub async fn get_deployment_block(&self, token: &str) -> Result<u64> {
        let url = format!(
            "{}?module=contract&action=getcontractcreation&contractaddresses={}&chainid={}&apikey={}",
            ETHERSCAN_API_URL, token, self.chain_id, self.api_key
        );

        // Shares the throttle and the in-band error handling with the log queries; it
        // is the first Etherscan call of a census and counts against the same ceiling.
        let creations: Vec<ContractCreation> = self
            .fetch_page(&url, "contract creation")
            .await?
            .ok_or_else(|| eyre!("No deployment data found"))?;

        let result = creations
            .into_iter()
            .next()
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

    /// Fetch one page of Etherscan results, surfacing in-band API errors.
    ///
    /// Etherscan reports failures with HTTP 200, `status: "0"`, and the explanation in
    /// `result` as a bare string rather than the success type. Deserializing the body
    /// straight into `T` therefore collapses every API error — invalid key, rate limit,
    /// Pro-only endpoint — into an indistinguishable decode failure. The envelope is
    /// inspected before `result` is typed, so the real message reaches the caller.
    ///
    /// Returns `Ok(None)` for the "No records found" response, which is a legitimate
    /// empty result rather than an error.
    ///
    /// Rate-limit rejections are retried with exponential backoff. Client-side spacing
    /// alone cannot prevent them: the ceiling is per API key, so concurrent rounds — or
    /// anything else sharing the key — can exhaust it between two correctly spaced calls.
    async fn fetch_page<T: serde::de::DeserializeOwned>(
        &self,
        url: &str,
        what: &str,
    ) -> Result<Option<T>> {
        let mut backoff = self.min_interval;

        for attempt in 0..=RATE_LIMIT_RETRIES {
            self.throttle().await;

            let body = self
                .client
                .get(url)
                .send()
                .await
                .with_context(|| format!("Failed to send {} request to Etherscan", what))?
                .text()
                .await
                .with_context(|| format!("Failed to read {} response body", what))?;

            let envelope: EtherscanResponse<serde_json::Value> = serde_json::from_str(&body)
                .with_context(|| {
                    format!(
                        "Failed to parse {} response envelope; body was: {}",
                        what,
                        body.chars().take(500).collect::<String>()
                    )
                })?;

            if envelope.status != "1" {
                if envelope.message.eq_ignore_ascii_case("No records found") {
                    return Ok(None);
                }

                // The `result` field carries Etherscan's actual explanation; `message` is
                // usually just "NOTOK".
                let detail = match &envelope.result {
                    Some(serde_json::Value::String(s)) if !s.is_empty() => s.clone(),
                    _ => envelope.message.clone(),
                };

                if Self::is_rate_limited(&detail) && attempt < RATE_LIMIT_RETRIES {
                    log::warn!(
                        "Etherscan rate limit on {} (attempt {}/{}): {}; retrying in {:?}",
                        what,
                        attempt + 1,
                        RATE_LIMIT_RETRIES,
                        detail,
                        backoff
                    );
                    sleep(backoff).await;
                    backoff *= 2;
                    continue;
                }

                return Err(eyre!("Etherscan {} request failed: {}", what, detail));
            }

            let result = match envelope.result {
                Some(value) => value,
                None => return Ok(None),
            };

            let typed = serde_json::from_value(result)
                .with_context(|| format!("Failed to parse {} result payload", what))?;

            return Ok(Some(typed));
        }

        unreachable!("the retry loop returns or errors on its final attempt")
    }

    /// Whether an Etherscan error message describes a rate-limit rejection.
    ///
    /// Matched on text because the API reports it in-band with the same `status: "0"`
    /// it uses for every other failure, with no distinguishing code.
    fn is_rate_limited(detail: &str) -> bool {
        let detail = detail.to_ascii_lowercase();
        detail.contains("rate limit") || detail.contains("too many requests")
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

            let logs: Vec<TransferLog> = match self
                .fetch_page::<Vec<TransferLog>>(&url, "transfer logs")
                .await
                .with_context(|| format!("Transfer logs page {}", page))?
            {
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
            // Spacing between requests is handled by `throttle`, so no sleep here.
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
            "0xdec2bacdd2f05b59de34da9b523dff8be42e5e38e818c82fdb0bae774387a724";

        loop {
            let url = format!(
                "{}?module=logs&action=getLogs&address={}&fromBlock={}&toBlock={}&topic0={}&page={}&offset=10000&chainid={}&apikey={}",
                ETHERSCAN_API_URL, token, from_block, to_block, delegate_votes_changed_topic, page, self.chain_id, self.api_key
            );

            let logs: Vec<DelegateVotesChangedLog> = match self
                .fetch_page::<Vec<DelegateVotesChangedLog>>(&url, "delegation logs")
                .await
                .with_context(|| format!("Delegation logs page {}", page))?
            {
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
            // Spacing between requests is handled by `throttle`, so no sleep here.
        }

        Ok(all_logs)
    }

    /// Resolve where a round's voting power is emitted from.
    ///
    /// Structural, not configured: a `BondedVotes` adapter exposes `token()`, `checkpoints()` and
    /// `registry()` as public immutables, so probing them tells us whether bonded collateral is in
    /// play without the server being told which deployment is "the governance one". A plain
    /// ERC20Votes token answers none of them and scans exactly as before.
    ///
    /// # Arguments
    /// * `round_token` - The token the round was requested against
    /// * `rpc_url` - The RPC endpoint
    pub async fn resolve_voting_power_sources(
        round_token: Address,
        rpc_url: &str,
    ) -> VotingPowerSources {
        let plain = VotingPowerSources {
            token: round_token,
            registry: None,
            checkpoints: None,
        };

        let Ok(url) = rpc_url.parse() else {
            // Not the same as "plain token": we could not look. Said out loud because the
            // consequence is a census missing every bond owner, which otherwise looks identical
            // to a token that simply has none.
            log::warn!(
                "Could not parse the RPC URL while resolving voting-power sources for {}; \
                 treating it as a plain token, so any bonded voters will be missing",
                round_token
            );
            return plain;
        };
        let provider = ProviderBuilder::new().connect_http(url);
        let adapter = BondedVotes::new(round_token, provider);

        // `token()` is the discriminator. Anything that answers it while also answering
        // `registry()` is an adapter over bonded collateral.
        let (underlying, registry) = match (
            adapter.token().call().await,
            adapter.registry().call().await,
        ) {
            (Ok(underlying), Ok(registry)) => (underlying, registry),
            // A plain ERC20Votes token does not implement these, so a revert here is the expected
            // negative answer and only worth a debug line.
            (Err(token_err), _) | (_, Err(token_err)) => {
                log::debug!(
                    "{} does not answer token()/registry() ({}); treating it as a plain \
                     ERC20Votes token",
                    round_token,
                    token_err
                );
                return plain;
            }
        };

        VotingPowerSources {
            token: underlying,
            registry: Some(registry),
            // Optional: the registry may not have been pointed at a checkpoint contract yet, in
            // which case `BondOwnerSet` alone still names every bond owner.
            checkpoints: adapter.checkpoints().call().await.ok(),
        }
    }

    /// Fetch every log for one contract and one `topic0`, paging until the source is exhausted.
    ///
    /// # Arguments
    /// * `address` - The contract emitting the event
    /// * `topic0` - The event signature hash
    /// * `from_block` - First block to scan
    /// * `to_block` - Last block to scan
    pub async fn get_logs_by_topic(
        &self,
        address: &str,
        topic0: &str,
        from_block: u64,
        to_block: u64,
    ) -> Result<Vec<TopicLog>> {
        let mut all_logs = Vec::new();
        let mut page = 1;

        loop {
            let url = format!(
                "{}?module=logs&action=getLogs&address={}&fromBlock={}&toBlock={}&topic0={}&page={}&offset=10000&chainid={}&apikey={}",
                ETHERSCAN_API_URL, address, from_block, to_block, topic0, page, self.chain_id, self.api_key
            );

            let logs: Vec<TopicLog> = match self
                .fetch_page::<Vec<TopicLog>>(&url, "topic logs")
                .await
                .with_context(|| format!("Logs page {} for {}", page, address))?
            {
                Some(logs) if !logs.is_empty() => logs,
                _ => break,
            };

            let log_count = logs.len();
            all_logs.extend(logs);

            if log_count < 10000 {
                break;
            }

            page += 1;
        }

        Ok(all_logs)
    }

    /// Fetch the addresses named as `bondOwner` by a `BondingRegistry`, and by the
    /// `BondedCheckpoints` it writes to.
    ///
    /// Bonded FOLD carries voting power through a `BondedVotes` adapter, which is a pure view:
    /// it emits nothing. Its power comes from two places the adapter merely reads, so an address
    /// can hold bonded weight while appearing in no `Transfer` and no `DelegateVotesChanged` log
    /// at all — scanning only the token would miss every operator.
    ///
    /// `BondOwnerSet` is the complete source. It is emitted both when an operator first names an
    /// owner and when ownership is transferred (`acceptBondOwner` emits it too), and there is no
    /// other way to become a bond owner. It also holds where `BondedCheckpointed` does not:
    /// configuring the checkpoint contract does not backfill, so an owner that bonded beforehand
    /// has no checkpoint event until its next mutation. `BondedCheckpointed` is scanned as well
    /// because it is the cheaper filter for the common case.
    ///
    /// Over-inclusion is free — every candidate is verified against `getPastVotes` afterwards and
    /// dropped if it has no power — so both sources are scanned rather than one being trusted.
    ///
    /// # Arguments
    /// * `registry` - The bonding registry emitting `BondOwnerSet`
    /// * `checkpoints` - The bonded checkpoints contract, or `None` if unset
    /// * `from_block` - First block to scan
    /// * `to_block` - Last block to scan
    pub async fn get_bond_owner_candidates(
        &self,
        registry: &str,
        checkpoints: Option<&str>,
        from_block: u64,
        to_block: u64,
    ) -> Result<Vec<Address>> {
        // keccak256("BondOwnerSet(address,address)")
        const BOND_OWNER_SET_TOPIC: &str =
            "0xf09dc4a8a4e1c9233bcb1d32c04ad4c9d516f140c23aa44f9e0d680f70799e08";
        // keccak256("BondedCheckpointed(address,uint48,uint256)")
        const BONDED_CHECKPOINTED_TOPIC: &str =
            "0xb6241efac9a4f02e4f1ba6a30a3a5fc5ba4b23a47f181eca3055466c775eb32c";

        let mut owners: HashSet<Address> = HashSet::new();

        // `bondOwner` is the second indexed parameter of `BondOwnerSet(operator, bondOwner)` and
        // the first of `BondedCheckpointed(bondOwner, timepoint, amount)`.
        for (address, topic, owner_topic_index) in [
            (Some(registry), BOND_OWNER_SET_TOPIC, 2usize),
            (checkpoints, BONDED_CHECKPOINTED_TOPIC, 1usize),
        ] {
            let Some(address) = address else { continue };

            let logs = self
                .get_logs_by_topic(address, topic, from_block, to_block)
                .await
                .with_context(|| format!("Bond owner logs for {}", address))?;

            for log in logs {
                if let Some(raw) = log.topics.get(owner_topic_index) {
                    if let Ok(owner) = Self::address_from_topic(raw) {
                        owners.insert(owner);
                    }
                }
            }
        }

        Ok(owners.into_iter().collect())
    }

    /// Decode an address from a 32-byte indexed log topic (left-padded).
    fn address_from_topic(topic: &str) -> Result<Address> {
        let hex = topic.trim_start_matches("0x");
        if hex.len() < 40 {
            return Err(eyre::eyre!("topic too short to hold an address: {}", topic));
        }
        Ok(format!("0x{}", &hex[hex.len() - 40..]).parse::<Address>()?)
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

    /// Select the divisor to scale raw voting power by.
    ///
    /// The order matches `CRISPProgram._initRound`: a nonzero explicit divisor wins, and the
    /// token metadata is read only when the round named no divisor. A round with an explicit
    /// divisor therefore does not depend on optional token metadata at all.
    ///
    /// `read_decimals` is a parameter so that this order, the derivation, and the metadata
    /// failure handling are testable without a node.
    async fn resolve_scale_factor<F, Fut>(
        divisor_override: Option<U256>,
        read_decimals: F,
    ) -> Result<U256>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Result<TokenDecimals>>,
    {
        if let Some(divisor) = divisor_override {
            if !divisor.is_zero() {
                return Ok(divisor);
            }
        }

        match read_decimals().await? {
            TokenDecimals::Reported(decimals) => default_voting_power_divisor(decimals),
            // The value the contract records when its own `decimals()` call reverts.
            TokenDecimals::Absent => Ok(U256::from(1)),
        }
    }

    /// Verify voting power for multiple addresses at an EIP-6372 timepoint
    pub async fn verify_voting_power(
        &self,
        token_address: Address,
        potential_voters: &[PotentialVoter],
        timepoint: u64,
        rpc_url: &str,
        threshold: U256,
        // The round's explicit divisor, when it named one. `None` derives from the token's
        // decimals, matching what the contract does for a zero divisor.
        divisor_override: Option<U256>,
    ) -> Result<Vec<TokenHolder>> {
        let mut token_holders: Vec<TokenHolder> = Vec::new();

        // A round that names its own divisor must be scaled by that, not by the decimals: the
        // contract enforces the round's value, so deriving here would serve balances in units the
        // chain disagrees with, and a mask built from one would fail in the verifier.
        //
        // The override is selected before any metadata call, as `CRISPProgram._initRound` does.
        // `decimals()` is optional on an ERC20, so a token that has no usable one must not stop
        // discovery for a round that already named its divisor.
        let scale_factor = Self::resolve_scale_factor(divisor_override, || {
            Self::get_decimals(token_address, rpc_url)
        })
        .await?;

        log::info!(
            "Verifying {} candidates against {} at timepoint {} (divisor={}, threshold={})",
            potential_voters.len(),
            token_address,
            timepoint,
            scale_factor,
            threshold
        );

        let mut below_threshold = 0usize;
        let mut rounds_to_zero = 0usize;

        for voter in potential_voters {
            match Self::get_past_votes(token_address, voter.address, timepoint, rpc_url).await {
                Ok(votes) => {
                    if votes >= threshold {
                        let scaled_votes = votes / scale_factor;

                        // Both values, because they answer different questions. The raw one is
                        // what the chain reports and what a holder recognises as their balance;
                        // the scaled one is what the ballot is bounded by, and a mismatch between
                        // a census and a tally is almost always a scaling mismatch.
                        log::info!(
                            "  eligible {} raw={} scaled={}",
                            voter.address,
                            votes,
                            scaled_votes
                        );

                        // Above the threshold but worth nothing once scaled: the leaf bounds every
                        // ballot to zero, so this address is in the census and can still only cast
                        // an empty vote. Worth saying out loud — it looks like eligibility from
                        // every angle except the one that counts.
                        if scaled_votes.is_zero() {
                            rounds_to_zero += 1;
                            log::warn!(
                                "  {} clears the threshold but scales to zero (raw={}, \
                                 divisor={}): it can vote, but carries no weight",
                                voter.address,
                                votes,
                                scale_factor
                            );
                        }

                        token_holders.push(TokenHolder {
                            address: voter.address.to_string(),
                            balance: scaled_votes.to_string(),
                        });
                    } else {
                        below_threshold += 1;
                        log::debug!(
                            "  skipped {} raw={} below threshold {}",
                            voter.address,
                            votes,
                            threshold
                        );
                    }
                }
                Err(e) => {
                    log::warn!("Failed to get votes for {}: {}", voter.address, e);
                }
            }

            // Rate limiting - small delay between RPC calls
            sleep(Duration::from_millis(50)).await;
        }

        log::info!(
            "Verified: {} eligible, {} below threshold, {} scale to zero",
            token_holders.len(),
            below_threshold,
            rounds_to_zero
        );

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

    /// Read a census token's EIP-6372 clock mode.
    ///
    /// Defaults to block numbers when `CLOCK_MODE()` is absent or unparseable: tokens
    /// predating EIP-6372 checkpoint on `block.number`, and that is also OpenZeppelin's
    /// default for `ERC20Votes`.
    async fn get_clock_mode(token_address: Address, rpc_url: &str) -> ClockMode {
        let Ok(url) = rpc_url.parse() else {
            return ClockMode::BlockNumber;
        };
        let provider = ProviderBuilder::new().connect_http(url);
        let token = ERC20Votes::new(token_address, provider);

        match token.CLOCK_MODE().call().await {
            Ok(mode) if mode.contains("mode=timestamp") => ClockMode::Timestamp,
            Ok(_) => ClockMode::BlockNumber,
            Err(_) => ClockMode::BlockNumber,
        }
    }

    /// Verify actual voting power for an address at an EIP-6372 timepoint
    async fn get_past_votes(
        token_address: Address,
        voter_address: Address,
        timepoint: u64,
        rpc_url: &str,
    ) -> Result<U256> {
        let url = rpc_url.parse().context("Failed to parse RPC URL")?;
        let provider = ProviderBuilder::new().connect_http(url);
        let token = ERC20Votes::new(token_address, provider);

        match token
            .getPastVotes(voter_address, U256::from(timepoint))
            .call()
            .await
        {
            Ok(votes) => Ok(votes),
            Err(e) => {
                // Fallback to balanceOf if getPastVotes fails. This substitutes a *current*
                // balance for a historical one, so it is logged: a timepoint in the wrong
                // unit reverts every call and would otherwise rebuild the whole census
                // from live balances without a single error.
                log::warn!(
                    "getPastVotes failed for {} at timepoint {} ({}), falling back to \
                     current balanceOf",
                    voter_address,
                    timepoint,
                    e
                );
                let balance = token
                    .balanceOf(voter_address)
                    .call()
                    .await
                    .context("Failed to call balanceOf")?;
                Ok(balance)
            }
        }
    }

    /// Get the token decimals.
    ///
    /// Three outcomes, because they must not be confused. A token that answers gives its
    /// decimals. A token that refuses the call has no usable `decimals()`, which is permitted on
    /// an ERC20, and the default divisor becomes 1 exactly as `CRISPProgram` does in its `catch`.
    /// Every other failure is an error: an RPC timeout or a transport failure judged nothing
    /// about the token, and a silent divisor of 1 would rescale the whole census.
    async fn get_decimals(token_address: Address, rpc_url: &str) -> Result<TokenDecimals> {
        let url = rpc_url.parse().context("Failed to parse RPC URL")?;
        let provider = ProviderBuilder::new().connect_http(url);
        let token = ERC20Votes::new(token_address, provider);

        match token.decimals().call().await {
            Ok(decimals) => Ok(TokenDecimals::Reported(decimals)),
            Err(error) if is_metadata_revert(&error) => {
                log::warn!(
                    "decimals() on {} reverted ({}). The default divisor is 1, which is what \
                     the contract records for the same token.",
                    token_address,
                    error
                );
                Ok(TokenDecimals::Absent)
            }
            Err(error) => Err(error).context(
                "Failed to call decimals. The node judged nothing about the token, so the \
                 divisor stays underived.",
            ),
        }
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

    /// Get all token holders with voting power at a census timepoint.
    ///
    /// `snapshot_timepoint` is an EIP-6372 timestamp, not a block height — `E3.requestBlock`
    /// carries `block.timestamp` regardless of which token forms the census. Log discovery
    /// needs the equivalent block, so both units are derived here: the block always bounds
    /// the log ranges, while `getPastVotes` receives whichever unit the census token's own
    /// `CLOCK_MODE()` reports.
    pub async fn get_token_holders_with_voting_power(
        &self,
        token_address: Address,
        snapshot_timepoint: u64,
        rpc_url: &str,
        threshold: U256,
        // The round's explicit voting-power divisor, or `None` to derive it from the decimals.
        divisor_override: Option<U256>,
    ) -> Result<Vec<TokenHolder>> {
        log::info!("Starting token holder discovery for {}", token_address);

        // Where the power is actually emitted from. For a `BondedVotes` adapter the round's token
        // emits nothing at all: wallet power comes from the underlying token's logs and bonded
        // power from the registry's, so scanning `token_address` alone would find nobody.
        let sources = Self::resolve_voting_power_sources(token_address, rpc_url).await;
        if sources.registry.is_some() {
            log::info!(
                "{} is a bonded-votes adapter: scanning token {} and registry {:?}",
                token_address,
                sources.token,
                sources.registry
            );
        }
        let scan_token = sources.token;

        // Step 1: Determine the block range
        let start_block = self
            .get_deployment_block(&scan_token.to_string())
            .await
            .context("Failed to get deployment block")?;
        log::info!("Token deployed at block: {}", start_block);

        let snapshot_block = Self::get_block_by_timestamp(snapshot_timepoint, rpc_url)
            .await
            .context("Failed to resolve snapshot timepoint to a block")?;
        log::info!(
            "Snapshot timepoint {} resolves to block {}",
            snapshot_timepoint,
            snapshot_block
        );

        // Step 2: Fetch transfer logs
        log::info!(
            "Fetching transfer logs from block {} to {}...",
            start_block,
            snapshot_block
        );
        let transfer_logs = self
            .get_transfer_logs(&scan_token.to_string(), start_block, snapshot_block)
            .await
            .context("Failed to fetch transfer logs")?;
        log::info!("Found {} transfer events", transfer_logs.len());

        // Step 3: Fetch delegation logs
        log::info!("Fetching delegation logs...");
        let delegation_logs = self
            .get_delegate_votes_changed_logs(&scan_token.to_string(), start_block, snapshot_block)
            .await
            .context("Failed to fetch delegation logs")?;
        log::info!("Found {} delegation events", delegation_logs.len());

        // Step 4: Identify potential voters
        log::info!("Identifying potential voters...");
        let mut potential_voters = self.get_potential_voters(&transfer_logs, &delegation_logs);

        // Bond owners hold power through the adapter without necessarily appearing in the token's
        // own logs, so they are unioned in as candidates. Over-inclusion is harmless: each is
        // verified against `getPastVotes` below and dropped if it has none.
        if let Some(registry) = sources.registry {
            let known: HashSet<Address> = potential_voters.iter().map(|v| v.address).collect();
            let bond_owners = self
                .get_bond_owner_candidates(
                    &registry.to_string(),
                    sources.checkpoints.map(|c| c.to_string()).as_deref(),
                    start_block,
                    snapshot_block,
                )
                .await
                .context("Failed to fetch bond owner candidates")?;

            log::info!("Found {} bond-owner candidates", bond_owners.len());
            for owner in bond_owners {
                if !known.contains(&owner) {
                    potential_voters.push(PotentialVoter {
                        address: owner,
                        token_balance: U256::ZERO,
                        has_delegation: false,
                    });
                }
            }
        }

        log::info!("Found {} potential voters", potential_voters.len());

        // Step 5: Verify actual voting power. The unit of the `getPastVotes` timepoint is
        // the census token's to decide, so ask it rather than assuming. Passing the wrong
        // unit reverts the call and silently degrades the census to current balances.
        let clock_mode = Self::get_clock_mode(token_address, rpc_url).await;
        let vote_timepoint = match clock_mode {
            ClockMode::Timestamp => snapshot_timepoint,
            ClockMode::BlockNumber => snapshot_block,
        };
        log::info!(
            "Census token clock is {:?}; verifying voting power at timepoint {}...",
            clock_mode,
            vote_timepoint
        );
        let token_holders = self
            .verify_voting_power(
                token_address,
                &potential_voters,
                vote_timepoint,
                rpc_url,
                threshold,
                divisor_override,
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
        snapshot_timepoint: u64,
        rpc_url: &str,
        balance: U256,
    ) -> Result<Vec<TokenHolder>> {
        log::info!(
            "Starting token holder discovery (constant balance) for {}",
            token_address
        );

        // Step 1: Determine the block range
        let start_block = self
            .get_deployment_block(&token_address.to_string())
            .await
            .context("Failed to get deployment block")?;
        log::info!("Token deployed at block: {}", start_block);

        // Eligibility here rests on the logs alone — no `getPastVotes` pass narrows the
        // set afterwards — so the range must not reach past the census timepoint.
        let snapshot_block = Self::get_block_by_timestamp(snapshot_timepoint, rpc_url)
            .await
            .context("Failed to resolve snapshot timepoint to a block")?;
        log::info!(
            "Snapshot timepoint {} resolves to block {}",
            snapshot_timepoint,
            snapshot_block
        );

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
                    "0xdec2bacdd2f05b59de34da9b523dff8be42e5e38e818c82fdb0bae774387a724".to_string(),
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
                    "0xdec2bacdd2f05b59de34da9b523dff8be42e5e38e818c82fdb0bae774387a724".to_string(),
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
        // A timepoint, matching what `E3.requestBlock` carries — not a block height.
        let snapshot_timepoint = 1761201108;

        let client = EtherscanClient::new(api_key.to_string(), chain_id);
        let res = client
            .get_token_holders_with_voting_power(
                token_address,
                snapshot_timepoint,
                rpc_url,
                threshold,
                // Derive from the token's decimals, as a round with a zero divisor does.
                None,
            )
            .await
            .unwrap();

        assert!(res.len() == 2);
    }

    #[tokio::test]
    #[ignore]
    async fn test_get_block_by_timestamp() {
        let rpc_url = &CONFIG.http_rpc_url;

        // A timepoint of the size `E3.requestBlock` carries. Read as a block height it
        // is far beyond any chain head, which is the failure this resolver removes.
        let snapshot_timepoint = 1761201108;

        let block = EtherscanClient::get_block_by_timestamp(snapshot_timepoint, rpc_url)
            .await
            .unwrap();

        assert!(block > 0);
        assert!(block < snapshot_timepoint);
    }

    #[tokio::test]
    #[ignore]
    async fn test_get_block_by_timestamp_is_the_last_block_at_or_before() {
        let rpc_url = &CONFIG.http_rpc_url;
        let snapshot_timepoint = 1761201108;

        let block = EtherscanClient::get_block_by_timestamp(snapshot_timepoint, rpc_url)
            .await
            .unwrap();

        // The boundary must be exact: the resolved block is at or before the timepoint,
        // and the next one is after it. An off-by-one here silently truncates or extends
        // the census.
        let url = rpc_url.parse().unwrap();
        let provider = ProviderBuilder::new().connect_http(url);
        let at = provider
            .get_block_by_number(BlockNumberOrTag::Number(block))
            .await
            .unwrap()
            .unwrap();
        let next = provider
            .get_block_by_number(BlockNumberOrTag::Number(block + 1))
            .await
            .unwrap()
            .unwrap();

        assert!(at.header.timestamp <= snapshot_timepoint);
        assert!(next.header.timestamp > snapshot_timepoint);
    }
}

/// Candidate discovery is only as good as its topic constants and its topic decoding: a wrong
/// hash matches no logs and a wrong index reads the wrong address, and both fail by silently
/// finding nobody rather than by erroring.
#[cfg(test)]
mod bond_owner_discovery_tests {
    use super::EtherscanClient;
    use alloy::primitives::{address, keccak256, Address};

    /// Pinned against the signatures the contracts actually declare. Computed here rather than
    /// copied, so a signature change breaks the test instead of quietly zeroing the census.
    #[test]
    fn topic_constants_match_the_event_signatures() {
        assert_eq!(
            format!("{:?}", keccak256(b"BondOwnerSet(address,address)")),
            "0xf09dc4a8a4e1c9233bcb1d32c04ad4c9d516f140c23aa44f9e0d680f70799e08"
        );
        assert_eq!(
            format!(
                "{:?}",
                keccak256(b"BondedCheckpointed(address,uint48,uint256)")
            ),
            "0xb6241efac9a4f02e4f1ba6a30a3a5fc5ba4b23a47f181eca3055466c775eb32c"
        );
        // The one that was wrong in this file: it matched nothing, so delegation logs always came
        // back empty and a pure delegatee never became a candidate.
        assert_eq!(
            format!(
                "{:?}",
                keccak256(b"DelegateVotesChanged(address,uint256,uint256)")
            ),
            "0xdec2bacdd2f05b59de34da9b523dff8be42e5e38e818c82fdb0bae774387a724"
        );
    }

    #[test]
    fn decodes_an_address_from_a_padded_topic() {
        let expected: Address = address!("f39Fd6e51aad88F6F4ce6aB8827279cffFb92266");
        let topic = "0x000000000000000000000000f39fd6e51aad88f6f4ce6ab8827279cfffb92266";

        assert_eq!(
            EtherscanClient::address_from_topic(topic).unwrap(),
            expected
        );
    }

    #[test]
    fn refuses_a_topic_too_short_to_hold_an_address() {
        assert!(EtherscanClient::address_from_topic("0xdeadbeef").is_err());
    }
}

/// The coordinator and `CRISPProgram` must scale voting power by the same divisor. A mismatch is
/// silent: an ONCHAIN client builds a mask against a bound the verifier refuses, and a TOKEN
/// census carries leaf weights the tally cannot decode back.
#[cfg(test)]
mod voting_power_divisor_tests {
    use super::{
        default_voting_power_divisor, EtherscanClient, TokenDecimals, MAX_DERIVABLE_DECIMALS,
    };
    use alloy::primitives::U256;

    /// The token that reverts `decimals()`. `CRISPProgram._defaultVotingPowerDivisor` catches the
    /// same revert and records divisor 1.
    async fn reverting_decimals() -> eyre::Result<TokenDecimals> {
        Ok(TokenDecimals::Absent)
    }

    /// An RPC failure. It judged nothing about the token, so it must not become divisor 1.
    async fn unreachable_node() -> eyre::Result<TokenDecimals> {
        Err(eyre::eyre!("Failed to call decimals"))
    }

    fn reports(
        decimals: u8,
    ) -> impl FnOnce() -> std::pin::Pin<Box<dyn std::future::Future<Output = eyre::Result<TokenDecimals>>>>
    {
        move || Box::pin(async move { Ok(TokenDecimals::Reported(decimals)) })
    }

    /// Every value the contract accepts, including the two that the previous `u128`
    /// exponentiation could not represent. 39 is the last exponent that fits in 128 bits and 40
    /// is the first that does not, so the pair pins the boundary that used to panic.
    #[test]
    fn the_default_divisor_matches_the_contract_for_every_supported_decimals() {
        // `10 ** (decimals - 1)` has no meaning below two decimals, so the contract returns 1.
        assert_eq!(default_voting_power_divisor(0).unwrap(), U256::from(1));
        assert_eq!(default_voting_power_divisor(1).unwrap(), U256::from(1));

        assert_eq!(default_voting_power_divisor(2).unwrap(), U256::from(10));
        assert_eq!(
            default_voting_power_divisor(18).unwrap(),
            U256::from(10).pow(U256::from(17))
        );
        assert_eq!(
            default_voting_power_divisor(39).unwrap(),
            U256::from(10).pow(U256::from(38))
        );
        assert_eq!(
            default_voting_power_divisor(40).unwrap(),
            U256::from(10).pow(U256::from(39))
        );
        assert_eq!(
            default_voting_power_divisor(MAX_DERIVABLE_DECIMALS).unwrap(),
            U256::from(10).pow(U256::from(77))
        );
    }

    /// The exact boundary the finding names. `10 ** 39` is larger than `u128::MAX`, so a 128-bit
    /// intermediate panics or wraps here while the contract derives the value without difficulty.
    #[test]
    fn the_divisor_for_40_decimals_exceeds_128_bits() {
        assert_eq!(
            default_voting_power_divisor(40).unwrap(),
            U256::from_str_radix("1000000000000000000000000000000000000000", 10).unwrap()
        );
        assert!(default_voting_power_divisor(40).unwrap() > U256::from(u128::MAX));
        assert!(default_voting_power_divisor(39).unwrap() <= U256::from(u128::MAX));
    }

    /// Refused with a message, not with a panic. `10 ** 78` does not fit in 256 bits, and the
    /// contract refuses the same value with `UnsupportedTokenDecimals`.
    #[test]
    fn a_decimals_above_the_contract_bound_is_refused() {
        assert!(default_voting_power_divisor(MAX_DERIVABLE_DECIMALS + 1).is_err());
        assert!(default_voting_power_divisor(u8::MAX).is_err());
    }

    /// The order the contract uses: the explicit divisor is selected before any metadata call.
    /// The reader here panics, so a test failure shows that metadata was read.
    #[tokio::test]
    async fn an_explicit_divisor_wins_and_no_metadata_is_read() {
        let divisor = U256::from(1_000u64);

        let resolved = EtherscanClient::resolve_scale_factor(Some(divisor), || {
            Box::pin(async {
                panic!("metadata must not be read when the round names a divisor");
                #[allow(unreachable_code)]
                Ok(TokenDecimals::Absent)
            })
                as std::pin::Pin<Box<dyn std::future::Future<Output = eyre::Result<TokenDecimals>>>>
        })
        .await
        .unwrap();

        assert_eq!(resolved, divisor);
    }

    /// The defect this pairing exists for: a token whose `decimals()` reverts must not stop
    /// discovery for a round that already named its divisor.
    #[tokio::test]
    async fn an_explicit_divisor_survives_a_reverting_decimals_call() {
        let divisor = U256::from(10).pow(U256::from(60));

        let resolved = EtherscanClient::resolve_scale_factor(Some(divisor), reverting_decimals)
            .await
            .unwrap();

        assert_eq!(resolved, divisor);
    }

    /// A zero divisor is how a round says it named none, so the default is derived.
    #[tokio::test]
    async fn a_zero_divisor_derives_the_default() {
        let resolved = EtherscanClient::resolve_scale_factor(Some(U256::ZERO), reports(18))
            .await
            .unwrap();

        assert_eq!(resolved, U256::from(10).pow(U256::from(17)));
    }

    /// The value `CRISPProgram` records when its own `decimals()` call reverts.
    #[tokio::test]
    async fn a_reverting_decimals_call_gives_divisor_one() {
        let resolved = EtherscanClient::resolve_scale_factor(None, reverting_decimals)
            .await
            .unwrap();

        assert_eq!(resolved, U256::from(1));
    }

    /// An RPC failure judged nothing about the token. Divisor 1 would rescale the whole census by
    /// `10 ** (decimals - 1)`, so the failure must propagate instead.
    #[tokio::test]
    async fn an_rpc_failure_does_not_become_divisor_one() {
        assert!(
            EtherscanClient::resolve_scale_factor(None, unreachable_node)
                .await
                .is_err()
        );
    }

    /// The derivation the contract performs for a 40-decimal token, through the same path
    /// discovery takes.
    #[tokio::test]
    async fn a_forty_decimal_token_resolves_without_overflow() {
        let resolved = EtherscanClient::resolve_scale_factor(None, reports(40))
            .await
            .unwrap();

        assert_eq!(resolved, U256::from(10).pow(U256::from(39)));
    }

    /// An unsupported default is an error, not a panic. Discovery handles an error, and an
    /// arithmetic panic bypasses that handling.
    #[tokio::test]
    async fn an_unsupported_decimals_is_an_error_rather_than_a_panic() {
        assert!(EtherscanClient::resolve_scale_factor(None, reports(79))
            .await
            .is_err());
    }
}
