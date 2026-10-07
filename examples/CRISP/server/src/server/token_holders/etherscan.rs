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
use alloy::sol_types::SolEvent;
use alloy::transports::RpcError;
use e3_sdk::evm_helpers::retry::call_with_retry;
use eyre::{eyre, Context, Result};
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
        function CLOCK_MODE() external view returns (string);
    }

    /// The `BondedVotes` adapter, which sums wallet voting power and bonded collateral.
    /// @dev Its weight comes from contracts that it only reads, so candidate discovery follows
    /// these references to the contracts that emit. The adapter itself emits only
    /// `BondedDelegateChanged`, when an owner moves its bonded weight to a delegate.
    #[sol(rpc)]
    contract BondedVotes {
        function token() external view returns (address);
        function checkpoints() external view returns (address);
        function registry() external view returns (address);
        function escrow() external view returns (address);

        event BondedDelegateChanged(
            address indexed owner,
            address indexed fromDelegate,
            address indexed toDelegate
        );
    }
}

sol! {
    #[sol(rpc)]
    interface VotingEscrow {
        function lockNFT() external view returns (address);
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
    /// The vote-escrow lock NFT whose `Transfer` logs name every escrow position holder. `None`
    /// when the round's token is not an adapter, or when the adapter exposes no escrow.
    ///
    /// Escrow holders are a third source of voting power: `BondedVotes.getPastVotes` sums the
    /// wallet's delegated votes, its bonded collateral, AND its escrow-locked balance. A holder
    /// whose power is entirely escrow-locked appears in none of the token's own logs and owns no
    /// bond, so without this they are never even considered as a candidate.
    pub escrow_lock_nft: Option<Address>,
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

/// True when the node evaluated a metadata call and the token refused it.
///
/// The two failure kinds must stay separate. A revert, or an answer that does not decode, shows
/// that the contract has no usable method, which is permitted. A timeout or a transport failure
/// judged nothing about the contract, and must not be read as an absent method.
fn is_metadata_revert(error: &alloy::contract::Error) -> bool {
    match error {
        // The call succeeded and returned nothing, so the method is absent. A call to an address
        // with no code takes this path as well.
        alloy::contract::Error::ZeroData(..) => true,
        // The node answered, and the answer does not decode.
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

/// A zero divisor would divide by zero, and the contract never stores one for a CUSTOM round.
const ZERO_DIVISOR: &str = "The voting-power divisor must be non-zero";

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
    /// A census timepoint can be a timestamp rather than a block height: `Interfold.request`
    /// assigns `block.timestamp` to `E3.requestBlock`, and a timestamp-clock token records
    /// `snapshotOf` in seconds. Log queries address blocks, so such a timepoint must be converted
    /// before it can bound a `getLogs` range.
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
    ) -> Result<VotingPowerSources> {
        let plain = VotingPowerSources {
            token: round_token,
            registry: None,
            checkpoints: None,
            escrow_lock_nft: None,
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
            return Ok(plain);
        };
        let provider = ProviderBuilder::new().connect_http(url);
        let provider_for_escrow = provider.clone();
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
                return Ok(plain);
            }
        };

        // The escrow's lock NFT, resolved through the adapter. Both hops are optional: an adapter
        // need not expose an escrow, and an escrow need not expose a lock NFT. A revert is that
        // negative answer, and yields `None`.
        //
        // A transport failure is not an answer. It judged nothing about the deployment, and
        // swallowing it would build a census silently missing every escrow-only holder — which
        // looks identical to a deployment that has none.
        let escrow_lock_nft = match adapter.escrow().call().await {
            Ok(escrow) => {
                let escrow_contract = VotingEscrow::new(escrow, provider_for_escrow);
                match escrow_contract.lockNFT().call().await {
                    Ok(nft) => Some(nft),
                    Err(error) if is_metadata_revert(&error) => {
                        log::debug!(
                            "Escrow {} does not answer lockNFT() ({}); treating it as having no \
                             escrow-held voting power",
                            escrow,
                            error
                        );
                        None
                    }
                    Err(error) => {
                        return Err(eyre!(
                            "Could not read lockNFT() from escrow {}: {}",
                            escrow,
                            error
                        ));
                    }
                }
            }
            Err(error) if is_metadata_revert(&error) => {
                log::debug!(
                    "{} does not answer escrow() ({}); treating it as having no escrow-held \
                     voting power",
                    round_token,
                    error
                );
                None
            }
            Err(error) => {
                return Err(eyre!(
                    "Could not read escrow() from {}: {}",
                    round_token,
                    error
                ));
            }
        };

        Ok(VotingPowerSources {
            token: underlying,
            registry: Some(registry),
            // Optional: the registry may not have been pointed at a checkpoint contract yet, in
            // which case `BondOwnerSet` alone still names every bond owner.
            checkpoints: adapter.checkpoints().call().await.ok(),
            escrow_lock_nft,
        })
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
    /// Bonded FOLD carries voting power through a `BondedVotes` adapter, which records no bonds
    /// itself. Its power comes from two places the adapter merely reads, so an address can hold
    /// bonded weight while appearing in no `Transfer` and no `DelegateVotesChanged` log at all —
    /// scanning only the token would miss every operator.
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

    /// Every address that has ever received a vote-escrow lock NFT.
    ///
    /// Escrow positions carry voting power through the adapter's `_lockedVotes` term without
    /// appearing in the token's own `Transfer` or `DelegateVotesChanged` logs — a holder who
    /// acquired FOLD and locked it in one flow never shows up as a wallet holder. They own no
    /// bond either, so neither existing candidate source finds them.
    ///
    /// Current owners are not resolved here, and burns are not subtracted. Over-inclusion is
    /// harmless in exactly the way it is for bond owners: every candidate is verified against
    /// `getPastVotes` at the round's snapshot and dropped if it has no power. Resolving current
    /// ownership instead would be wrong — a position transferred after the snapshot must still
    /// be evaluated at whoever held it then, which only the verification step can decide.
    ///
    /// # Arguments
    /// * `lock_nft` - The escrow's ERC721 lock NFT
    /// * `from_block` - First block to scan
    /// * `to_block` - Last block to scan
    pub async fn get_escrow_holder_candidates(
        &self,
        lock_nft: &str,
        from_block: u64,
        to_block: u64,
    ) -> Result<Vec<Address>> {
        // keccak256("Transfer(address,address,uint256)"). On an ERC721 all three parameters are
        // indexed, so the recipient is topic 2 and the token id topic 3.
        const TRANSFER_TOPIC: &str =
            "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";

        let logs = self
            .get_logs_by_topic(lock_nft, TRANSFER_TOPIC, from_block, to_block)
            .await
            .with_context(|| format!("Escrow lock NFT transfer logs for {}", lock_nft))?;

        Ok(Self::escrow_holders_from_logs(&logs))
    }

    /// The distinct, non-zero recipients named by a set of ERC721 `Transfer` logs.
    ///
    /// Split from the fetch so the decoding rules can be tested without a network: which topic
    /// carries the recipient, that ERC20-shaped logs are skipped, and that mint's zero `from`
    /// never becomes a candidate.
    fn escrow_holders_from_logs(logs: &[TopicLog]) -> Vec<Address> {
        let mut holders: HashSet<Address> = HashSet::new();
        for log in logs {
            // An ERC20 `Transfer` shares this signature but leaves the value unindexed, giving
            // three topics rather than four. Skipping those keeps a misconfigured address from
            // contributing garbage candidates.
            if log.topics.len() < 4 {
                continue;
            }
            if let Some(raw) = log.topics.get(2) {
                if let Ok(holder) = Self::address_from_topic(raw) {
                    if !holder.is_zero() {
                        holders.insert(holder);
                    }
                }
            }
        }

        holders.into_iter().collect()
    }

    /// Every address that a `BondedVotes` adapter named as a bonded delegate.
    ///
    /// An owner moves its bonded weight to a delegate with `delegateBonded`, and the delegate
    /// takes it with `acceptBonded`. A Safe that cannot sign a ballot does this to vote through a
    /// key. That key can hold the weight with no token log, no bond and no escrow position, so no
    /// other source finds it, and the census would drop the weight. The adapter emits
    /// `BondedDelegateChanged` for each change. An adapter deployed before bonded delegation emits
    /// nothing, and this finds nobody.
    ///
    /// Over-inclusion is harmless on the same terms as for bond owners: every candidate is
    /// verified against `getPastVotes` at the round's snapshot.
    ///
    /// # Arguments
    /// * `adapter` - The `BondedVotes` adapter that the round names as its token
    /// * `from_block` - First block to scan
    /// * `to_block` - Last block to scan
    pub async fn get_bonded_delegate_candidates(
        &self,
        adapter: &str,
        from_block: u64,
        to_block: u64,
    ) -> Result<Vec<Address>> {
        let logs = self
            .get_logs_by_topic(
                adapter,
                &format!("{:#x}", BondedVotes::BondedDelegateChanged::SIGNATURE_HASH),
                from_block,
                to_block,
            )
            .await
            .with_context(|| format!("Bonded delegation logs for {}", adapter))?;

        Ok(Self::bonded_delegates_from_logs(&logs))
    }

    /// The distinct, non-zero delegates named by a set of `BondedDelegateChanged` logs.
    ///
    /// Split from the fetch so the topic layout can be tested without a network. The delegate is
    /// `toDelegate`, the third indexed parameter, after the owner and the previous delegate. A
    /// delegation that ends names the zero address, which never becomes a candidate.
    fn bonded_delegates_from_logs(logs: &[TopicLog]) -> Vec<Address> {
        let delegates: HashSet<Address> = logs
            .iter()
            .filter_map(|log| log.topics.get(3))
            .filter_map(|raw| Self::address_from_topic(raw).ok())
            .filter(|delegate| !delegate.is_zero())
            .collect();

        delegates.into_iter().collect()
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

    /// Verify voting power for multiple addresses at an EIP-6372 timepoint.
    ///
    /// `divisor` is the value `CRISPProgram` stored for the round. The contract chose it so that
    /// the census sums to less than the plaintext modulus, using the total supply at the same
    /// snapshot. Every balance is therefore read with `getPastVotes` at that snapshot and divided
    /// by it, never replaced by a current balance, which can exceed that supply. A failed read is
    /// retried, and a voter whose read keeps failing fails the census: `setMerkleRoot` takes one
    /// root, so a voter left out of it could never vote.
    pub async fn verify_voting_power<P: Provider>(
        &self,
        token: &ERC20Votes::ERC20VotesInstance<P>,
        potential_voters: &[PotentialVoter],
        timepoint: u64,
        threshold: U256,
        divisor: U256,
    ) -> Result<Vec<TokenHolder>> {
        eyre::ensure!(!divisor.is_zero(), ZERO_DIVISOR);
        let mut token_holders: Vec<TokenHolder> = Vec::new();

        log::info!(
            "Verifying {} candidates against {} at timepoint {} (divisor={}, threshold={})",
            potential_voters.len(),
            token.address(),
            timepoint,
            divisor,
            threshold
        );

        let mut below_threshold = 0usize;
        let mut rounds_to_zero = 0usize;

        for voter in potential_voters {
            let votes = call_with_retry("getPastVotes", &[], || async {
                Ok(token
                    .getPastVotes(voter.address, U256::from(timepoint))
                    .call()
                    .await?)
            })
            .await
            .map_err(|e| eyre!("Failed to read the votes of {}: {e:#}", voter.address))?;
            if votes >= threshold {
                let scaled_votes = votes / divisor;

                // Both values, because they answer different questions. The raw one is what the
                // chain reports and what a holder recognises as their balance; the scaled one is
                // what the ballot is bounded by, and a mismatch between a census and a tally is
                // almost always a scaling mismatch.
                log::info!(
                    "  eligible {} raw={} scaled={}",
                    voter.address,
                    votes,
                    scaled_votes
                );

                // Above the threshold but worth nothing once scaled: the leaf bounds every ballot
                // to zero, so this address is in the census and can still only cast an empty vote.
                // Worth saying out loud — it looks like eligibility from every angle except the
                // one that counts.
                if scaled_votes.is_zero() {
                    rounds_to_zero += 1;
                    log::warn!(
                        "  {} clears the threshold but scales to zero (raw={}, divisor={}): it \
                         can vote, but carries no weight",
                        voter.address,
                        votes,
                        divisor
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

    /// Get all token holders with voting power at a round's snapshot.
    ///
    /// `snapshot` is the timepoint `CRISPProgram` recorded for the round (`snapshotOf`), in the
    /// census token's EIP-6372 clock units. The divisor was sized against the total supply at
    /// exactly this timepoint, so every balance is read there. Log discovery needs a block: a
    /// block-number clock names it, and a timestamp clock resolves to the last block at or before it.
    pub async fn get_token_holders_with_voting_power(
        &self,
        token_address: Address,
        snapshot: u64,
        rpc_url: &str,
        threshold: U256,
        // The divisor `CRISPProgram` stored for the round.
        divisor: U256,
    ) -> Result<Vec<TokenHolder>> {
        eyre::ensure!(!divisor.is_zero(), ZERO_DIVISOR);
        log::info!("Starting token holder discovery for {}", token_address);

        let sources = Self::resolve_voting_power_sources(token_address, rpc_url)
            .await
            .context("Failed to resolve voting-power sources")?;
        let snapshot_block = match Self::get_clock_mode(token_address, rpc_url).await {
            ClockMode::BlockNumber => snapshot,
            ClockMode::Timestamp => Self::get_block_by_timestamp(snapshot, rpc_url)
                .await
                .context("Failed to resolve snapshot timepoint to a block")?,
        };
        self.get_token_holders_with_voting_power_from_sources(
            token_address,
            snapshot_block,
            snapshot,
            rpc_url,
            threshold,
            divisor,
            sources,
        )
        .await
    }

    /// Scan logs up to `snapshot_block` for candidates, then read each candidate's votes at
    /// `timepoint`, in the census token's clock units.
    #[allow(clippy::too_many_arguments)]
    async fn get_token_holders_with_voting_power_from_sources(
        &self,
        token_address: Address,
        snapshot_block: u64,
        timepoint: u64,
        rpc_url: &str,
        threshold: U256,
        divisor: U256,
        sources: VotingPowerSources,
    ) -> Result<Vec<TokenHolder>> {
        // The adapter logs only bonded delegation. Scan it, and its token, registry and escrow.
        if sources.registry.is_some() {
            log::info!(
                "{} is a bonded-votes adapter: scanning it, token {}, registry {:?} and escrow lock \
                 NFT {:?}",
                token_address,
                sources.token,
                sources.registry,
                sources.escrow_lock_nft
            );
        }
        let scan_token = sources.token;

        // Step 1: Determine the block range
        let start_block = self
            .get_deployment_block(&scan_token.to_string())
            .await
            .context("Failed to get deployment block")?;
        log::info!("Token deployed at block: {}", start_block);
        log::info!(
            "Snapshot timepoint {} resolves to block {}",
            timepoint,
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
        // own logs, and so do the delegates that bond owners gave their bonded weight to. Both are
        // unioned in as candidates. Over-inclusion is harmless: each is verified against
        // `getPastVotes` below and dropped if it has none.
        if let Some(registry) = sources.registry {
            let mut known: HashSet<Address> = potential_voters.iter().map(|v| v.address).collect();
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

            let bonded_delegates = self
                .get_bonded_delegate_candidates(
                    &token_address.to_string(),
                    start_block,
                    snapshot_block,
                )
                .await
                .context("Failed to fetch bonded delegate candidates")?;
            log::info!(
                "Found {} bonded-delegate candidates",
                bonded_delegates.len()
            );

            for candidate in bond_owners.into_iter().chain(bonded_delegates) {
                if known.insert(candidate) {
                    potential_voters.push(PotentialVoter {
                        address: candidate,
                        token_balance: U256::ZERO,
                        has_delegation: false,
                    });
                }
            }
        }

        // Escrow-locked power is the third term of the adapter's sum, and it reaches nobody
        // through the two sources above: a holder who locked FOLD without ever holding it in a
        // wallet has no token logs, and owns no bond. Unioned in on the same terms.
        if let Some(lock_nft) = sources.escrow_lock_nft {
            let known: HashSet<Address> = potential_voters.iter().map(|v| v.address).collect();
            let escrow_holders = self
                .get_escrow_holder_candidates(&lock_nft.to_string(), start_block, snapshot_block)
                .await
                .context("Failed to fetch escrow holder candidates")?;

            log::info!("Found {} escrow-holder candidates", escrow_holders.len());
            for holder in escrow_holders {
                if !known.contains(&holder) {
                    potential_voters.push(PotentialVoter {
                        address: holder,
                        token_balance: U256::ZERO,
                        has_delegation: false,
                    });
                }
            }
        }

        log::info!("Found {} potential voters", potential_voters.len());

        // Step 5: Verify actual voting power.
        let url = rpc_url.parse().context("Failed to parse RPC URL")?;
        let token = ERC20Votes::new(token_address, ProviderBuilder::new().connect_http(url));
        let token_holders = self
            .verify_voting_power(&token, &potential_voters, timepoint, threshold, divisor)
            .await
            .context("Failed to verify voting power")?;

        log::info!(
            "Discovery complete: {} addresses with voting power above threshold",
            token_holders.len()
        );

        Ok(token_holders)
    }

    /// Get token holders with a constant voting credit.
    /// A bonded-votes adapter emits no transfer logs. Discover its underlying token, bond owners
    /// and bonded delegates, then check their votes at the snapshot before assigning the constant
    /// credit.
    /// Plain tokens keep the transfer-log census, which also supports tokens without IVotes.
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

        let sources = Self::resolve_voting_power_sources(token_address, rpc_url)
            .await
            .context("Failed to resolve voting-power sources")?;

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

        if sources.registry.is_some() {
            // `getPastVotes` takes the adapter's own clock units.
            let timepoint = match Self::get_clock_mode(token_address, rpc_url).await {
                ClockMode::Timestamp => snapshot_timepoint,
                ClockMode::BlockNumber => snapshot_block,
            };
            let holders = self
                .get_token_holders_with_voting_power_from_sources(
                    token_address,
                    snapshot_block,
                    timepoint,
                    rpc_url,
                    U256::from(1),
                    U256::from(1),
                    sources,
                )
                .await?;
            return Ok(Self::assign_constant_balance(holders, balance));
        }

        // Step 1: Determine the block range
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

    fn assign_constant_balance(holders: Vec<TokenHolder>, balance: U256) -> Vec<TokenHolder> {
        holders
            .into_iter()
            .map(|holder| TokenHolder {
                address: holder.address,
                balance: balance.to_string(),
            })
            .collect()
    }
}

/// The local-chain census: the first ten Anvil accounts, each with `balance`.
pub fn get_mock_token_holders(balance: &str) -> Vec<TokenHolder> {
    [
        "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
        "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
        "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC",
        "0x90F79bf6EB2c4f870365E785982E1f101E93b906",
        "0x15d34AAf54267DB7D7c367839AAf71A00a2C6A65",
        "0x9965507D1a55bcC2695C58ba16FB37d819B0A4dc",
        "0x976EA74026E726554dB657fA54763abd0C3a0aa9",
        "0x14dC79964da2C08b23698B3D3cc7Ca32193d9955",
        "0x23618e81E3f5cdF7f54C3d65f7FBc0aBf5B21E8f",
        "0xa0Ee7A142d267C1f36714E4a8F75612F20a79720",
    ]
    .into_iter()
    .map(|address| TokenHolder {
        address: address.to_string(),
        balance: balance.to_string(),
    })
    .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::CONFIG;

    /// Left-pad an address into a 32-byte indexed topic.
    fn topic(addr: &str) -> String {
        format!("0x{:0>64}", addr.trim_start_matches("0x"))
    }

    const ZERO: &str = "0x0000000000000000000000000000000000000000";
    const ALICE: &str = "0x680921b11dD10982FAa868ceb0AD16dd2239137A";
    const BOB: &str = "0xBB10585C2cf0E3f7B1346E8F9acb5914391F8ab6";

    /// A mint names its recipient in topic 2; the zero `from` must not become a candidate.
    ///
    /// A lock minted straight to its holder is the case no other candidate source reaches: that
    /// address has no token transfers, no delegation, and no bond.
    #[test]
    fn escrow_mint_names_the_recipient_not_the_zero_address() {
        let logs = vec![TopicLog {
            address: "0xlocknft".to_string(),
            topics: vec![
                "0xddf252ad".to_string(),
                topic(ZERO),
                topic(ALICE),
                "0x11".to_string(),
            ],
        }];

        let holders = EtherscanClient::escrow_holders_from_logs(&logs);

        assert_eq!(holders.len(), 1);
        assert_eq!(holders[0], ALICE.parse::<Address>().unwrap());
    }

    /// An ERC20 `Transfer` shares the signature but leaves the value unindexed, so it carries
    /// three topics. Decoding one as ERC721 would read the wrong slot.
    #[test]
    fn erc20_shaped_transfers_are_skipped() {
        let logs = vec![TopicLog {
            address: "0xtoken".to_string(),
            topics: vec!["0xddf252ad".to_string(), topic(ALICE), topic(BOB)],
        }];

        assert!(EtherscanClient::escrow_holders_from_logs(&logs).is_empty());
    }

    /// A position that changed hands yields both holders. Neither is resolved to a current
    /// owner: whoever held it at the round's snapshot is decided by `getPastVotes`, so both are
    /// offered as candidates and the verification step drops the one with no power.
    #[test]
    fn transferred_positions_offer_both_holders_as_candidates() {
        let logs = vec![
            TopicLog {
                address: "0xlocknft".to_string(),
                topics: vec![
                    "0xddf252ad".to_string(),
                    topic(ZERO),
                    topic(ALICE),
                    "0x11".to_string(),
                ],
            },
            TopicLog {
                address: "0xlocknft".to_string(),
                topics: vec![
                    "0xddf252ad".to_string(),
                    topic(ALICE),
                    topic(BOB),
                    "0x11".to_string(),
                ],
            },
        ];

        let holders = EtherscanClient::escrow_holders_from_logs(&logs);

        assert_eq!(holders.len(), 2);
        assert!(holders.contains(&ALICE.parse::<Address>().unwrap()));
        assert!(holders.contains(&BOB.parse::<Address>().unwrap()));
    }

    /// Repeated transfers to one address must not inflate the candidate list.
    #[test]
    fn repeat_recipients_are_deduplicated() {
        let one = TopicLog {
            address: "0xlocknft".to_string(),
            topics: vec![
                "0xddf252ad".to_string(),
                topic(ZERO),
                topic(ALICE),
                "0x11".to_string(),
            ],
        };
        let logs = vec![one.clone(), one];

        assert_eq!(EtherscanClient::escrow_holders_from_logs(&logs).len(), 1);
    }

    /// The census must find the key that an owner, such as a Safe, gave its bonded weight to. That
    /// key can have no other log at all. The topics come from the ABI, so a wrong index fails here.
    #[test]
    fn bonded_delegation_names_each_delegate_and_never_the_zero_address() {
        let owner = Address::repeat_byte(0xaa);
        let first = Address::repeat_byte(0xbb);
        let second = Address::repeat_byte(0xcc);
        let log = |from: Address, to: Address| TopicLog {
            address: "0xadapter".to_string(),
            topics: BondedVotes::BondedDelegateChanged {
                owner,
                fromDelegate: from,
                toDelegate: to,
            }
            .encode_log_data()
            .topics()
            .iter()
            .map(|topic| format!("{topic:#x}"))
            .collect(),
        };

        // `first` accepts. The owner then moves on, which ends the delegation before `second`
        // accepts.
        let logs = vec![
            log(Address::ZERO, first),
            log(first, Address::ZERO),
            log(Address::ZERO, second),
        ];

        let delegates: HashSet<Address> = EtherscanClient::bonded_delegates_from_logs(&logs)
            .into_iter()
            .collect();
        assert_eq!(delegates, HashSet::from([first, second]));
    }

    /// A transport failure while resolving the escrow must not degrade to "no escrow".
    ///
    /// An unreachable node judged nothing about the deployment. Treating it as an absent
    /// interface would build a census silently missing every escrow-only holder, which is
    /// indistinguishable from a deployment that has none.
    #[tokio::test]
    async fn an_unreachable_node_does_not_become_an_absent_escrow() {
        let result = EtherscanClient::resolve_voting_power_sources(
            "0x028deEA644258c78b1B5B2eacF469F5D781Fb43E"
                .parse()
                .unwrap(),
            "http://127.0.0.1:1",
        )
        .await;

        // The adapter probe fails first and cannot tell a plain token from an unreachable node,
        // so the call either errors or reports a plain token — never an adapter with a silently
        // dropped escrow.
        if let Ok(sources) = result {
            assert!(
                sources.registry.is_none() && sources.escrow_lock_nft.is_none(),
                "an unreachable node must not report a partially resolved adapter"
            );
        }
    }

    /// An unparsable RPC URL is a configuration fault, not a chain answer, and resolves to a
    /// plain token with no sources rather than a partially filled one.
    #[tokio::test]
    async fn an_unparsable_rpc_url_resolves_to_a_plain_token() {
        let sources = EtherscanClient::resolve_voting_power_sources(
            "0x028deEA644258c78b1B5B2eacF469F5D781Fb43E"
                .parse()
                .unwrap(),
            "not a url",
        )
        .await
        .expect("an unparsable URL is reported as a plain token, not an error");

        assert!(sources.registry.is_none());
        assert!(sources.checkpoints.is_none());
        assert!(sources.escrow_lock_nft.is_none());
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
    fn constant_credit_preserves_verified_voters() {
        let voters = vec![TokenHolder {
            address: "0x0000000000000000000000000000000000000001".to_string(),
            balance: "200000000000000000000".to_string(),
        }];

        let credited = EtherscanClient::assign_constant_balance(voters, U256::from(1));
        assert_eq!(credited.len(), 1);
        assert_eq!(credited[0].balance, "1");
    }

    // Integration tests (requires valid API key)
    #[tokio::test]
    #[ignore]
    async fn test_get_token_holders_with_voting_power() {
        let token = "0xb0BE360719f84c5351621590B7FfBD8EB0B46B5d";
        let token_address: Address = token.parse().unwrap();
        let chain_id = CONFIG.chain_id;
        let api_key = &CONFIG.etherscan_api_key;
        let rpc_url = &CONFIG.http_rpc_url;
        let threshold = U256::ZERO;
        // `snapshotOf` is in the clock units of the token. This token runs a block-number clock,
        // and Sepolia block 9471180 was mined at timestamp 1761201108.
        let snapshot = 9471180;

        let client = EtherscanClient::new(api_key.to_string(), chain_id);
        let res = client
            .get_token_holders_with_voting_power(
                token_address,
                snapshot,
                rpc_url,
                threshold,
                // The divisor `CRISPProgram` stored for the round.
                U256::from(1),
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

/// `verify_voting_power` refuses what would mis-scale a census or leave a voter out of it.
#[cfg(test)]
mod verify_voting_power_tests {
    use super::{ERC20Votes, EtherscanClient, PotentialVoter};
    use alloy::primitives::{Address, Bytes, U256};
    use alloy::providers::ProviderBuilder;
    use alloy::transports::mock::Asserter;

    /// The addresses `verify_voting_power` keeps, with `responses` answering each `getPastVotes`.
    async fn verify(
        responses: Asserter,
        voters: &[Address],
        divisor: U256,
    ) -> eyre::Result<Vec<String>> {
        let token = ERC20Votes::new(
            Address::repeat_byte(1),
            ProviderBuilder::default().connect_mocked_client(responses),
        );
        let voters: Vec<PotentialVoter> = voters
            .iter()
            .map(|&address| PotentialVoter {
                address,
                token_balance: U256::ZERO,
                has_delegation: true,
            })
            .collect();
        let holders = EtherscanClient::new("test_key".to_string(), 1)
            .verify_voting_power(&token, &voters, 1, U256::from(1), divisor)
            .await?;
        Ok(holders.into_iter().map(|holder| holder.address).collect())
    }

    /// A zero divisor would divide by zero, and the contract never stores one for a CUSTOM round.
    #[tokio::test]
    async fn a_zero_divisor_is_refused() {
        assert!(verify(Asserter::new(), &[], U256::ZERO).await.is_err());
        assert!(verify(Asserter::new(), &[], U256::from(1))
            .await
            .unwrap()
            .is_empty());
    }

    /// `setMerkleRoot` takes one root, so a voter left out of a census can never vote. A read that
    /// fails once is retried, and a read that keeps failing fails the whole census.
    #[tokio::test(start_paused = true)]
    async fn a_census_never_leaves_out_a_voter_it_cannot_read() {
        let (alice, bob) = (Address::repeat_byte(0xa), Address::repeat_byte(0xb));
        let votes = Bytes::from(U256::from(7).to_be_bytes::<32>());

        let flaky = Asserter::new();
        flaky.push_failure_msg("the node lags");
        flaky.push_success(&votes);
        assert_eq!(
            verify(flaky, &[alice], U256::from(1)).await.unwrap(),
            [alice.to_string()]
        );

        // Alice reads. Every read of Bob fails, because no response is left.
        let failing = Asserter::new();
        failing.push_success(&votes);
        assert!(verify(failing, &[alice, bob], U256::from(1)).await.is_err());
    }
}
