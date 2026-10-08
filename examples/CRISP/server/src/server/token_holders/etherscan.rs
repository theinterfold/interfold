// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Token-census discovery: Etherscan logs name the candidates, `getPastVotes` decides who votes.
//!
//! Over-inclusion is free. Every candidate is verified against `getPastVotes` at the round's
//! snapshot and dropped if it has no power, so each source scans more widely rather than trusting
//! one. A holder that no source names is lost for good: `setMerkleRoot` takes one root.

use super::requester_census::MAX_CENSUS_SIZE;
use crate::server::models::TokenHolder;
use crate::server::rpc::{self, HTTP};
use alloy::eips::BlockNumberOrTag;
use alloy::primitives::{Address, B256, U256};
use alloy::providers::{DynProvider, Provider};
use alloy::sol;
use alloy::sol_types::SolEvent;
use alloy::transports::RpcError;
use e3_sdk::evm_helpers::retry::call_with_retry;
use eyre::{ensure, eyre, Context, Result};
use serde::{de::DeserializeOwned, Deserialize};
use std::collections::{HashMap, HashSet};
use tokio::sync::Mutex;
use tokio::time::{sleep, Duration, Instant};

sol! {
    #[sol(rpc)]
    contract ERC20Votes {
        function getPastVotes(address account, uint256 timepoint) external view returns (uint256);
        function CLOCK_MODE() external view returns (string);

        event Transfer(address indexed from, address indexed to, uint256 value);
        event DelegateVotesChanged(address indexed delegate, uint256 previousVotes, uint256 newVotes);
    }

    /// The `BondedVotes` adapter sums wallet voting power and bonded collateral. Its weight comes
    /// from contracts that it only reads, so discovery follows these references to the contracts
    /// that emit. The adapter itself emits only `BondedDelegateChanged`.
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

    contract BondingRegistry {
        event BondOwnerSet(address indexed operator, address indexed bondOwner);
    }

    contract BondedCheckpoints {
        event BondedCheckpointed(address indexed bondOwner, uint48 indexed timepoint, uint256 amount);
    }

    #[sol(rpc)]
    interface VotingEscrow {
        function lockNFT() external view returns (address);
    }
}

/// Where a round's voting power is emitted from, resolved from the token the round names.
#[derive(Debug)]
struct VotingPowerSources {
    /// The ERC20Votes token whose logs carry wallet voting power: the round's token for a plain
    /// token, the adapter's underlying one otherwise.
    token: Address,
    /// The bonding registry emitting `BondOwnerSet`. `None` when the round's token is not an
    /// adapter.
    registry: Option<Address>,
    /// The contract emitting `BondedCheckpointed`, when one is configured.
    checkpoints: Option<Address>,
    /// The vote-escrow lock NFT whose `Transfer` logs name every escrow position holder.
    /// `BondedVotes.getPastVotes` sums wallet votes, bonded collateral AND escrow-locked balance,
    /// so a holder whose power is all escrow-locked appears in no other source.
    escrow_lock_nft: Option<Address>,
}

/// Which unit a census token's `getPastVotes` timepoint is denominated in (EIP-6372). The token
/// sets it, not Interfold, so it is read per token.
#[derive(Debug)]
enum ClockMode {
    BlockNumber,
    Timestamp,
}

#[derive(Debug)]
struct PotentialVoter {
    address: Address,
    token_balance: U256,
    has_delegation: bool,
}

/// True when the node evaluated a metadata call and the token refused it.
///
/// A revert, or an answer that does not decode, shows that the contract has no usable method,
/// which is permitted. A timeout or transport failure judged nothing about the contract and must
/// not be read as an absent method.
fn is_metadata_revert(error: &alloy::contract::Error) -> bool {
    match error {
        // The call succeeded and returned nothing, as a call to an address with no code does.
        alloy::contract::Error::ZeroData(..) => true,
        alloy::contract::Error::AbiError(_) => true,
        alloy::contract::Error::TransportError(RpcError::ErrorResp(payload)) => {
            payload.as_revert_data().is_some() || payload.message.to_lowercase().contains("revert")
        }
        _ => false,
    }
}

/// `Some(value)` for an answer, `None` for a metadata revert, `Err` for anything else.
fn optional<T>(result: Result<T, alloy::contract::Error>, what: &str) -> Result<Option<T>> {
    match result {
        Ok(value) => Ok(Some(value)),
        Err(error) if is_metadata_revert(&error) => {
            log::debug!("{what} is not answered ({error}); treating it as absent");
            Ok(None)
        }
        Err(error) => Err(eyre!("Could not read {what}: {error}")),
    }
}

const ETHERSCAN_API_URL: &str = "https://api.etherscan.io/v2/api";

/// Etherscan rejects calls above a per-key ceiling (3/sec on the free tier) outright rather than
/// queueing them. 500ms leaves headroom for retries and for other users of the key.
const MIN_REQUEST_INTERVAL: Duration = Duration::from_millis(500);

/// How many times a failed request is retried before giving up.
const RATE_LIMIT_RETRIES: u32 = 5;

/// The `offset` of a `getLogs` page; a shorter page ends the scan.
const PAGE_SIZE: usize = 10_000;

/// Pause between `getPastVotes` reads.
const VERIFY_PACING: Duration = Duration::from_millis(50);

/// A zero divisor would divide by zero, and the contract never stores one for a CUSTOM round.
const ZERO_DIVISOR: &str = "The voting-power divisor must be non-zero";

#[derive(Deserialize)]
struct EtherscanResponse {
    status: String,
    message: String,
    result: Option<serde_json::Value>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ContractCreation {
    block_number: String,
}

/// The parts of an Etherscan log that discovery reads.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Log {
    topics: Vec<String>,
    #[serde(default)]
    data: String,
    #[serde(default)]
    block_number: String,
}

enum Failure {
    Retry(eyre::Report),
    Fatal(eyre::Report),
}

/// When the last Etherscan request started. Process-wide, so concurrent rounds share one spacing
/// schedule. The lock is held across the wait so callers queue instead of firing together.
static LAST_REQUEST: Mutex<Option<Instant>> = Mutex::const_new(None);

async fn throttle() {
    let mut last = LAST_REQUEST.lock().await;
    if let Some(previous) = *last {
        sleep(MIN_REQUEST_INTERVAL.saturating_sub(previous.elapsed())).await;
    }
    *last = Some(Instant::now());
}

/// Client for token-holder discovery through the Etherscan API and the chain RPC.
pub struct EtherscanClient {
    api_key: String,
    chain_id: u64,
}

impl EtherscanClient {
    pub fn new(api_key: String, chain_id: u64) -> Self {
        Self { api_key, chain_id }
    }

    async fn get_deployment_block(&self, token: Address) -> Result<u64> {
        let params = [
            ("module", "contract".to_string()),
            ("action", "getcontractcreation".to_string()),
            ("contractaddresses", token.to_string()),
        ];
        let creations: Vec<ContractCreation> = self
            .fetch(&params, "contract creation")
            .await?
            .unwrap_or_default();
        let creation = creations
            .first()
            .ok_or_else(|| eyre!("No deployment data found for {token}"))?;

        parse_block_number(&creation.block_number).ok_or_else(|| {
            eyre!(
                "Unparsable deployment block '{}' for {token}",
                creation.block_number
            )
        })
    }

    /// Fetch every log of one `topic0` from one contract, paging until a short page.
    async fn get_logs(
        &self,
        address: Address,
        topic0: B256,
        from_block: u64,
        to_block: u64,
    ) -> Result<Vec<Log>> {
        let mut all_logs = Vec::new();
        for page in 1u32.. {
            let params = [
                ("module", "logs".to_string()),
                ("action", "getLogs".to_string()),
                ("address", address.to_string()),
                ("fromBlock", from_block.to_string()),
                ("toBlock", to_block.to_string()),
                ("topic0", format!("{topic0:#x}")),
                ("page", page.to_string()),
                ("offset", PAGE_SIZE.to_string()),
            ];
            let logs: Vec<Log> = self
                .fetch(&params, "logs")
                .await
                .with_context(|| format!("Logs page {page} for {address}"))?
                .unwrap_or_default();

            let page_len = logs.len();
            all_logs.extend(logs);
            if page_len < PAGE_SIZE {
                break;
            }
        }
        Ok(all_logs)
    }

    /// Fetch one Etherscan result, retrying transport failures, 429, 5xx and in-band rate limits
    /// with exponential backoff. The ceiling is per API key, so spacing alone cannot prevent
    /// rejections. `Ok(None)` is the "No records found" answer, a legitimate empty result.
    async fn fetch<T: DeserializeOwned>(
        &self,
        params: &[(&str, String)],
        what: &str,
    ) -> Result<Option<T>> {
        let mut backoff = MIN_REQUEST_INTERVAL;
        let mut retries = 0;
        loop {
            throttle().await;
            match self.request(params, what).await {
                Ok(result) => return Ok(result),
                Err(Failure::Retry(error)) if retries < RATE_LIMIT_RETRIES => {
                    retries += 1;
                    log::warn!(
                        "Etherscan {what} request failed (attempt {retries}/{}): {error:#}; \
                         retrying in {backoff:?}",
                        RATE_LIMIT_RETRIES + 1
                    );
                    sleep(backoff).await;
                    backoff *= 2;
                }
                Err(Failure::Retry(error) | Failure::Fatal(error)) => return Err(error),
            }
        }
    }

    async fn request<T: DeserializeOwned>(
        &self,
        params: &[(&str, String)],
        what: &str,
    ) -> Result<Option<T>, Failure> {
        // `reqwest` errors embed the request URL, which carries the API key; strip it.
        let transport = |error: reqwest::Error, doing: &str| {
            Failure::Retry(
                eyre::Report::new(error.without_url())
                    .wrap_err(format!("Failed to {doing} {what} Etherscan request")),
            )
        };

        let response = HTTP
            .get(ETHERSCAN_API_URL)
            .query(&[
                ("chainid", self.chain_id.to_string()),
                ("apikey", self.api_key.clone()),
            ])
            .query(params)
            .send()
            .await
            .map_err(|error| transport(error, "send"))?;
        let status = response.status();
        if status == reqwest::StatusCode::TOO_MANY_REQUESTS || status.is_server_error() {
            return Err(Failure::Retry(eyre!(
                "Etherscan {what} request returned HTTP {status}"
            )));
        }
        let body = response
            .text()
            .await
            .map_err(|error| transport(error, "read the body of"))?;

        // Etherscan reports every failure in-band: HTTP 200, `status: "0"`, and the explanation
        // in `result` as a bare string. Typing `result` first would turn each of them (invalid
        // key, rate limit, Pro-only endpoint) into an indistinguishable decode error.
        let envelope: EtherscanResponse = serde_json::from_str(&body)
            .with_context(|| {
                format!(
                    "Failed to parse {what} response envelope; body was: {}",
                    body.chars().take(500).collect::<String>()
                )
            })
            .map_err(Failure::Fatal)?;

        if envelope.status != "1" {
            if envelope.message.eq_ignore_ascii_case("No records found") {
                return Ok(None);
            }
            // `message` is usually just "NOTOK"; `result` carries the explanation.
            let detail = match envelope.result {
                Some(serde_json::Value::String(text)) if !text.is_empty() => text,
                _ => envelope.message,
            };
            let error = eyre!("Etherscan {what} request failed: {detail}");
            return Err(if is_rate_limited(&detail) {
                Failure::Retry(error)
            } else {
                Failure::Fatal(error)
            });
        }

        envelope
            .result
            .map(serde_json::from_value)
            .transpose()
            .with_context(|| format!("Failed to parse {what} result payload"))
            .map_err(Failure::Fatal)
    }

    /// Addresses named as `bondOwner` by a `BondingRegistry`, and by the checkpoint contract it
    /// writes to.
    ///
    /// `BondOwnerSet` is the complete source: it is emitted when an operator first names an owner
    /// and on every ownership transfer. It also covers owners that bonded before the checkpoint
    /// contract was configured, which has no backfill. `BondedCheckpointed` is scanned as the
    /// cheaper filter for the common case.
    async fn get_bond_owner_candidates(
        &self,
        registry: Address,
        checkpoints: Option<Address>,
        from_block: u64,
        to_block: u64,
    ) -> Result<HashSet<Address>> {
        // `bondOwner` is the second indexed parameter of `BondOwnerSet(operator, bondOwner)` and
        // the first of `BondedCheckpointed(bondOwner, timepoint, amount)`.
        let sources = [
            (
                Some(registry),
                BondingRegistry::BondOwnerSet::SIGNATURE_HASH,
                2,
            ),
            (
                checkpoints,
                BondedCheckpoints::BondedCheckpointed::SIGNATURE_HASH,
                1,
            ),
        ];
        let mut owners = HashSet::new();
        for (address, topic0, owner_index) in sources {
            let Some(address) = address else { continue };
            let logs = self
                .get_logs(address, topic0, from_block, to_block)
                .await
                .with_context(|| format!("Bond owner logs for {address}"))?;
            owners.extend(topic_addresses(&logs, owner_index));
        }
        Ok(owners)
    }

    /// Every address that has received a vote-escrow lock NFT.
    ///
    /// Current owners are not resolved and burns are not subtracted: a position transferred after
    /// the snapshot must still be evaluated at whoever held it then, which only `getPastVotes`
    /// can decide.
    async fn get_escrow_holder_candidates(
        &self,
        lock_nft: Address,
        from_block: u64,
        to_block: u64,
    ) -> Result<HashSet<Address>> {
        let logs = self
            .get_logs(
                lock_nft,
                ERC20Votes::Transfer::SIGNATURE_HASH,
                from_block,
                to_block,
            )
            .await
            .with_context(|| format!("Escrow lock NFT transfer logs for {lock_nft}"))?;
        Ok(escrow_holders_from_logs(&logs))
    }

    /// Every delegate that a `BondedVotes` adapter named through `BondedDelegateChanged`.
    ///
    /// A Safe that cannot sign a ballot moves its bonded weight to a key. That key can hold the
    /// weight with no token log, no bond and no escrow position, so no other source finds it and
    /// the census would drop the weight. An adapter that predates bonded delegation emits nothing
    /// and finds nobody.
    async fn get_bonded_delegate_candidates(
        &self,
        adapter: Address,
        from_block: u64,
        to_block: u64,
    ) -> Result<HashSet<Address>> {
        let logs = self
            .get_logs(
                adapter,
                BondedVotes::BondedDelegateChanged::SIGNATURE_HASH,
                from_block,
                to_block,
            )
            .await
            .with_context(|| format!("Bonded delegation logs for {adapter}"))?;
        Ok(bonded_delegates_from_logs(&logs))
    }

    /// Every candidate for a round: wallet holders and delegates from the token's logs, plus, for
    /// an adapter, bond owners, bonded delegates and escrow holders.
    async fn discover_candidates(
        &self,
        round_token: Address,
        sources: &VotingPowerSources,
        snapshot_block: u64,
    ) -> Result<Vec<PotentialVoter>> {
        let start_block = self
            .get_deployment_block(sources.token)
            .await
            .context("Failed to get deployment block")?;
        log::info!(
            "Scanning {} from block {start_block} to {snapshot_block}",
            sources.token
        );

        let transfers = self
            .get_logs(
                sources.token,
                ERC20Votes::Transfer::SIGNATURE_HASH,
                start_block,
                snapshot_block,
            )
            .await
            .context("Failed to fetch transfer logs")?;
        let delegations = self
            .get_logs(
                sources.token,
                ERC20Votes::DelegateVotesChanged::SIGNATURE_HASH,
                start_block,
                snapshot_block,
            )
            .await
            .context("Failed to fetch delegation logs")?;
        let mut voters = get_potential_voters(&transfers, &delegations);
        let known: HashSet<Address> = voters.iter().map(|voter| voter.address).collect();

        // The adapter's own logs hold only bonded delegation, and it is the round's token, not
        // `sources.token`, that emits them.
        let mut extra = HashSet::new();
        if let Some(registry) = sources.registry {
            extra.extend(
                self.get_bond_owner_candidates(
                    registry,
                    sources.checkpoints,
                    start_block,
                    snapshot_block,
                )
                .await
                .context("Failed to fetch bond owner candidates")?,
            );
            extra.extend(
                self.get_bonded_delegate_candidates(round_token, start_block, snapshot_block)
                    .await
                    .context("Failed to fetch bonded delegate candidates")?,
            );
        }
        if let Some(lock_nft) = sources.escrow_lock_nft {
            extra.extend(
                self.get_escrow_holder_candidates(lock_nft, start_block, snapshot_block)
                    .await
                    .context("Failed to fetch escrow holder candidates")?,
            );
        }
        voters.extend(
            extra
                .into_iter()
                .filter(|address| !known.contains(address))
                .map(|address| PotentialVoter {
                    address,
                    token_balance: U256::ZERO,
                    has_delegation: false,
                }),
        );

        ensure!(
            voters.len() <= MAX_CENSUS_SIZE,
            "{} candidates exceed the {MAX_CENSUS_SIZE} the eligibility tree can hold",
            voters.len()
        );
        log::info!("Found {} potential voters", voters.len());
        Ok(voters)
    }

    /// Token holders with voting power at a round's snapshot.
    ///
    /// `snapshot` is the timepoint `CRISPProgram` recorded (`snapshotOf`), in the census token's
    /// clock units. The divisor was sized against the total supply at exactly this timepoint, so
    /// every balance is read there. Log discovery needs a block: a block-number clock names it, a
    /// timestamp clock resolves to the last block at or before it.
    pub async fn get_token_holders_with_voting_power(
        &self,
        token_address: Address,
        snapshot: u64,
        rpc_url: &str,
        threshold: U256,
        divisor: U256,
    ) -> Result<Vec<TokenHolder>> {
        ensure!(!divisor.is_zero(), ZERO_DIVISOR);
        log::info!("Starting token holder discovery for {token_address}");

        let provider = rpc::http_provider(rpc_url)?;
        let sources = resolve_voting_power_sources(&provider, token_address)
            .await
            .context("Failed to resolve voting-power sources")?;
        let snapshot_block = match get_clock_mode(&provider, token_address).await? {
            ClockMode::BlockNumber => snapshot,
            ClockMode::Timestamp => block_at_or_before(&provider, snapshot)
                .await
                .context("Failed to resolve snapshot timepoint to a block")?,
        };
        let candidates = self
            .discover_candidates(token_address, &sources, snapshot_block)
            .await?;

        let token = ERC20Votes::new(token_address, provider);
        let holders = verify_voting_power(&token, &candidates, snapshot, threshold, divisor)
            .await
            .context("Failed to verify voting power")?;
        log::info!("Discovery complete: {} voters", holders.len());
        Ok(holders)
    }

    /// Token holders that each get a constant voting credit.
    ///
    /// A bonded-votes adapter emits no transfer logs, so its candidates are checked with
    /// `getPastVotes` at the snapshot before the credit is assigned. Plain tokens keep the
    /// transfer-log census, which also supports tokens without IVotes. Eligibility there rests on
    /// the logs alone, so the scan must not reach past the census timepoint.
    pub async fn get_token_holders_with_constant_balance(
        &self,
        token_address: Address,
        snapshot_timepoint: u64,
        rpc_url: &str,
        balance: U256,
    ) -> Result<Vec<TokenHolder>> {
        log::info!("Starting token holder discovery (constant balance) for {token_address}");

        let provider = rpc::http_provider(rpc_url)?;
        let sources = resolve_voting_power_sources(&provider, token_address)
            .await
            .context("Failed to resolve voting-power sources")?;
        let snapshot_block = block_at_or_before(&provider, snapshot_timepoint)
            .await
            .context("Failed to resolve snapshot timepoint to a block")?;
        // `getPastVotes` takes the adapter's own clock units.
        let adapter_timepoint = match sources.registry {
            Some(_) => Some(match get_clock_mode(&provider, token_address).await? {
                ClockMode::Timestamp => snapshot_timepoint,
                ClockMode::BlockNumber => snapshot_block,
            }),
            None => None,
        };
        let candidates = self
            .discover_candidates(token_address, &sources, snapshot_block)
            .await?;

        let holders: Vec<TokenHolder> = match adapter_timepoint {
            Some(timepoint) => {
                let token = ERC20Votes::new(token_address, provider);
                let one = U256::from(1);
                verify_voting_power(&token, &candidates, timepoint, one, one)
                    .await
                    .context("Failed to verify voting power")?
                    .into_iter()
                    .map(|holder| TokenHolder {
                        balance: balance.to_string(),
                        ..holder
                    })
                    .collect()
            }
            None => candidates
                .into_iter()
                .filter(|voter| voter.token_balance > U256::ZERO || voter.has_delegation)
                .map(|voter| TokenHolder {
                    address: voter.address.to_string(),
                    balance: balance.to_string(),
                })
                .collect(),
        };
        log::info!("Discovery complete: {} eligible addresses", holders.len());
        Ok(holders)
    }
}

fn is_rate_limited(detail: &str) -> bool {
    let detail = detail.to_ascii_lowercase();
    detail.contains("rate limit") || detail.contains("too many requests")
}

/// Resolve where a round's voting power is emitted from.
///
/// A `BondedVotes` adapter exposes `token()`, `registry()`, `checkpoints()` and `escrow()`, so
/// probing them tells whether bonded collateral is in play without configuring which deployment
/// is the governance one. A plain ERC20Votes token answers none and is scanned alone. Only a
/// metadata revert is an answer: a transport failure is an error, because treating it as a plain
/// token would build a census silently missing every bonded and escrow-only holder.
async fn resolve_voting_power_sources(
    provider: &DynProvider,
    round_token: Address,
) -> Result<VotingPowerSources> {
    let adapter = BondedVotes::new(round_token, provider.clone());
    let plain = VotingPowerSources {
        token: round_token,
        registry: None,
        checkpoints: None,
        escrow_lock_nft: None,
    };

    let Some(underlying) = optional(adapter.token().call().await, "token()")? else {
        return Ok(plain);
    };
    let Some(registry) = optional(adapter.registry().call().await, "registry()")? else {
        return Ok(plain);
    };
    // Both hops are optional: an adapter need not expose an escrow, nor an escrow a lock NFT.
    let escrow_lock_nft = match optional(adapter.escrow().call().await, "escrow()")? {
        Some(escrow) => optional(
            VotingEscrow::new(escrow, provider.clone())
                .lockNFT()
                .call()
                .await,
            "lockNFT()",
        )?,
        None => None,
    };

    Ok(VotingPowerSources {
        token: underlying,
        registry: Some(registry),
        // The registry may not point at a checkpoint contract yet; `BondOwnerSet` alone then
        // still names every bond owner.
        checkpoints: optional(adapter.checkpoints().call().await, "checkpoints()")?,
        escrow_lock_nft,
    })
}

/// A token without `CLOCK_MODE()` checkpoints on `block.number`, as does OpenZeppelin's default.
async fn get_clock_mode(provider: &DynProvider, token: Address) -> Result<ClockMode> {
    let mode = optional(
        ERC20Votes::new(token, provider.clone())
            .CLOCK_MODE()
            .call()
            .await,
        "CLOCK_MODE()",
    )?;
    Ok(match mode {
        Some(mode) if mode.contains("mode=timestamp") => ClockMode::Timestamp,
        _ => ClockMode::BlockNumber,
    })
}

/// The highest block mined at or before an EIP-6372 timestamp timepoint.
///
/// `Interfold.request` assigns `block.timestamp` to `E3.requestBlock`, and a timestamp-clock
/// token records `snapshotOf` in seconds, while log queries address blocks. Etherscan's
/// `getblocknobytime` is Pro-only, so this binary-searches over RPC; the search also pins the
/// boundary exactly, including every block that counts at the timepoint and none that follow.
async fn block_at_or_before(provider: &impl Provider, timestamp: u64) -> Result<u64> {
    let block_timestamp = |number: u64| async move {
        provider
            .get_block_by_number(BlockNumberOrTag::Number(number))
            .await
            .with_context(|| format!("Failed to fetch block {number}"))?
            .map(|block| block.header.timestamp)
            .ok_or_else(|| eyre!("Block {number} not found"))
    };

    let latest = provider
        .get_block_number()
        .await
        .context("Failed to fetch latest block number")?;

    // The census is built moments after the request is mined, so the head can precede the timepoint.
    if block_timestamp(latest).await? <= timestamp {
        return Ok(latest);
    }
    ensure!(
        block_timestamp(0).await? <= timestamp,
        "Timestamp {timestamp} predates the genesis block; it is not a valid timepoint"
    );

    // `lo` is always at or before the timepoint, `hi` always after it.
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

/// Read each candidate's votes at `timepoint` and keep those at or above `threshold`, scaled by
/// `divisor` (the value `CRISPProgram` stored, sized so the census sums below the plaintext
/// modulus).
///
/// Balances are read with `getPastVotes` at the snapshot, never replaced by a current balance,
/// which can exceed the supply that sized the divisor. A failed read is retried; a voter whose
/// read keeps failing fails the census, because a voter left out of the one root can never vote.
async fn verify_voting_power<P: Provider>(
    token: &ERC20Votes::ERC20VotesInstance<P>,
    potential_voters: &[PotentialVoter],
    timepoint: u64,
    threshold: U256,
    divisor: U256,
) -> Result<Vec<TokenHolder>> {
    ensure!(!divisor.is_zero(), ZERO_DIVISOR);
    log::info!(
        "Verifying {} candidates against {} at timepoint {timepoint} (divisor={divisor}, \
         threshold={threshold})",
        potential_voters.len(),
        token.address()
    );

    let mut token_holders = Vec::new();
    let mut below_threshold = 0usize;
    let mut scale_to_zero = 0usize;

    for voter in potential_voters {
        let votes = call_with_retry("getPastVotes", &[], || async {
            Ok(token
                .getPastVotes(voter.address, U256::from(timepoint))
                .call()
                .await?)
        })
        .await
        .map_err(|e| eyre!("Failed to read the votes of {}: {e:#}", voter.address))?;

        if votes < threshold {
            below_threshold += 1;
            log::debug!("skipped {} raw={votes} below threshold", voter.address);
        } else {
            let scaled_votes = votes / divisor;
            log::debug!(
                "eligible {} raw={votes} scaled={scaled_votes}",
                voter.address
            );
            // In the census, but every ballot is bounded to zero by the leaf.
            scale_to_zero += usize::from(scaled_votes.is_zero());
            token_holders.push(TokenHolder {
                address: voter.address.to_string(),
                balance: scaled_votes.to_string(),
            });
        }

        sleep(VERIFY_PACING).await;
    }

    log::info!(
        "Verified: {} eligible, {below_threshold} below threshold, {scale_to_zero} scale to zero \
         (can vote, carry no weight)",
        token_holders.len()
    );
    Ok(token_holders)
}

/// Wallet holders from the balances implied by `Transfer` logs, plus every delegate named by
/// `DelegateVotesChanged` logs, which may hold no tokens of their own.
fn get_potential_voters(transfers: &[Log], delegations: &[Log]) -> Vec<PotentialVoter> {
    // `DelegateVotesChanged(delegate, ..)`: the delegate is topic 1.
    let delegates = topic_addresses(delegations, 1);
    let mut voters: HashMap<Address, PotentialVoter> = compute_balances_from_logs(transfers)
        .into_iter()
        .map(|(address, token_balance)| {
            let voter = PotentialVoter {
                address,
                token_balance,
                has_delegation: delegates.contains(&address),
            };
            (address, voter)
        })
        .collect();
    for address in delegates {
        voters.entry(address).or_insert(PotentialVoter {
            address,
            token_balance: U256::ZERO,
            has_delegation: true,
        });
    }
    voters.into_values().collect()
}

/// Balances implied by `Transfer` logs, applied in block order. Ties keep Etherscan's ascending
/// order, which the saturating math relies on to see a mint before a burn in the same block.
fn compute_balances_from_logs(logs: &[Log]) -> HashMap<Address, U256> {
    let mut ordered: Vec<&Log> = logs.iter().collect();
    ordered.sort_by_cached_key(|log| parse_block_number(&log.block_number).unwrap_or(0));

    let mut balances: HashMap<Address, U256> = HashMap::new();
    for log in ordered {
        let [_, from, to, ..] = log.topics.as_slice() else {
            continue;
        };
        let (Some(from), Some(to)) = (topic_address(from), topic_address(to)) else {
            continue;
        };
        let value = U256::from_str_radix(log.data.strip_prefix("0x").unwrap_or(&log.data), 16)
            .unwrap_or_default();

        if !from.is_zero() {
            let balance = balances.entry(from).or_default();
            *balance = balance.saturating_sub(value);
        }
        if !to.is_zero() {
            let balance = balances.entry(to).or_default();
            *balance = balance.saturating_add(value);
        }
    }
    balances
}

/// The distinct, non-zero addresses carried by topic `index` of each log.
fn topic_addresses<'a>(logs: impl IntoIterator<Item = &'a Log>, index: usize) -> HashSet<Address> {
    logs.into_iter()
        .filter_map(|log| log.topics.get(index))
        .filter_map(|topic| topic_address(topic))
        .filter(|address| !address.is_zero())
        .collect()
}

/// Recipients of ERC721 `Transfer` logs, where all three parameters are indexed: the recipient is
/// topic 2. An ERC20 `Transfer` shares the signature but leaves the value unindexed, giving three
/// topics; those are skipped so a misconfigured address contributes no garbage candidates. A
/// mint's zero `from` never becomes a candidate.
fn escrow_holders_from_logs(logs: &[Log]) -> HashSet<Address> {
    topic_addresses(logs.iter().filter(|log| log.topics.len() >= 4), 2)
}

/// Delegates of `BondedDelegateChanged(owner, fromDelegate, toDelegate)` logs: `toDelegate` is
/// topic 3. A delegation that ends names the zero address, which never becomes a candidate.
fn bonded_delegates_from_logs(logs: &[Log]) -> HashSet<Address> {
    topic_addresses(logs, 3)
}

/// Decode an address from a left-padded 32-byte topic.
fn topic_address(topic: &str) -> Option<Address> {
    topic.parse::<B256>().ok().map(Address::from_word)
}

/// A block number in hex (`0x…`) or decimal.
fn parse_block_number(block_number: &str) -> Option<u64> {
    match block_number.strip_prefix("0x") {
        Some(hex) => u64::from_str_radix(hex, 16).ok(),
        None => block_number.parse().ok(),
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
    use alloy::primitives::{address, Bytes};
    use alloy::providers::ProviderBuilder;
    use alloy::transports::mock::Asserter;

    const ZERO: &str = "0x0000000000000000000000000000000000000000";
    const ALICE: &str = "0x680921b11dD10982FAa868ceb0AD16dd2239137A";
    const BOB: &str = "0xBB10585C2cf0E3f7B1346E8F9acb5914391F8ab6";

    /// Left-pad an address into a 32-byte indexed topic.
    fn topic(addr: &str) -> String {
        format!("0x{:0>64}", addr.trim_start_matches("0x"))
    }

    fn log(topics: &[&str], data: &str) -> Log {
        Log {
            topics: topics.iter().map(|topic| topic.to_string()).collect(),
            data: data.to_string(),
            block_number: "0x1".to_string(),
        }
    }

    /// `Transfer(from, to, value)` with ERC20 topics.
    fn transfer(from: &str, to: &str, value: u8) -> Log {
        log(
            &[&topic("0xddf252ad"), &topic(from), &topic(to)],
            &format!("0x{value:064x}"),
        )
    }

    fn addr(hex: &str) -> Address {
        hex.parse().unwrap()
    }

    /// Pinned against the signatures the contracts declare. A wrong hash matches no logs, so it
    /// fails by silently finding nobody.
    #[test]
    fn topic_constants_match_the_event_signatures() {
        for (actual, expected) in [
            (
                BondingRegistry::BondOwnerSet::SIGNATURE_HASH,
                "0xf09dc4a8a4e1c9233bcb1d32c04ad4c9d516f140c23aa44f9e0d680f70799e08",
            ),
            (
                BondedCheckpoints::BondedCheckpointed::SIGNATURE_HASH,
                "0xb6241efac9a4f02e4f1ba6a30a3a5fc5ba4b23a47f181eca3055466c775eb32c",
            ),
            (
                ERC20Votes::Transfer::SIGNATURE_HASH,
                "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef",
            ),
            (
                ERC20Votes::DelegateVotesChanged::SIGNATURE_HASH,
                "0xdec2bacdd2f05b59de34da9b523dff8be42e5e38e818c82fdb0bae774387a724",
            ),
        ] {
            assert_eq!(format!("{actual:#x}"), expected);
        }
    }

    #[test]
    fn decodes_an_address_from_a_padded_topic() {
        assert_eq!(
            topic_address("0x000000000000000000000000f39fd6e51aad88f6f4ce6ab8827279cfffb92266"),
            Some(address!("f39Fd6e51aad88F6F4ce6aB8827279cffFb92266"))
        );
        assert_eq!(topic_address("0xdeadbeef"), None);
        // Non-ASCII input from the API must not panic a byte-index slice.
        assert_eq!(topic_address(&format!("0x{}", "é".repeat(40))), None);
    }

    /// A mint names its recipient in topic 2, and the zero `from` must not become a candidate. A
    /// lock minted straight to its holder is the case no other source reaches.
    #[test]
    fn escrow_mint_names_the_recipient_not_the_zero_address() {
        let mint = log(
            &[&topic("0xddf252ad"), &topic(ZERO), &topic(ALICE), "0x11"],
            "0x",
        );

        assert_eq!(
            escrow_holders_from_logs(&[mint]),
            HashSet::from([addr(ALICE)])
        );
    }

    /// An ERC20 `Transfer` shares the signature but carries three topics; decoding one as ERC721
    /// would read the wrong slot.
    #[test]
    fn erc20_shaped_transfers_are_skipped() {
        let erc20 = log(&[&topic("0xddf252ad"), &topic(ALICE), &topic(BOB)], "0x");

        assert!(escrow_holders_from_logs(&[erc20]).is_empty());
    }

    /// A position that changed hands yields both holders, once each however often they receive:
    /// whoever held it at the snapshot is decided by `getPastVotes`.
    #[test]
    fn transferred_positions_offer_both_holders_as_candidates() {
        let nft = |from: &str, to: &str| {
            log(
                &[&topic("0xddf252ad"), &topic(from), &topic(to), "0x11"],
                "0x",
            )
        };
        let logs = [nft(ZERO, ALICE), nft(ZERO, ALICE), nft(ALICE, BOB)];

        assert_eq!(
            escrow_holders_from_logs(&logs),
            HashSet::from([addr(ALICE), addr(BOB)])
        );
    }

    /// The census must find the key that an owner, such as a Safe, gave its bonded weight to. That
    /// key can have no other log at all. The topics come from the ABI, so a wrong index fails here.
    #[test]
    fn bonded_delegation_names_each_delegate_and_never_the_zero_address() {
        let owner = Address::repeat_byte(0xaa);
        let first = Address::repeat_byte(0xbb);
        let second = Address::repeat_byte(0xcc);
        let log = |from: Address, to: Address| Log {
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
            data: String::new(),
            block_number: String::new(),
        };

        // `first` accepts. The owner then moves on, which ends the delegation before `second`
        // accepts.
        let logs = [
            log(Address::ZERO, first),
            log(first, Address::ZERO),
            log(Address::ZERO, second),
        ];

        assert_eq!(
            bonded_delegates_from_logs(&logs),
            HashSet::from([first, second])
        );
    }

    fn mocked(responses: &Asserter) -> DynProvider {
        ProviderBuilder::default()
            .connect_mocked_client(responses.clone())
            .erased()
    }

    /// A revert is the expected answer of a plain token. A transport failure judged nothing about
    /// the deployment: reading it as a plain token would build a census silently missing every
    /// bonded and escrow-only holder.
    #[tokio::test]
    async fn only_a_revert_resolves_to_a_plain_token() {
        let token = Address::repeat_byte(1);

        let reverting = Asserter::new();
        reverting.push_failure(
            serde_json::from_value(serde_json::json!({
                "code": 3,
                "message": "execution reverted"
            }))
            .unwrap(),
        );
        let sources = resolve_voting_power_sources(&mocked(&reverting), token)
            .await
            .unwrap();
        assert!(sources.registry.is_none() && sources.escrow_lock_nft.is_none());

        let unreachable = rpc::http_provider("http://127.0.0.1:1").unwrap();
        assert!(resolve_voting_power_sources(&unreachable, token)
            .await
            .is_err());

        let failing = Asserter::new();
        failing.push_failure_msg("the node lags");
        assert!(get_clock_mode(&mocked(&failing), token).await.is_err());
    }

    #[test]
    fn balances_apply_in_block_order_whatever_the_listing_order() {
        // The burn is listed first but mined later: applied in listing order it would saturate
        // to zero before the mint lands.
        let burn = Log {
            block_number: "0x2".to_string(),
            ..transfer(ALICE, BOB, 50)
        };
        let mint = transfer(ZERO, ALICE, 100);

        let balances = compute_balances_from_logs(&[burn, mint]);

        assert_eq!(balances.get(&addr(ALICE)), Some(&U256::from(50)));
        assert_eq!(balances.get(&addr(BOB)), Some(&U256::from(50)));
        assert_eq!(balances.get(&Address::ZERO), None);
    }

    #[test]
    fn potential_voters_are_holders_plus_delegates() {
        let transfers = [transfer(ZERO, ALICE, 100)];
        // `DelegateVotesChanged(delegate, ..)` names its delegate in topic 1.
        let delegations = [
            log(&[&topic("0xdec2bacd"), &topic(BOB)], "0x"),
            log(&[&topic("0xdec2bacd"), &topic(ZERO)], "0x"),
        ];

        let voters = get_potential_voters(&transfers, &delegations);

        assert_eq!(voters.len(), 2);
        let find = |who: &str| voters.iter().find(|v| v.address == addr(who)).unwrap();
        assert_eq!(find(ALICE).token_balance, U256::from(100));
        assert!(!find(ALICE).has_delegation);
        assert!(find(BOB).has_delegation);
    }

    /// The addresses `verify_voting_power` keeps, with `responses` answering each `getPastVotes`.
    async fn verify(
        responses: Asserter,
        voters: &[Address],
        divisor: U256,
    ) -> eyre::Result<Vec<String>> {
        let token = ERC20Votes::new(Address::repeat_byte(1), mocked(&responses));
        let voters: Vec<PotentialVoter> = voters
            .iter()
            .map(|&address| PotentialVoter {
                address,
                token_balance: U256::ZERO,
                has_delegation: true,
            })
            .collect();
        let holders = verify_voting_power(&token, &voters, 1, U256::from(1), divisor).await?;
        Ok(holders.into_iter().map(|holder| holder.address).collect())
    }

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
