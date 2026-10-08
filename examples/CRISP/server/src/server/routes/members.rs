// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Domain routes about the voting token's delegates.
//!
//! Building the delegate directory means scanning every `DelegateChanged` the token has emitted
//! and reading each delegate's current voting power. Both frontends otherwise do that in the
//! browser on every page load, for logs this server has already indexed. Here it is one indexed
//! read plus one `eth_call` per 200 delegates, shared by every client and cached per block.
//!
//! The route takes a token and answers one question about it, so there is no calldata to inspect:
//! the only calls it makes are `totalSupply()` and `getVotes(address)`.

use crate::config::CONFIG;
use crate::server::app_data::AppData;
use crate::server::rate_limit::ChainRateLimiter;

use super::chain::{aggregate3Call, charge, Multicall3Call3, MULTICALL3};
use super::scan::{
    scan_logs, served_address, unavailable, ScanCache, ScanCtx, Target, NO_BACKFILL,
};

use actix_web::{web, HttpRequest, HttpResponse, Responder};
use alloy::eips::BlockNumberOrTag;
use alloy::network::TransactionBuilder;
use alloy::primitives::{Address, Bytes, U256};
use alloy::providers::{DynProvider, Provider};
use alloy::rpc::types::TransactionRequest;
use alloy::sol;
use alloy::sol_types::{SolCall, SolEvent};
use serde::{Deserialize, Serialize};
use std::cmp::Reverse;
use std::collections::HashSet;
use std::sync::LazyLock;

const ROUTE: &str = "/members/delegates";

pub fn setup_routes(config: &mut web::ServiceConfig) {
    config.service(web::scope("/members").route("/delegates", web::post().to(delegates)));
}

sol! {
    /// Emitted by every `ERC20Votes` token when an account changes its delegate. `toDelegate` is
    /// indexed, so the candidate set is readable from topics alone.
    event DelegateChanged(
        address indexed delegator,
        address indexed fromDelegate,
        address indexed toDelegate
    );

    function getVotes(address account) external view returns (uint256);
    function totalSupply() external view returns (uint256);
}

/// Delegates per `aggregate3`. The candidate set grows with every address ever delegated to, and
/// one call carrying all of them would eventually exceed the node's calldata or response limits
/// and fail the whole directory.
const MULTICALL_BATCH: usize = 200;

/// Cost charged to the caller's read window: between a free cache hit and a miss, which is one
/// indexed read plus a handful of `eth_call`s.
const DELEGATES_READ_COST: usize = 8;

#[derive(Deserialize)]
struct DelegatesRequest {
    /// Defaults to `CRISP_VOTING_TOKEN`. One server can answer for more than one app's token; the
    /// bound is the allowlist, checked below.
    #[serde(default)]
    token: Option<String>,
    /// Where to read each candidate's CURRENT voting power, when that is not the token. The
    /// governance app scans `DelegateChanged` on the token but reads `getVotes` from a
    /// bonded-votes adapter. `total_supply` stays on the token either way.
    #[serde(default)]
    power_source: Option<String>,
    /// Where `DelegateChanged` is emitted, when that is not the token (a voting escrow's IVotes
    /// adapter). Supply, delegation and voting weight may all sit on different contracts.
    #[serde(default)]
    delegation_source: Option<String>,
    /// The block the history has to reach back to, the token's deployment block. Coverage records
    /// where THIS server started indexing, so without it the route would answer from partial
    /// history and drop every delegate whose last `DelegateChanged` predates the index.
    #[serde(default)]
    from_block: Option<u64>,
}

#[derive(Clone, Serialize)]
struct DelegateEntry {
    address: String,
    /// A `uint256` as a decimal string: JSON numbers cannot carry it.
    voting_power: String,
}

#[derive(Clone, Serialize)]
struct DelegatesResponse {
    token: String,
    /// Equal to `token` unless the caller named another.
    power_source: String,
    /// Equal to `token` unless the caller named another.
    delegation_source: String,
    /// The block every voting-power read was pinned to. Unpinned, each batch would resolve
    /// against whatever head it hit, so a delegation landing mid-scan would be counted in one
    /// batch and not another and the percentages would stop summing.
    block: u64,
    /// The block range the `DelegateChanged` scan covered. A directory scanned from later than the
    /// token's deployment is missing delegates, and nothing else in the response shows it.
    scanned_from: u64,
    scanned_to: u64,
    /// How far local indexing reaches. Below `scanned_to` means part of this answer came from the
    /// upstream provider.
    indexed_head: u64,
    total_supply: String,
    delegates: Vec<DelegateEntry>,
}

/// What is remembered per directory, on two clocks.
#[derive(Default)]
struct TokenCache {
    /// The candidate set and the range it was built from. Delegates only ACCUMULATE (an address
    /// that stops holding power is dropped by `getVotes`, not by the scan), so the set is extended
    /// a block at a time and the historical scan is paid once per process.
    scanned: Option<(u64, u64)>,
    candidates: Vec<Address>,
    /// The directory as computed at a block; voting power changes with every delegation.
    directory: Option<(u64, DelegatesResponse)>,
}

/// Keyed by all three roles, not by the token: the same token yields a DIFFERENT directory
/// depending on where delegation and voting weight are read from.
static CACHE: LazyLock<ScanCache<TokenCache>> = LazyLock::new(ScanCache::new);

/// The cached directory for `block`, if it covers `scan_from`.
fn cached_directory(key: &str, block: u64, scan_from: u64) -> Option<DelegatesResponse> {
    CACHE.peek(key, |entry| {
        let (cached_block, response) = entry.directory.as_ref()?;
        (*cached_block == block && response.scanned_from <= scan_from).then(|| response.clone())
    })
}

/// The delegate directory for a voting token: every address ever delegated to that still holds
/// voting power, ranked, with the token's total supply for percentages.
async fn delegates(
    http_request: HttpRequest,
    request: web::Json<DelegatesRequest>,
    store: web::Data<AppData>,
    limiter: web::Data<ChainRateLimiter>,
) -> impl Responder {
    directory(&http_request, &request, &store, &limiter)
        .await
        .unwrap_or_else(|refusal| refusal)
}

async fn directory(
    http_request: &HttpRequest,
    request: &DelegatesRequest,
    store: &web::Data<AppData>,
    limiter: &ChainRateLimiter,
) -> Result<HttpResponse, HttpResponse> {
    charge(http_request, limiter, DELEGATES_READ_COST, ROUTE)?;

    let requested = request
        .token
        .clone()
        .or_else(|| CONFIG.crisp_voting_token.clone())
        .unwrap_or_default();
    let token = served_address(&requested, "token", "Token")?;

    // Each source is a second contract this route calls, so it is allowlisted on its own account.
    let source = |raw: &Option<String>, noun: &str, not_served: &str| match raw {
        Some(raw) => served_address(raw, noun, not_served),
        None => Ok(token),
    };
    let power_source = source(&request.power_source, "power source", "Voting power source")?;
    let delegation_source = source(
        &request.delegation_source,
        "delegation source",
        "Delegation source",
    )?;

    // Coverage follows the contract whose LOGS are scanned, not the token.
    let ctx = ScanCtx::open(
        store,
        ROUTE,
        delegation_source,
        token,
        request.from_block,
        NO_BACKFILL,
    )
    .await?;

    let cache_key = format!("{token:#x}|{:#x}|{power_source:#x}", ctx.address);

    if let Some(hit) = cached_directory(&cache_key, ctx.block, ctx.scan_from) {
        return Ok(HttpResponse::Ok().json(hit));
    }

    // Whoever waited here almost certainly no longer needs to scan, so check again.
    let _scanning = CACHE.exclusive(&cache_key).await;

    if let Some(hit) = cached_directory(&cache_key, ctx.block, ctx.scan_from) {
        return Ok(HttpResponse::Ok().json(hit));
    }

    // Reuse the candidate set when it starts early enough and scan only what was mined since. A
    // caller asking for MORE history than was scanned before gets a full rescan.
    let reusable = CACHE.peek(&cache_key, |entry| {
        entry
            .scanned
            .filter(|(from, to)| *from <= ctx.scan_from && *to <= ctx.block)
            .map(|(from, to)| (from, to, entry.candidates.clone()))
    });
    let (known, scanned_from, scan_start) = match reusable {
        Some((from, to, known)) => (known, from, to.saturating_add(1)),
        None => (Vec::new(), ctx.scan_from, ctx.scan_from),
    };

    let fresh = scan_delegate_changed(
        store,
        ctx.provider,
        &ctx.target(DelegateChanged::SIGNATURE_HASH),
        scan_start,
        ctx.block,
    )
    .await
    .map_err(|e| {
        unavailable(
            "members/delegates: scanning DelegateChanged failed",
            e,
            "Failed to read the delegate history",
        )
    })?;
    let candidates = merge(known, fresh);

    let (total_supply, delegates) =
        build_directory(ctx.provider, token, power_source, ctx.block, &candidates)
            .await
            .map_err(|e| {
                unavailable(
                    "members/delegates: reading voting power failed",
                    e,
                    "Failed to read voting power",
                )
            })?;

    let response = DelegatesResponse {
        token: token.to_string(),
        power_source: power_source.to_string(),
        delegation_source: delegation_source.to_string(),
        block: ctx.block,
        scanned_from,
        scanned_to: ctx.block,
        indexed_head: ctx.indexed_head,
        total_supply: total_supply.to_string(),
        delegates,
    };

    CACHE.insert(
        cache_key,
        TokenCache {
            scanned: Some((scanned_from, ctx.block)),
            candidates,
            directory: Some((ctx.block, response.clone())),
        },
    );

    Ok(HttpResponse::Ok().json(response))
}

/// Add `fresh` to `known`, keeping first-seen order and dropping repeats.
fn merge(known: Vec<Address>, fresh: Vec<Address>) -> Vec<Address> {
    let mut seen: HashSet<Address> = known.iter().copied().collect();
    let mut merged = known;
    merged.extend(fresh.into_iter().filter(|address| seen.insert(*address)));
    merged
}

/// Every address delegated TO in `[from, to]`.
///
/// An address that has since delegated away is still a candidate; whether it holds power now is
/// decided by `getVotes`, not by the last event about it.
async fn scan_delegate_changed(
    store: &web::Data<AppData>,
    provider: &DynProvider,
    target: &Target<'_>,
    from: u64,
    to: u64,
) -> eyre::Result<Vec<Address>> {
    let logs = scan_logs(store, provider, target, from, to).await?;

    // topics[3] is `toDelegate`: [signature, delegator, fromDelegate, toDelegate]. The zero
    // address is what `delegate(address(0))` records, an undelegation that can never hold power.
    Ok(logs
        .iter()
        .filter_map(|log| log.topics.get(3))
        .map(|topic| Address::from_word(*topic))
        .filter(|address| *address != Address::ZERO)
        .collect())
}

/// Total supply plus each candidate's voting power at `block`, zeros dropped, ranked.
async fn build_directory(
    provider: &DynProvider,
    token: Address,
    // Where `getVotes` is read from.
    power_source: Address,
    block: u64,
    candidates: &[Address],
) -> eyre::Result<(U256, Vec<DelegateEntry>)> {
    let at_block = BlockNumberOrTag::Number(block);

    let supply_raw = provider
        .call(
            TransactionRequest::default()
                .with_to(token)
                .with_input(Bytes::from(totalSupplyCall {}.abi_encode())),
        )
        .block(at_block.into())
        .await?;
    let total_supply = totalSupplyCall::abi_decode_returns(&supply_raw)?;

    let mut powers = Vec::with_capacity(candidates.len());

    for chunk in candidates.chunks(MULTICALL_BATCH) {
        let calls = chunk
            .iter()
            .map(|account| Multicall3Call3 {
                target: power_source,
                // Per-call failure, not a reverting batch: one account the token cannot answer for
                // must not discard the whole directory.
                allowFailure: true,
                callData: Bytes::from(getVotesCall { account: *account }.abi_encode()),
            })
            .collect();

        let raw = provider
            .call(
                TransactionRequest::default()
                    .with_to(MULTICALL3)
                    .with_input(Bytes::from(aggregate3Call { calls }.abi_encode())),
            )
            .block(at_block.into())
            .await?;

        for (account, result) in chunk.iter().zip(aggregate3Call::abi_decode_returns(&raw)?) {
            if !result.success {
                continue;
            }
            let Ok(power) = getVotesCall::abi_decode_returns(&result.returnData) else {
                continue;
            };
            if power != U256::ZERO {
                powers.push((power, *account));
            }
        }
    }

    // Ranked here because every consumer wants the same order. The sort is stable, so equal
    // powers keep their first-seen order.
    powers.sort_by_key(|(power, _)| Reverse(*power));

    let delegates = powers
        .into_iter()
        .map(|(power, account)| DelegateEntry {
            address: account.to_string(),
            voting_power: power.to_string(),
        })
        .collect();

    Ok((total_supply, delegates))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::database::SledDB;
    use crate::server::log_repo::StoredLog;
    use alloy::providers::ProviderBuilder;
    use e3_sdk::indexer::SharedStore;
    use std::sync::Arc;

    fn temp_store() -> web::Data<AppData> {
        let db = sled::Config::new().temporary(true).open().unwrap();
        web::Data::new(AppData::new(SharedStore::new(Arc::new(
            tokio::sync::RwLock::new(SledDB::from_db(db).unwrap()),
        ))))
    }

    /// Run the production scanner through its indexed path. The provider URL is never contacted.
    async fn index_candidates(
        store: &web::Data<AppData>,
        token: Address,
        from: u64,
        to: u64,
    ) -> eyre::Result<Vec<Address>> {
        let provider = ProviderBuilder::new()
            .connect_http("http://127.0.0.1:1".parse().unwrap())
            .erased();
        let key = format!("{token:#x}");
        let target = Target::any(
            token,
            &key,
            DelegateChanged::SIGNATURE_HASH,
            Some((from, to)),
        );
        scan_delegate_changed(store, &provider, &target, from, to).await
    }

    fn topic_for(address: Address) -> String {
        format!("0x{:0>64}", format!("{:x}", address))
    }

    fn delegate_changed(token: Address, to_delegate: Address, block: u64, index: u64) -> StoredLog {
        StoredLog {
            removed: false,
            address: token.to_string().to_lowercase(),
            topics: vec![
                format!("{:#x}", DelegateChanged::SIGNATURE_HASH),
                topic_for(Address::repeat_byte(0xaa)),
                topic_for(Address::ZERO),
                topic_for(to_delegate),
            ],
            data: "0x".to_string(),
            block_number: block,
            transaction_hash: None,
            log_index: index,
            block_hash: None,
            transaction_index: None,
        }
    }

    #[actix_web::test]
    async fn candidates_are_deduplicated_and_kept_in_first_seen_order() {
        let store = temp_store();
        let token = Address::repeat_byte(0x11);
        let first = Address::repeat_byte(0x22);
        let second = Address::repeat_byte(0x33);

        let mut logs = store.logs();
        logs.append(delegate_changed(token, first, 100, 0))
            .await
            .unwrap();
        logs.append(delegate_changed(token, second, 101, 0))
            .await
            .unwrap();
        // The same delegate again, and an undelegation to the zero address.
        logs.append(delegate_changed(token, first, 102, 0))
            .await
            .unwrap();
        logs.append(delegate_changed(token, Address::ZERO, 103, 0))
            .await
            .unwrap();

        // Dedup belongs to `merge`, which also folds an incremental scan into the set already
        // held, so the two paths cannot disagree about what a repeat is.
        let found = merge(
            Vec::new(),
            index_candidates(&store, token, 0, 200).await.unwrap(),
        );

        assert_eq!(found, vec![first, second]);
    }

    #[actix_web::test]
    async fn a_malformed_indexed_topic_is_skipped() {
        let store = temp_store();
        let token = Address::repeat_byte(0x11);
        let good = Address::repeat_byte(0x22);
        let mut malformed = delegate_changed(token, Address::repeat_byte(0x33), 10, 0);
        malformed.topics[3] = "0x1234".to_string();
        let mut logs = store.logs();
        logs.append(malformed).await.unwrap();
        logs.append(delegate_changed(token, good, 11, 0))
            .await
            .unwrap();

        let found = index_candidates(&store, token, 0, 100).await.unwrap();
        assert_eq!(found, vec![good]);
    }

    #[test]
    fn the_delegate_changed_signature_matches_the_erc20votes_event() {
        // keccak256("DelegateChanged(address,address,address)"), the topic both frontends filter
        // on, so an answer from this route covers the same events their scan does.
        assert_eq!(
            format!("{:#x}", DelegateChanged::SIGNATURE_HASH),
            "0x3134e8a2e6d97e929a7e54011ea5485d7d196dd5f0ba4d4ef95803e8e3fc257f"
        );
    }
}
