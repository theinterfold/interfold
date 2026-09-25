// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Domain routes about the voting token's delegates.
//!
//! The first route that answers a QUESTION rather than proxying a chain primitive, and the reason
//! is cost. Building the delegate directory means scanning every `DelegateChanged` the token has
//! ever emitted and then reading each delegate's current voting power. Both frontends do that in
//! the browser today: a chunked `eth_getLogs` walk from the token's deployment block, then
//! `getVotes` multicalled in batches — repeated by every client, on every page load, for a set of
//! logs this server has already indexed.
//!
//! Doing it here collapses that to one indexed read plus one `eth_call` per 200 delegates, shared
//! by every client and cached for the life of a block.
//!
//! It is also the shape that fixes what `/chain/rpc` cannot. That endpoint has to infer intent
//! from an address parameter, which is why Multicall3 could hide its real targets behind an
//! allowed `to` and why account reads had to be exempted from the allowlist entirely. This route
//! takes a token and answers one question about it; there is no calldata to inspect, and the only
//! calls it will ever make are `totalSupply()` and `getVotes(address)`.

use crate::config::CONFIG;
use crate::server::app_data::AppData;
use crate::server::models::JsonResponse;
use crate::server::rate_limit::ChainRateLimiter;

use super::chain::{admit, is_allowed, parse_address, too_many_requests, upstream, MULTICALL3};
use super::scan::{coverage_for, scan_logs, Coverage, Target};

use actix_web::{web, HttpRequest, HttpResponse, Responder};
use alloy::eips::BlockNumberOrTag;
use alloy::network::TransactionBuilder;
use alloy::primitives::{Address, Bytes, U256};
use alloy::providers::{DynProvider, Provider};
use alloy::rpc::types::TransactionRequest;
use alloy::sol;
use alloy::sol_types::{SolCall, SolEvent};
use log::error;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tokio::sync::RwLock;

pub fn setup_routes(config: &mut web::ServiceConfig) {
    config.service(web::scope("/members").route("/delegates", web::post().to(delegates)));
}

sol! {
    /// The event every `ERC20Votes` token emits when an account changes its delegate. `toDelegate`
    /// is indexed, so the candidate set is readable from topics alone — no log data to decode.
    event DelegateChanged(
        address indexed delegator,
        address indexed fromDelegate,
        address indexed toDelegate
    );

    function getVotes(address account) external view returns (uint256);
    function totalSupply() external view returns (uint256);

    struct Call3 {
        address target;
        bool allowFailure;
        bytes callData;
    }

    struct MulticallResult {
        bool success;
        bytes returnData;
    }

    function aggregate3(Call3[] calls) external returns (MulticallResult[] returnData);
}

/// Delegates per `aggregate3`.
///
/// The candidate set grows with every address ever delegated to, and one call carrying all of
/// them eventually exceeds the node's calldata or response limits — at which point the whole
/// directory fails rather than one batch of it.
const MULTICALL_BATCH: usize = 200;

/// Cost charged to the caller's read window.
///
/// A cache hit is free and a miss is one indexed read plus a handful of `eth_call`s, so this is
/// priced between the two rather than at either extreme.
const DELEGATES_READ_COST: usize = 8;

#[derive(Debug, Deserialize)]
pub struct DelegatesRequest {
    /// Defaults to `CRISP_VOTING_TOKEN`. Present so one server can answer for more than one app's
    /// token — the bound is which tokens it INDEXES, checked below, not an allowlist.
    #[serde(default)]
    pub token: Option<String>,
    /// Where to read each candidate's CURRENT voting power, when that is not the token itself.
    ///
    /// Delegation and voting weight can live on different contracts: the governance app scans
    /// `DelegateChanged` on the token but reads `getVotes` from a bonded-votes adapter, so a
    /// directory built entirely against the token would list the right delegates with the wrong
    /// numbers. Defaults to the token, which is the common case. `total_supply` stays on the
    /// token either way — it is what the percentages divide by.
    #[serde(default)]
    pub power_source: Option<String>,
    /// Where `DelegateChanged` is emitted, when that is not the token itself.
    ///
    /// With a voting escrow in play, delegation moves to the escrow's IVotes adapter and the
    /// token's own delegation feeds a read nobody consumes — so the candidate scan has to follow
    /// the adapter. Defaults to the token. Together with `power_source` this lets all three roles
    /// (supply, delegation, voting weight) sit on different contracts, which is what the
    /// governance deployment actually does.
    #[serde(default)]
    pub delegation_source: Option<String>,
    /// The block the caller needs the history to reach back to — the token's deployment block.
    ///
    /// The server cannot know it: coverage records where THIS server started indexing, which on a
    /// deployment with no backfill is long after the token shipped. Without this the route would
    /// answer from partial history and look authoritative doing so, dropping every delegate whose
    /// last `DelegateChanged` predates the index. The caller knows the number, so the caller
    /// supplies it and the server refuses what it cannot cover.
    #[serde(default)]
    pub from_block: Option<u64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DelegateEntry {
    pub address: String,
    /// A `uint256` as a decimal string: JSON numbers cannot carry it, and every consumer parses
    /// it into a bigint anyway.
    pub voting_power: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct DelegatesResponse {
    pub token: String,
    /// Where the voting power was read from. Equal to `token` unless the caller named another.
    pub power_source: String,
    /// Where `DelegateChanged` was scanned. Equal to `token` unless the caller named another.
    pub delegation_source: String,
    /// The block every voting-power read was pinned to.
    ///
    /// Pinned, not `latest`: left unpinned, each batch resolves against whatever head it happens
    /// to hit, so a delegation landing mid-scan is counted in one batch and not another, and the
    /// percentages stop summing.
    pub block: u64,
    /// The block range the `DelegateChanged` scan actually covered.
    ///
    /// The guarantee this route makes, and the one a client has to be able to check: a directory
    /// scanned from later than the token's deployment is missing delegates, and nothing else in
    /// the response would distinguish it from a complete one.
    pub scanned_from: u64,
    pub scanned_to: u64,
    /// How far local indexing has been applied. Below `scanned_to` means part of this answer came
    /// from the upstream provider rather than the index — correct either way, just slower.
    pub indexed_head: u64,
    pub total_supply: String,
    pub delegates: Vec<DelegateEntry>,
}

/// What is remembered per token, on two different clocks.
#[derive(Default)]
struct TokenCache {
    /// The candidate set and the range it was built from. Delegates only ever ACCUMULATE — an
    /// address that stops holding power is dropped by `getVotes`, not by the scan — so this is
    /// extended a block at a time rather than rebuilt, and the expensive historical scan is paid
    /// once for the life of the process instead of once per block.
    scanned: Option<(u64, u64)>,
    candidates: Vec<Address>,
    /// The directory as computed at a block. Voting power changes with every delegation, so this
    /// is only good for the block it was pinned to.
    directory: Option<(u64, DelegatesResponse)>,
}

/// Per-token cache.
///
/// The whole point of moving this server-side: within one block the answer is identical for every
/// caller, so the first request pays for it and the rest are a map lookup. Keyed by lowercased
/// token address; bounded by how many tokens this server is asked about.
static CACHE: once_cell::sync::Lazy<RwLock<HashMap<String, TokenCache>>> =
    once_cell::sync::Lazy::new(|| RwLock::new(HashMap::new()));

/// One in-flight scan per token.
///
/// Without this, a cold cache is a thundering herd: the historical scan can be tens of windows,
/// the cache is only written when it finishes, and every request that arrives meanwhile sees a
/// miss and starts its own. A restart with a handful of open browsers would multiply the whole
/// backfill by the number of tabs. Holders queue and then find the cache warm — the recheck after
/// acquiring is what makes the wait worth having.
static SCANS: once_cell::sync::Lazy<
    RwLock<HashMap<String, std::sync::Arc<tokio::sync::Mutex<()>>>>,
> = once_cell::sync::Lazy::new(|| RwLock::new(HashMap::new()));

/// The lock for one token, created on first use.
async fn scan_lock(token_key: &str) -> std::sync::Arc<tokio::sync::Mutex<()>> {
    if let Some(existing) = SCANS.read().await.get(token_key) {
        return existing.clone();
    }
    SCANS
        .write()
        .await
        .entry(token_key.to_string())
        .or_default()
        .clone()
}

/// The cached directory for `block`, if it covers `scan_from`.
async fn cached_directory(
    token_key: &str,
    block: u64,
    scan_from: u64,
) -> Option<DelegatesResponse> {
    let cache = CACHE.read().await;
    let (cached_block, response) = cache.get(token_key)?.directory.as_ref()?;
    (*cached_block == block && response.scanned_from <= scan_from).then(|| response.clone())
}

/// The delegate directory for a voting token: every address ever delegated to that still holds
/// voting power, ranked, with the token's total supply for percentages.
async fn delegates(
    http_request: HttpRequest,
    request: web::Json<DelegatesRequest>,
    store: web::Data<AppData>,
    limiter: web::Data<ChainRateLimiter>,
) -> impl Responder {
    if let Err((caller, cost)) = admit(&http_request, &limiter, DELEGATES_READ_COST) {
        return too_many_requests(&caller, cost, "/members/delegates");
    }

    let requested = request
        .token
        .clone()
        .or_else(|| CONFIG.crisp_voting_token.clone())
        .unwrap_or_default();

    let Some(token) = parse_address(&requested) else {
        return HttpResponse::BadRequest().json(JsonResponse {
            response: format!("Invalid token address: {requested}"),
        });
    };
    // The bound this route was missing. Without it any address could be named, and a `from_block`
    // inside the 600-window cap would buy up to 600 sequential `eth_getLogs` calls plus one
    // `aggregate3` per 200 discovered addresses — fan-out the fixed cost charged above does not
    // account for. Worse, every distinct address left a permanent `SCANS` entry and every
    // successful scan a permanent `CACHE` entry, so a caller could grow both without limit by
    // naming addresses nobody watches. `/proposals` and `/rounds/inputs` check the same way.
    if !is_allowed(&token) {
        return HttpResponse::NotFound().json(JsonResponse {
            response: format!("Token {token} is not served by this indexer"),
        });
    }

    let token_key = token.to_string().to_lowercase();

    // What the local index can answer for, if anything. NOT a precondition: a range it cannot
    // cover is scanned upstream below. Refusing instead would have been safe and useless — the
    // client's fallback does exactly that scan, so refusing just moves the same work back into
    // every browser, which is what this route exists to stop.
    // Defaults to the token. Allowlisted on its own account: it is a second contract this route
    // will call, so it has to be one this server serves.
    let power_source = match &request.power_source {
        Some(raw) => match parse_address(raw) {
            Some(address) if is_allowed(&address) => address,
            Some(address) => {
                return HttpResponse::NotFound().json(JsonResponse {
                    response: format!(
                        "Voting power source {address} is not served by this indexer"
                    ),
                });
            }
            None => {
                return HttpResponse::BadRequest().json(JsonResponse {
                    response: format!("Invalid power source address: {raw}"),
                });
            }
        },
        None => token,
    };

    // Same treatment as `power_source`: allowlisted on its own account, because it is another
    // contract this route reads.
    let delegation_source = match &request.delegation_source {
        Some(raw) => match parse_address(raw) {
            Some(address) if is_allowed(&address) => address,
            Some(address) => {
                return HttpResponse::NotFound().json(JsonResponse {
                    response: format!("Delegation source {address} is not served by this indexer"),
                });
            }
            None => {
                return HttpResponse::BadRequest().json(JsonResponse {
                    response: format!("Invalid delegation source address: {raw}"),
                });
            }
        },
        None => token,
    };
    let scan_key = delegation_source.to_string().to_lowercase();

    // Keyed by all three roles, not by the token. The same token yields a DIFFERENT directory
    // depending on where delegation and voting weight are read from, so a token-keyed cache would
    // serve one caller's answer to another and be wrong for both.
    let cache_key = format!(
        "{token_key}|{scan_key}|{}",
        power_source.to_string().to_lowercase()
    );

    // Coverage follows the contract whose LOGS are scanned, not the token.
    let indexed = coverage_for(&store, &scan_key).await;
    let indexed_head = indexed.map(|(_, head)| head).unwrap_or(0);

    // Where history has to start. The server cannot know it — coverage records where THIS server
    // began indexing, which on a deployment with no backfill is long after the token shipped — so
    // the caller names it, and only a token this server indexes has a usable default.
    let Some(scan_from) = request.from_block.or(indexed.map(|(from, _)| from)) else {
        return HttpResponse::BadRequest().json(JsonResponse {
            response: format!(
                "from_block is required for {token}: this server does not index its logs, so it \
                 has no deployment block to scan from"
            ),
        });
    };

    let provider = match upstream().await {
        Ok(p) => p,
        Err(e) => {
            error!("members/delegates: provider unavailable: {e}");
            return HttpResponse::ServiceUnavailable().json(JsonResponse {
                response: "Upstream RPC unavailable".to_string(),
            });
        }
    };

    let block = match provider.get_block_number().await {
        Ok(number) => number,
        Err(e) => {
            error!("members/delegates: could not read the head: {e}");
            return HttpResponse::ServiceUnavailable().json(JsonResponse {
                response: "Upstream RPC unavailable".to_string(),
            });
        }
    };

    // Everything below this point is the work; a request arriving in the same block as the last
    // one does none of it.
    if let Some(hit) = cached_directory(&cache_key, block, scan_from).await {
        return HttpResponse::Ok().json(hit);
    }

    // One scan per token at a time. Whoever waited here almost certainly no longer needs to scan
    // at all, so check again before doing any work.
    let lock = scan_lock(&cache_key).await;
    let _scanning = lock.lock().await;

    if let Some(hit) = cached_directory(&cache_key, block, scan_from).await {
        return HttpResponse::Ok().json(hit);
    }

    // Reuse the existing candidate set when it starts early enough, and scan only what has been
    // mined since. A caller asking for MORE history than was scanned before gets a full rescan.
    let reusable = CACHE.read().await.get(&cache_key).and_then(|entry| {
        entry
            .scanned
            .filter(|(from, to)| *from <= scan_from && *to <= block)
            .map(|(from, to)| (from, to, entry.candidates.clone()))
    });

    let (mut candidates, scanned_from) = match reusable {
        Some((from, to, known)) => {
            match scan_delegate_changed(
                &store,
                provider,
                delegation_source,
                &scan_key,
                to + 1,
                block,
                indexed,
            )
            .await
            {
                Ok(fresh) => (merge(known, fresh), from),
                Err(e) => return scan_failed(e),
            }
        }
        None => {
            match scan_delegate_changed(
                &store,
                provider,
                delegation_source,
                &scan_key,
                scan_from,
                block,
                indexed,
            )
            .await
            {
                Ok(found) => (merge(Vec::new(), found), scan_from),
                Err(e) => return scan_failed(e),
            }
        }
    };
    candidates.shrink_to_fit();

    let response = match build_directory(
        provider,
        token,
        power_source,
        delegation_source,
        block,
        &candidates,
    )
    .await
    {
        Ok(mut built) => {
            built.scanned_from = scanned_from;
            built.scanned_to = block;
            built.indexed_head = indexed_head;
            built
        }
        Err(e) => {
            error!("members/delegates: reading voting power failed: {e}");
            return HttpResponse::ServiceUnavailable().json(JsonResponse {
                response: "Failed to read voting power".to_string(),
            });
        }
    };

    CACHE.write().await.insert(
        cache_key,
        TokenCache {
            scanned: Some((scanned_from, block)),
            candidates,
            directory: Some((block, response.clone())),
        },
    );

    HttpResponse::Ok().json(response)
}

fn scan_failed(e: eyre::Report) -> HttpResponse {
    error!("members/delegates: scanning DelegateChanged failed: {e}");
    HttpResponse::ServiceUnavailable().json(JsonResponse {
        response: "Failed to read the delegate history".to_string(),
    })
}

/// Add `fresh` to `known`, keeping first-seen order and dropping repeats.
fn merge(known: Vec<Address>, fresh: Vec<Address>) -> Vec<Address> {
    let mut seen: std::collections::HashSet<Address> = known.iter().copied().collect();
    let mut merged = known;
    for address in fresh {
        if seen.insert(address) {
            merged.push(address);
        }
    }
    merged
}

/// Every address delegated TO in `[from, to]`.
///
/// `toDelegate` is indexed, so the candidate set is readable from topics alone — no log data has
/// to be decoded. An address that has since delegated away is still a candidate; whether it holds
/// power now is decided by `getVotes`, not by the last event about it.
async fn scan_delegate_changed(
    store: &web::Data<AppData>,
    provider: &DynProvider,
    token: Address,
    token_key: &str,
    from: u64,
    to: u64,
    indexed: Coverage,
) -> eyre::Result<Vec<Address>> {
    let logs = scan_logs(
        store,
        provider,
        &Target::any(token, token_key, DelegateChanged::SIGNATURE_HASH, indexed),
        from,
        to,
    )
    .await?;

    let mut candidates = Vec::new();
    for log in logs {
        // topics[3] is `toDelegate`: [signature, delegator, fromDelegate, toDelegate].
        let Some(topic) = log.topics.get(3) else {
            continue;
        };
        let address = Address::from_word(*topic);
        // The zero address is what `delegate(address(0))` records — an undelegation, not a
        // delegate. It can never hold voting power.
        if address != Address::ZERO {
            candidates.push(address);
        }
    }

    Ok(candidates)
}

/// Total supply plus each candidate's voting power at `block`, zeros dropped, ranked.
async fn build_directory(
    provider: &alloy::providers::DynProvider,
    token: Address,
    // Where `getVotes` is read from — the token unless the caller named another contract.
    power_source: Address,
    // Where `DelegateChanged` was scanned — reported so a caller can confirm it got the
    // directory it asked for rather than a token-wide one.
    delegation_source: Address,
    block: u64,
    candidates: &[Address],
) -> eyre::Result<DelegatesResponse> {
    let supply_call = totalSupplyCall {};
    let supply_raw = provider
        .call(
            TransactionRequest::default()
                .with_to(token)
                .with_input(Bytes::from(supply_call.abi_encode())),
        )
        .block(BlockNumberOrTag::Number(block).into())
        .await?;
    let total_supply = totalSupplyCall::abi_decode_returns(&supply_raw)?;

    let mut delegates = Vec::with_capacity(candidates.len());

    for chunk in candidates.chunks(MULTICALL_BATCH) {
        let calls = chunk
            .iter()
            .map(|account| Call3 {
                target: power_source,
                // Per-call failure rather than a reverting batch: one token that does not
                // implement `getVotes` for one account must not discard the whole directory.
                allowFailure: true,
                callData: Bytes::from(getVotesCall { account: *account }.abi_encode()),
            })
            .collect::<Vec<_>>();

        let raw = provider
            .call(
                TransactionRequest::default()
                    .with_to(MULTICALL3)
                    .with_input(Bytes::from(
                        aggregate3Call {
                            calls: calls.clone(),
                        }
                        .abi_encode(),
                    )),
            )
            .block(BlockNumberOrTag::Number(block).into())
            .await?;

        let results = aggregate3Call::abi_decode_returns(&raw)?;

        for (account, result) in chunk.iter().zip(results) {
            if !result.success {
                continue;
            }
            let Ok(power) = getVotesCall::abi_decode_returns(&result.returnData) else {
                continue;
            };
            if power == U256::ZERO {
                continue;
            }
            delegates.push(DelegateEntry {
                address: account.to_string(),
                voting_power: power.to_string(),
            });
        }
    }

    // Ranked here rather than in the client: every consumer wants the same order, and sorting
    // decimal strings on the client means parsing them all first.
    delegates.sort_by(|a, b| {
        let left: U256 = a.voting_power.parse().unwrap_or(U256::ZERO);
        let right: U256 = b.voting_power.parse().unwrap_or(U256::ZERO);
        right.cmp(&left)
    });

    Ok(DelegatesResponse {
        token: token.to_string(),
        power_source: power_source.to_string(),
        delegation_source: delegation_source.to_string(),
        block,
        // Filled in by the caller, which is the only place that knows what the scan covered.
        scanned_from: 0,
        scanned_to: 0,
        indexed_head: 0,
        total_supply: total_supply.to_string(),
        delegates,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::database::SledDB;
    use crate::server::log_repo::StoredLog;
    use alloy::providers::ProviderBuilder;
    use e3_sdk::indexer::SharedStore;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Arc;

    /// A store in a directory of its own, removed when the guard drops.
    struct TempStore {
        path: std::path::PathBuf,
        data: web::Data<AppData>,
    }

    impl Drop for TempStore {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }

    fn temp_store() -> TempStore {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let path = std::env::temp_dir().join(format!(
            "crisp-members-test-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let db = SharedStore::new(Arc::new(tokio::sync::RwLock::new(
            SledDB::new(path.to_str().expect("temp path is valid utf-8")).expect("opening sled"),
        )));
        TempStore {
            path,
            data: web::Data::new(AppData::new(db)),
        }
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
        let token_key = token.to_string().to_lowercase();
        scan_delegate_changed(
            store,
            &provider,
            token,
            &token_key,
            from,
            to,
            Some((from, to)),
        )
        .await
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

        let mut logs = store.data.logs();
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

        // Dedup belongs to `merge`, which is also what folds an incremental scan into the set
        // already held — so the two paths cannot disagree about what a repeat is.
        let found = merge(
            Vec::new(),
            index_candidates(&store.data, token, 0, 200).await.unwrap(),
        );

        assert_eq!(found, vec![first, second]);
    }

    #[actix_web::test]
    async fn a_delegate_outside_the_scanned_range_is_not_a_candidate() {
        let store = temp_store();
        let token = Address::repeat_byte(0x11);
        let inside = Address::repeat_byte(0x22);
        let outside = Address::repeat_byte(0x33);

        let mut logs = store.data.logs();
        logs.append(delegate_changed(token, inside, 50, 0))
            .await
            .unwrap();
        logs.append(delegate_changed(token, outside, 5_000, 0))
            .await
            .unwrap();

        let found = index_candidates(&store.data, token, 0, 100).await.unwrap();

        assert_eq!(found, vec![inside]);
    }

    #[actix_web::test]
    async fn another_contracts_events_are_not_mixed_in() {
        let store = temp_store();
        let token = Address::repeat_byte(0x11);
        let other_token = Address::repeat_byte(0x99);
        let ours = Address::repeat_byte(0x22);
        let theirs = Address::repeat_byte(0x33);

        let mut logs = store.data.logs();
        logs.append(delegate_changed(token, ours, 10, 0))
            .await
            .unwrap();
        logs.append(delegate_changed(other_token, theirs, 11, 0))
            .await
            .unwrap();

        let found = index_candidates(&store.data, token, 0, 100).await.unwrap();

        assert_eq!(found, vec![ours]);
    }

    #[test]
    fn an_incremental_scan_extends_the_set_without_repeating_it() {
        let known = vec![Address::repeat_byte(0x11), Address::repeat_byte(0x22)];
        // A delegate seen again in the new window, and one seen for the first time.
        let fresh = vec![Address::repeat_byte(0x22), Address::repeat_byte(0x33)];

        assert_eq!(
            merge(known, fresh),
            vec![
                Address::repeat_byte(0x11),
                Address::repeat_byte(0x22),
                Address::repeat_byte(0x33)
            ]
        );
    }

    #[test]
    fn merging_nothing_new_leaves_the_set_alone() {
        let known = vec![Address::repeat_byte(0x11)];
        assert_eq!(merge(known.clone(), Vec::new()), known);
    }

    #[actix_web::test]
    async fn a_malformed_indexed_topic_is_skipped() {
        let store = temp_store();
        let token = Address::repeat_byte(0x11);
        let good = Address::repeat_byte(0x22);
        let mut malformed = delegate_changed(token, Address::repeat_byte(0x33), 10, 0);
        malformed.topics[3] = "0x1234".to_string();
        let mut logs = store.data.logs();
        logs.append(malformed).await.unwrap();
        logs.append(delegate_changed(token, good, 11, 0))
            .await
            .unwrap();

        let found = index_candidates(&store.data, token, 0, 100).await.unwrap();
        assert_eq!(found, vec![good]);
    }

    #[test]
    fn the_delegate_changed_signature_matches_the_erc20votes_event() {
        // keccak256("DelegateChanged(address,address,address)") — the topic both frontends filter
        // on today, so an answer from this route covers the same events their scan does.
        assert_eq!(
            format!("{:#x}", DelegateChanged::SIGNATURE_HASH),
            "0x3134e8a2e6d97e929a7e54011ea5485d7d196dd5f0ba4d4ef95803e8e3fc257f"
        );
    }
}
