// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Chain access for clients that have no RPC provider of their own.
//!
//! These routes are deliberately NOT a general purpose JSON-RPC proxy:
//!
//! - Every method that names an address is checked against an allowlist (`INDEX_CONTRACTS` plus
//!   the contracts this server is configured against), so the server cannot become free RPC for
//!   the rest of the chain. The data is public; the allowlist bounds cost and abuse, not
//!   disclosure. The check fails closed: an unknown parameter shape is refused, and so is a
//!   request that omits the address a method could have carried (an `eth_call` with no `to` is
//!   arbitrary EVM execution; an `eth_getLogs` with no `address` is every log on the chain). The
//!   few methods that name no address are bounded by shape instead: a capped `feeHistory`.
//! - Only reads. No path here can send a transaction; writes stay with the user's wallet.
//! - Log queries are windowed server-side, so a caller may ask for a contract's whole history in
//!   one request without knowing the provider's `eth_getLogs` range cap.

mod policy;

use crate::config::CONFIG;
use crate::server::app_data::AppData;
use crate::server::rate_limit::ChainRateLimiter;
use crate::server::read_cache::{self, Counters};
use crate::server::rpc::{self, HTTP};

use super::scan::{
    coverage_for, covered, unavailable, upstream_failed, upstream_window, window_count, windows,
    LOG_WINDOW,
};
use super::{json_message, upstream_unavailable};
use policy::{call_cache_key, global_request_is_too_broad, hex_u64, requested_addresses, Scope};

pub(super) use policy::{
    aggregate3Call, is_allowed, is_log_indexed, parse_address, Multicall3Call3, MULTICALL3,
};

use actix_web::http::StatusCode;
use actix_web::{web, HttpRequest, HttpResponse, Responder};
use alloy::eips::BlockNumberOrTag;
use alloy::network::TransactionBuilder;
use alloy::primitives::{Bytes, B256};
use alloy::providers::Provider;
use alloy::rpc::types::{Filter, TransactionRequest};
use log::{error, warn};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::str::FromStr;

/// Cap on the calls one `/chain/read` request or one JSON-RPC batch may carry. A batch runs
/// sequentially, so an unbounded one is unbounded upstream load held on a single connection.
const MAX_BATCH: usize = 64;

/// Cap on the windows one log query may expand into. A request for "genesis to head" would
/// otherwise become thousands of sequential upstream calls; callers know their contract's
/// deployment block and are expected to start there.
const MAX_LOG_WINDOWS: u64 = 500;

/// Cost charged for `/chain/block-at-timestamp`. The route bisects over block headers, about
/// `log2(head)` upstream reads (roughly 25 on a 20-million-block chain). 32 covers any height up
/// to 2^32 and avoids a head read just to price the request.
const BLOCK_SEARCH_COST: usize = 32;

/// Who to charge a request to.
///
/// `realip_remote_addr` reads `Forwarded` / `X-Forwarded-For` with NO trust-proxy check, so a
/// caller could present a new address on every request, mint a fresh window each time, and never
/// be limited. The header is believed only when the deployment declares a proxy that overwrites
/// it; otherwise the socket peer, which cannot be forged, is used.
pub(super) fn identify(request: &HttpRequest, trust_proxy_headers: bool) -> String {
    let info = request.connection_info();
    let caller = if trust_proxy_headers {
        info.realip_remote_addr()
    } else {
        info.peer_addr()
    };
    caller.unwrap_or("unknown").to_string()
}

/// Charge a request against the caller's read window, returning `(caller, cost)` when it does not
/// fit.
///
/// These routes are cheap per call and unbounded in aggregate. The allowlist bounds WHICH
/// contracts they reach, not HOW OFTEN. `cost` is in upstream calls, so a batch is charged for
/// what it will cause, not for being one HTTP request.
pub(super) fn admit(
    request: &HttpRequest,
    limiter: &ChainRateLimiter,
    cost: usize,
) -> Result<(), (String, usize)> {
    let caller = identify(request, limiter.trusts_proxy_headers());
    limiter
        .check_caller_cost(&caller, cost)
        .map_err(|_| (caller, cost))
}

/// The typed routes' refusal.
pub(super) fn too_many_requests(caller: &str, cost: usize, route: &str) -> HttpResponse {
    warn!("Rate limit refused {route} from {caller} (cost {cost})");
    json_message(
        StatusCode::TOO_MANY_REQUESTS,
        "Too many chain reads from this address, slow down",
    )
}

/// [`admit`], with the typed routes' refusal as the error.
pub(super) fn charge(
    request: &HttpRequest,
    limiter: &ChainRateLimiter,
    cost: usize,
    route: &str,
) -> Result<(), HttpResponse> {
    admit(request, limiter, cost).map_err(|(caller, cost)| too_many_requests(&caller, cost, route))
}

pub fn setup_routes(config: &mut web::ServiceConfig) {
    config.service(
        web::scope("/chain")
            .route("/rpc", web::post().to(rpc))
            .route("/head", web::post().to(head))
            .route("/read", web::post().to(read))
            .route("/logs", web::post().to(logs))
            .route("/block-at-timestamp", web::post().to(block_at_timestamp))
            .route("/stats", web::post().to(stats)),
    );
}

#[derive(Serialize)]
struct StatsResponse {
    #[serde(flatten)]
    counters: Counters,
    /// Upstream requests avoided: every cache hit and every log query the index answered.
    upstream_calls_saved: u64,
}

/// How much upstream traffic this server absorbs, so "the indexer saves RPC calls" is checkable
/// against a running deployment.
async fn stats() -> impl Responder {
    let counters = read_cache::counters();
    let upstream_calls_saved = counters
        .call_hits
        .saturating_add(counters.head_hits)
        .saturating_add(counters.log_index_hits);

    HttpResponse::Ok().json(StatsResponse {
        counters,
        upstream_calls_saved,
    })
}

/// JSON-RPC methods this endpoint forwards.
///
/// An allowlist, not a denylist of writes: a method added by a future provider or client stays
/// unreachable until someone decides it belongs here. Everything listed is a read; transactions
/// are signed and broadcast by the user's own wallet.
const ALLOWED_RPC_METHODS: &[&str] = &[
    "eth_call",
    "eth_getLogs",
    "eth_blockNumber",
    "eth_chainId",
    "eth_getBlockByNumber",
    "eth_getBlockByHash",
    "eth_getCode",
    "eth_getStorageAt",
    "eth_getBalance",
    "eth_getTransactionByHash",
    "eth_getTransactionReceipt",
    "eth_getTransactionCount",
    "eth_estimateGas",
    "eth_gasPrice",
    "eth_maxPriorityFeePerGas",
    "eth_feeHistory",
    "net_version",
    "web3_clientVersion",
];

/// `jsonrpc` is not declared: serde skips it, and this endpoint does not vary on the version.
#[derive(Deserialize)]
struct RpcRequest {
    id: Option<Value>,
    method: String,
    #[serde(default)]
    params: Value,
}

fn rpc_error(id: Option<Value>, code: i64, message: &str) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message } })
}

fn rpc_result(id: Option<Value>, result: impl Into<Value>) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "result": result.into() })
}

/// A read-only, allowlisted JSON-RPC endpoint, so a browser client can point a standard Ethereum
/// library at the CRISP server and drop its hosted-provider key as a configuration change.
///
/// `eth_getLogs` is special-cased: the range is split into windows here.
async fn rpc(
    request: HttpRequest,
    body: web::Json<Value>,
    store: web::Data<AppData>,
    limiter: web::Data<ChainRateLimiter>,
) -> impl Responder {
    // The batch cap is checked BEFORE the window is charged: an oversized batch costs more than
    // the whole window, so charging first would answer with a 429 instead of the error naming the
    // cap.
    let cost = match body.as_array() {
        Some(entries) if entries.len() > MAX_BATCH => {
            return HttpResponse::Ok().json(rpc_error(
                None,
                -32600,
                &format!("At most {MAX_BATCH} calls per batch"),
            ));
        }
        // A batch of N is N sequential upstream requests held open on one connection.
        Some(entries) => entries.len(),
        None => 1,
    };
    if let Err((caller, cost)) = admit(&request, &limiter, cost) {
        warn!("Rate limit refused /chain/rpc from {caller} (cost {cost})");
        return HttpResponse::TooManyRequests().json(rpc_error(
            None,
            -32005,
            "Too many chain reads from this address, slow down",
        ));
    }

    // A top-level array is a JSON-RPC batch; viem sends one whenever `batch: true` is set.
    match body.into_inner() {
        // An empty batch is an Invalid Request per the spec.
        Value::Array(entries) if entries.is_empty() => {
            HttpResponse::Ok().json(rpc_error(None, -32600, "Invalid request: empty batch"))
        }
        Value::Array(entries) => {
            let mut responses = Vec::with_capacity(entries.len());
            for entry in entries {
                responses.push(handle_rpc_call(entry, &store).await);
            }
            HttpResponse::Ok().json(responses)
        }
        single => HttpResponse::Ok().json(handle_rpc_call(single, &store).await),
    }
}

/// One JSON-RPC call, as a response object so the batch path can collect them.
async fn handle_rpc_call(entry: Value, store: &web::Data<AppData>) -> Value {
    let id = entry.get("id").cloned();

    let request: RpcRequest = match serde_json::from_value(entry) {
        Ok(parsed) => parsed,
        Err(e) => return rpc_error(id, -32600, &format!("Invalid request: {e}")),
    };

    if !ALLOWED_RPC_METHODS.contains(&request.method.as_str()) {
        return rpc_error(
            id,
            -32601,
            &format!("Method not served by this indexer: {}", request.method),
        );
    }

    match requested_addresses(&request.method, &request.params) {
        Scope::Addresses(addresses) => {
            for address in addresses {
                match parse_address(&address) {
                    Some(parsed) if is_allowed(&parsed) => {}
                    Some(parsed) => {
                        return rpc_error(
                            id,
                            -32602,
                            &format!("Address not served by this indexer: {parsed}"),
                        );
                    }
                    None => return rpc_error(id, -32602, "Invalid address"),
                }
            }
        }
        Scope::Unscoped(reason) => {
            return rpc_error(id, -32602, &format!("{}: {reason}", request.method));
        }
        // Nothing to check by address: the bound has to come from the shape of the request.
        Scope::Global => {
            if let Some(reason) = global_request_is_too_broad(&request.method, &request.params) {
                return rpc_error(id, -32602, reason);
            }
        }
    }

    // Constant for the life of the deployment, and viem asks on every client boot.
    if request.method == "eth_chainId" {
        return rpc_result(id, format!("0x{:x}", CONFIG.chain_id));
    }

    if request.method == "eth_blockNumber" {
        if let Some(number) = read_cache::head_number().await {
            read_cache::record_head(true);
            return rpc_result(id, format!("0x{number:x}"));
        }
        read_cache::record_head(false);
    }

    let call_key = (request.method == "eth_call")
        .then(|| call_cache_key(&request.params))
        .flatten();
    // Read BEFORE the upstream request: if the head moves while it is in flight, the result
    // describes the older block and must not be filed under the newer one.
    let issued_at_block = read_cache::current_latest_block().await;

    if let Some((address, data, block)) = &call_key {
        if let Some(hit) = read_cache::call(address, data, *block).await {
            read_cache::record_call(true);
            return rpc_result(id, hit);
        }
        read_cache::record_call(false);
    }

    // The index can usually answer `eth_getLogs` outright; when it cannot, forwarding a wide range
    // verbatim would relay the provider's range-cap error to a caller who cannot know the cap.
    if request.method == "eth_getLogs" {
        if let Some(indexed) = logs_from_index(store, &request.params).await {
            read_cache::record_logs(true);
            return rpc_result(id, indexed);
        }
        read_cache::record_logs(false);

        return match forward_windowed_logs(&request.params).await {
            Ok(logs) => rpc_result(id, logs),
            // The range-cap message is the one thing a caller can act on, so it survives.
            Err(e) => {
                let message = e.to_string();
                error!("chain/rpc eth_getLogs: {message}");
                if message.contains("too wide") {
                    rpc_error(id, -32602, &message)
                } else {
                    rpc_error(id, -32000, "Upstream log query failed")
                }
            }
        };
    }

    let body = json!({
        "jsonrpc": "2.0",
        "id": request.id.clone().unwrap_or(json!(1)),
        "method": request.method,
        "params": request.params,
    });

    let response = match HTTP.post(&CONFIG.http_rpc_url).json(&body).send().await {
        Ok(response) => response,
        Err(e) => {
            error!("chain/rpc: upstream request failed: {}", e.without_url());
            return rpc_error(id, -32000, "Upstream RPC unavailable");
        }
    };
    let value = match response.json::<Value>().await {
        Ok(value) => value,
        Err(e) => {
            error!(
                "chain/rpc: upstream returned invalid JSON: {}",
                e.without_url()
            );
            return rpc_error(id, -32000, "Upstream returned invalid JSON");
        }
    };

    // Only successful results are cached: an error is about this attempt, not about the chain.
    if let (Some((address, data, block)), Some(result)) =
        (&call_key, value.get("result").and_then(Value::as_str))
    {
        read_cache::put_call(address, data, *block, result.to_string(), issued_at_block).await;
    }

    // Only the number is known here. A timestamp of 0 would make `/chain/head` serve an epoch date
    // that callers compare voting deadlines against.
    if request.method == "eth_blockNumber" {
        if let Some(number) = value
            .get("result")
            .and_then(Value::as_str)
            .and_then(hex_u64)
        {
            read_cache::put_block_number(number).await;
        }
    }

    value
}

/// Answer an `eth_getLogs` filter from the log index, or `None` when it cannot be answered there.
///
/// The answer has the JSON-RPC wire shape, so a caller cannot tell an indexed answer from a
/// forwarded one. `None` on any doubt sends the query upstream rather than answering short.
async fn logs_from_index(store: &web::Data<AppData>, params: &Value) -> Option<Vec<Value>> {
    let filter = params.get(0)?;
    let address = filter.get("address")?.as_str()?;

    // `blockHash` names one specific block, possibly an orphaned one. The index is keyed by
    // height, and with both range bounds absent the bounds below would default to the head and
    // answer with the head block's logs.
    if filter.get("blockHash").is_some_and(|v| !v.is_null()) {
        return None;
    }

    let indexed = coverage_for(store, address).await?;
    let indexed_head = indexed.1;

    // `pending` includes blocks an index built from applied blocks cannot speak for. A
    // non-string bound defaults to the head, as an absent one does.
    let bound = |value: Option<&Value>| match value.and_then(Value::as_str) {
        None => Some(indexed_head),
        Some("pending") => None,
        Some(_) => range_bound(value, indexed_head),
    };

    // Both bounds default to `latest`, not genesis: a filter with no `fromBlock` is a
    // single-block query.
    let from = bound(filter.get("fromBlock"))?;
    let to = bound(filter.get("toBlock"))?;

    // Not clamped: a request reaching past what has been applied must go upstream.
    if !covered(Some(indexed), from, to) {
        return None;
    }

    // Only positional topic filters are served; an array in a position means "any of these",
    // which the index does not implement.
    let topics: Vec<Option<String>> = match filter.get("topics") {
        None => Vec::new(),
        Some(Value::Array(entries)) => entries
            .iter()
            .map(|entry| match entry {
                Value::Null => Some(None),
                Value::String(topic) => Some(Some(topic.clone())),
                _ => None,
            })
            .collect::<Option<_>>()?,
        Some(_) => return None,
    };

    let found = store
        .logs()
        .query(address, from, to, &topics)
        .await
        .map_err(|e| warn!("chain/rpc eth_getLogs: index read failed, going upstream: {e}"))
        .ok()?;

    // Every field of the mined-log shape, or nothing. An entry stored without `blockHash` or
    // `transactionIndex` cannot be rendered completely, and `null` there is the shape of a PENDING
    // log. Such a query goes upstream until the range is re-indexed.
    found
        .into_iter()
        .map(|log| {
            let (block_hash, transaction_index) = (log.block_hash?, log.transaction_index?);
            Some(json!({
                "address": log.address,
                "topics": log.topics,
                "data": log.data,
                "blockNumber": format!("0x{:x}", log.block_number),
                "blockHash": block_hash,
                "transactionHash": log.transaction_hash,
                "transactionIndex": format!("0x{transaction_index:x}"),
                "logIndex": format!("0x{:x}", log.log_index),
                "removed": false,
            }))
        })
        .collect()
}

/// A log-range bound: a hex number (`0x` required), `earliest`, or a tag that resolves to `head`.
/// `None` for anything else, so a malformed bound such as a decimal `"1000"` is refused instead of
/// silently rewritten to a different range.
fn range_bound(value: Option<&Value>, head: u64) -> Option<u64> {
    match value {
        None | Some(Value::Null) => Some(head),
        Some(Value::String(tag)) => match tag.as_str() {
            "latest" | "pending" | "safe" | "finalized" => Some(head),
            "earliest" => Some(0),
            hex => hex.strip_prefix("0x").and_then(hex_u64),
        },
        Some(_) => None,
    }
}

/// One `eth_getLogs` call upstream: the `result` array, or an error for a JSON-RPC error.
async fn fetch_logs(filter: &impl Serialize) -> anyhow::Result<Vec<Value>> {
    let body = json!({ "jsonrpc": "2.0", "id": 1, "method": "eth_getLogs", "params": [filter] });
    let send = async {
        HTTP.post(&CONFIG.http_rpc_url)
            .json(&body)
            .send()
            .await?
            .json()
            .await
    };
    let mut response: Value = send.await.map_err(reqwest::Error::without_url)?;

    if let Some(error) = response.get("error") {
        anyhow::bail!("upstream error: {error}");
    }

    Ok(match response.get_mut("result").map(Value::take) {
        Some(Value::Array(logs)) => logs,
        _ => Vec::new(),
    })
}

/// Run an `eth_getLogs` request as a series of bounded windows and concatenate the results.
async fn forward_windowed_logs(params: &Value) -> eyre::Result<Vec<Value>> {
    let mut filter = params.get(0).cloned().unwrap_or_else(|| json!({}));

    // A `blockHash` filter names one block and excludes a range, so windowing it would produce a
    // request the node rejects. It is forwarded as-is in a single call.
    if filter.get("blockHash").is_some_and(|v| !v.is_null()) {
        return fetch_logs(&filter).await.map_err(|e| eyre::eyre!("{e:#}"));
    }

    let head = rpc::provider().await?.get_block_number().await?;

    let bound = |key: &str| {
        let value = filter.get(key);
        range_bound(value, head).ok_or_else(|| eyre::eyre!("invalid block tag: {value:?}"))
    };
    let from = bound("fromBlock")?;
    let to = bound("toBlock")?.min(head);

    if window_count(from, to) > MAX_LOG_WINDOWS {
        eyre::bail!(
            "range {from}-{to} is too wide; at most {} blocks per request",
            MAX_LOG_WINDOWS * LOG_WINDOW
        );
    }

    let Some(window) = filter.as_object_mut() else {
        eyre::bail!("the log filter must be an object");
    };

    let mut all = Vec::new();
    for (start, end) in windows(from, to) {
        window.insert("fromBlock".into(), format!("0x{start:x}").into());
        window.insert("toBlock".into(), format!("0x{end:x}").into());

        all.extend(upstream_window(|| fetch_logs(&*window)).await?);
    }

    Ok(all)
}

#[derive(Serialize)]
struct HeadResponse {
    block_number: u64,
    timestamp: u64,
    chain_id: u64,
}

/// The chain head: block number and its timestamp, so callers deciding whether a voting window has
/// closed need no second round trip.
async fn head(http_request: HttpRequest, limiter: web::Data<ChainRateLimiter>) -> impl Responder {
    if let Err(refused) = charge(&http_request, &limiter, 1, "/chain/head") {
        return refused;
    }

    // The most-polled call in the app: serving a few seconds old head collapses many hooks into
    // one upstream request. Only a fully-known head is served: an entry learned from
    // `eth_blockNumber` has no timestamp, and callers compare voting deadlines against it.
    if let Some(cached) = read_cache::head().await {
        if let Some(timestamp) = cached.timestamp {
            read_cache::record_head(true);
            return HttpResponse::Ok().json(HeadResponse {
                block_number: cached.block_number,
                timestamp,
                chain_id: CONFIG.chain_id,
            });
        }
    }
    read_cache::record_head(false);

    let provider = match rpc::provider().await {
        Ok(provider) => provider,
        Err(e) => return upstream_failed("chain/head: provider unavailable", e),
    };

    match provider.get_block_by_number(BlockNumberOrTag::Latest).await {
        Ok(Some(block)) => {
            read_cache::put_head(block.header.number, block.header.timestamp).await;
            HttpResponse::Ok().json(HeadResponse {
                block_number: block.header.number,
                timestamp: block.header.timestamp,
                chain_id: CONFIG.chain_id,
            })
        }
        Ok(None) => json_message(
            StatusCode::SERVICE_UNAVAILABLE,
            "Upstream RPC returned no head block",
        ),
        Err(e) => upstream_failed("chain/head", e),
    }
}

#[derive(Deserialize)]
struct ReadCall {
    address: String,
    /// ABI-encoded calldata, hex with or without the `0x` prefix. The caller owns the encoding,
    /// so a client can use any view function without a redeploy.
    data: String,
    /// Historical block; latest when omitted.
    #[serde(default)]
    block_number: Option<u64>,
}

#[derive(Deserialize)]
struct ReadRequest {
    calls: Vec<ReadCall>,
}

#[derive(Serialize)]
struct ReadResult {
    /// Hex-encoded return data, or null when the call reverted.
    result: Option<String>,
    /// Revert reason, so a caller can tell "reverted" from "returned empty".
    error: Option<String>,
}

/// `eth_call` against allowlisted contracts, batched.
///
/// Point reads (a balance, a delegation, a proposal struct) come from the chain, not the index:
/// they are per-user and change constantly, and a stale answer is the wrong balance or a voter
/// wrongly told they are ineligible.
async fn read(
    http_request: HttpRequest,
    request: web::Json<ReadRequest>,
    limiter: web::Data<ChainRateLimiter>,
) -> impl Responder {
    // Capped before charged, as in `/chain/rpc`.
    if request.calls.len() > MAX_BATCH {
        return json_message(
            StatusCode::BAD_REQUEST,
            format!("At most {MAX_BATCH} calls per request"),
        );
    }

    if let Err(refused) = charge(&http_request, &limiter, request.calls.len(), "/chain/read") {
        return refused;
    }

    if request.calls.is_empty() {
        return HttpResponse::Ok().json(Vec::<ReadResult>::new());
    }

    let provider = match rpc::provider().await {
        Ok(provider) => provider,
        Err(e) => return upstream_failed("chain/read: provider unavailable", e),
    };

    // Every call is validated before any is fetched, so a bad call at the end of the batch costs
    // no upstream request.
    let mut parsed = Vec::with_capacity(request.calls.len());
    for call in &request.calls {
        let Some(address) = parse_address(&call.address) else {
            return json_message(
                StatusCode::BAD_REQUEST,
                format!("Invalid address: {}", call.address),
            );
        };
        if !is_allowed(&address) {
            return json_message(
                StatusCode::FORBIDDEN,
                format!("Address not served by this indexer: {address}"),
            );
        }
        let Ok(data) = Bytes::from_str(call.data.trim()) else {
            return json_message(StatusCode::BAD_REQUEST, "Invalid calldata");
        };
        parsed.push((address, data));
    }

    let mut results = Vec::with_capacity(parsed.len());
    let issued_at_block = read_cache::current_latest_block().await;

    for (call, (address, data)) in request.calls.iter().zip(parsed) {
        // Within one block an `eth_call` at `latest` is deterministic, so a repeat is a redundant
        // question, not a fresher answer.
        if let Some(hit) = read_cache::call(&call.address, &call.data, call.block_number).await {
            read_cache::record_call(true);
            results.push(ReadResult {
                result: Some(hit),
                error: None,
            });
            continue;
        }
        read_cache::record_call(false);

        let mut pending = provider.call(
            TransactionRequest::default()
                .with_to(address)
                .with_input(data),
        );
        if let Some(number) = call.block_number {
            pending = pending.block(BlockNumberOrTag::Number(number).into());
        }

        // A revert is reported per call, not as a batch failure: callers probe functions a
        // contract may not implement, and one expected revert must not discard the other results.
        results.push(match pending.await {
            Ok(output) => {
                let encoded = output.to_string();
                read_cache::put_call(
                    &call.address,
                    &call.data,
                    call.block_number,
                    encoded.clone(),
                    issued_at_block,
                )
                .await;
                ReadResult {
                    result: Some(encoded),
                    error: None,
                }
            }
            Err(e) => ReadResult {
                result: None,
                error: Some(e.to_string()),
            },
        });
    }

    HttpResponse::Ok().json(results)
}

#[derive(Deserialize)]
struct LogsRequest {
    address: String,
    /// Positional topic filters. `null` in any position matches anything, as in `eth_getLogs`.
    #[serde(default)]
    topics: Vec<Option<String>>,
    #[serde(default)]
    from_block: Option<u64>,
    #[serde(default)]
    to_block: Option<u64>,
}

#[derive(Serialize)]
struct LogEntry {
    address: String,
    topics: Vec<String>,
    data: String,
    block_number: Option<u64>,
    transaction_hash: Option<String>,
    log_index: Option<u64>,
}

/// `eth_getLogs` over an arbitrary range, windowed server-side.
async fn logs(
    http_request: HttpRequest,
    request: web::Json<LogsRequest>,
    store: web::Data<AppData>,
    limiter: web::Data<ChainRateLimiter>,
) -> impl Responder {
    // Admission happens twice. This charge covers the request and the index-served path, which
    // makes no upstream call. The upstream scan is charged again for the windows it opens once the
    // range is known: a query can expand to `MAX_LOG_WINDOWS` calls.
    if let Err(refused) = charge(&http_request, &limiter, 1, "/chain/logs") {
        return refused;
    }

    let Some(address) = parse_address(&request.address) else {
        return json_message(
            StatusCode::BAD_REQUEST,
            format!("Invalid address: {}", request.address),
        );
    };

    if !is_allowed(&address) {
        return json_message(
            StatusCode::FORBIDDEN,
            format!("Address not served by this indexer: {address}"),
        );
    }

    // Parsed before either source and before the window charge, so the index and the upstream
    // path refuse the same filters. Refused, not truncated: a log has at most four topics.
    if request.topics.len() > 4 {
        return json_message(
            StatusCode::BAD_REQUEST,
            "At most 4 topic positions may be filtered",
        );
    }
    let mut topics = Vec::with_capacity(request.topics.len());
    for (position, topic) in request.topics.iter().enumerate() {
        match topic
            .as_deref()
            .map(|t| B256::from_str(t.trim()))
            .transpose()
        {
            Ok(topic) => topics.push(topic),
            Err(_) => {
                return json_message(
                    StatusCode::BAD_REQUEST,
                    format!("Invalid topic at position {position}"),
                )
            }
        }
    }

    // Served from the index when it demonstrably covers the whole range: a scan of a contract's
    // history becomes one read. A silently short answer is worse than a slower correct one.
    let from = request.from_block.unwrap_or(0);
    if let Some(indexed) = coverage_for(&store, &request.address).await {
        // Compared BEFORE clamping, so a caller asking past the indexed head gets the upstream
        // answer, not a quietly truncated one.
        let to = request.to_block.unwrap_or(indexed.1);

        if covered(Some(indexed), from, to) {
            let wanted: Vec<Option<String>> =
                topics.iter().map(|t| t.map(|h| h.to_string())).collect();
            match store
                .logs()
                .query(&request.address, from, to, &wanted)
                .await
            {
                Ok(found) => {
                    read_cache::record_logs(true);
                    return HttpResponse::Ok().json(
                        found
                            .into_iter()
                            .map(|log| LogEntry {
                                address: log.address,
                                topics: log.topics,
                                data: log.data,
                                block_number: Some(log.block_number),
                                transaction_hash: log.transaction_hash,
                                log_index: Some(log.log_index),
                            })
                            .collect::<Vec<_>>(),
                    );
                }
                Err(e) => error!("chain/logs: index read failed, falling back upstream: {e}"),
            }
        }
    }

    // Reached only when the index could not answer, so the counter reflects real fallthrough.
    read_cache::record_logs(false);

    let provider = match rpc::provider().await {
        Ok(provider) => provider,
        Err(e) => return upstream_failed("chain/logs: provider unavailable", e),
    };

    let head = match provider.get_block_number().await {
        Ok(number) => number,
        Err(e) => return upstream_failed("chain/logs: head lookup failed", e),
    };

    let to = request.to_block.unwrap_or(head).min(head);

    if from > to {
        return HttpResponse::Ok().json(Vec::<LogEntry>::new());
    }

    let count = window_count(from, to);

    if count > MAX_LOG_WINDOWS {
        return json_message(
            StatusCode::BAD_REQUEST,
            format!(
                "Range {from}-{to} is too wide; at most {} blocks per request. Start from the \
                 contract's deployment block.",
                MAX_LOG_WINDOWS * LOG_WINDOW
            ),
        );
    }

    // Charged after the width cap, so a range too wide to serve is refused with the message that
    // explains it, not with a rate-limit refusal.
    if let Err(refused) = charge(
        &http_request,
        &limiter,
        count as usize,
        "/chain/logs (upstream scan)",
    ) {
        return refused;
    }

    let mut base = Filter::new().address(address);
    for (position, topic) in topics.into_iter().enumerate() {
        let Some(hash) = topic else { continue };
        base = match position {
            0 => base.event_signature(hash),
            1 => base.topic1(hash),
            2 => base.topic2(hash),
            _ => base.topic3(hash),
        };
    }

    let mut entries: Vec<LogEntry> = Vec::new();

    for (start, end) in windows(from, to) {
        let filter = &base
            .clone()
            .from_block(BlockNumberOrTag::Number(start))
            .to_block(BlockNumberOrTag::Number(end));

        let found = upstream_window(|| async move {
            provider.get_logs(filter).await.map_err(anyhow::Error::from)
        })
        .await;

        match found {
            Ok(found) => entries.extend(found.into_iter().map(|log| LogEntry {
                address: log.address().to_string(),
                topics: log.topics().iter().map(|t| t.to_string()).collect(),
                data: log.data().data.to_string(),
                block_number: log.block_number,
                transaction_hash: log.transaction_hash.map(|h| h.to_string()),
                log_index: log.log_index,
            })),
            Err(e) => {
                return unavailable(
                    format_args!("chain/logs: window {start}-{end} failed"),
                    e,
                    "Upstream RPC rejected a log query",
                );
            }
        }
    }

    entries.sort_by_key(|entry| (entry.block_number, entry.log_index));

    HttpResponse::Ok().json(entries)
}

#[derive(Deserialize)]
struct BlockAtTimestampRequest {
    timestamp: u64,
}

#[derive(Serialize)]
struct BlockAtTimestampResponse {
    block_number: u64,
    timestamp: u64,
}

/// The last block at or before a timestamp, so clients can turn a proposal's snapshot timepoint
/// into a block without an `O(log n)` client-side bisection.
async fn block_at_timestamp(
    http_request: HttpRequest,
    request: web::Json<BlockAtTimestampRequest>,
    limiter: web::Data<ChainRateLimiter>,
) -> impl Responder {
    if let Err(refused) = charge(
        &http_request,
        &limiter,
        BLOCK_SEARCH_COST,
        "/chain/block-at-timestamp",
    ) {
        return refused;
    }

    let provider = match rpc::provider().await {
        Ok(provider) => provider,
        Err(e) => return upstream_failed("chain/block-at-timestamp: provider unavailable", e),
    };

    let target = request.timestamp;

    let head_block = match provider.get_block_by_number(BlockNumberOrTag::Latest).await {
        Ok(Some(block)) => block,
        Ok(None) => return upstream_unavailable(),
        Err(e) => return upstream_failed("chain/block-at-timestamp: head lookup failed", e),
    };

    // A timestamp in the future resolves to the head: callers ask about windows that have not
    // closed yet, and the latest block is the honest answer.
    if head_block.header.timestamp <= target {
        return HttpResponse::Ok().json(BlockAtTimestampResponse {
            block_number: head_block.header.number,
            timestamp: head_block.header.timestamp,
        });
    }

    let mut low = 0u64;
    let mut high = head_block.header.number;
    let mut best: Option<(u64, u64)> = None;

    while low <= high {
        let mid = low + (high - low) / 2;

        // A failed probe aborts the search: the bisection has ruled out only half the range at
        // each step, so `best` is a partial answer. Returning it once reported block 0 and made a
        // snapshot lookup read `getPastVotes(voter, 0)` and mark every voter ineligible.
        let block = match provider
            .get_block_by_number(BlockNumberOrTag::Number(mid))
            .await
        {
            Ok(Some(block)) => block,
            Ok(None) => {
                return unavailable(
                    "chain/block-at-timestamp",
                    format_args!("block {mid} missing during bisection"),
                    "Upstream RPC could not resolve the timestamp",
                );
            }
            Err(e) => {
                return upstream_failed(
                    format_args!("chain/block-at-timestamp: block {mid} lookup failed"),
                    e,
                );
            }
        };

        if block.header.timestamp <= target {
            best = Some((block.header.number, block.header.timestamp));
            let Some(next) = mid.checked_add(1) else {
                break;
            };
            low = next;
        } else {
            if mid == 0 {
                break;
            }
            high = mid - 1;
        }
    }

    // `best` is empty only when even genesis is later than the target. There is no honest block
    // number to report: `0` with a `0` timestamp reads as an epoch date to a voting-window check.
    let Some((block_number, timestamp)) = best else {
        return json_message(
            StatusCode::NOT_FOUND,
            "No block exists at or before that timestamp",
        );
    };

    HttpResponse::Ok().json(BlockAtTimestampResponse {
        block_number,
        timestamp,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[actix_web::test]
    async fn an_untrusted_forwarded_header_cannot_mint_a_new_identity() {
        // With `trust_proxy_headers` off (the default), two requests from the same socket are the
        // same caller however they label themselves; otherwise the window bounds nothing.
        let first = actix_web::test::TestRequest::default()
            .peer_addr("10.0.0.1:1111".parse().unwrap())
            .insert_header(("X-Forwarded-For", "1.2.3.4"))
            .to_http_request();
        let second = actix_web::test::TestRequest::default()
            .peer_addr("10.0.0.1:2222".parse().unwrap())
            .insert_header(("X-Forwarded-For", "5.6.7.8"))
            .to_http_request();

        assert_eq!(identify(&first, false), identify(&second, false));

        // With a trusted proxy in front, the header is what distinguishes them.
        assert_ne!(identify(&first, true), identify(&second, true));
    }
}
