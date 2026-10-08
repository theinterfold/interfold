// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Reading one contract's event history, from the index where it reaches and the provider where
//! it does not, plus the request plumbing every domain route shares.
//!
//! Index coverage begins wherever this server started indexing, which on a deployment with no
//! backfill is long after the contract shipped. A route that refused what its index cannot cover
//! would push the scan back into every browser, so the gap is fetched upstream here, once, for
//! everyone.

use crate::server::app_data::AppData;
use crate::server::rpc;

use super::chain::{is_allowed, is_log_indexed, parse_address};
use super::{json_message, upstream_unavailable};

use actix_web::{http::StatusCode, web, HttpResponse};
use alloy::eips::BlockNumberOrTag;
use alloy::primitives::{Address, Bytes, B256};
use alloy::providers::{DynProvider, Provider};
use alloy::rpc::types::Filter;
use e3_sdk::evm_helpers::retry::call_with_retry;
use log::{error, warn};
use std::collections::HashMap;
use std::fmt::Display;
use std::future::Future;
use std::str::FromStr;
use std::sync::{Arc, Mutex, PoisonError, RwLock};
use tokio::sync::OwnedMutexGuard;

/// Blocks per upstream `eth_getLogs` window. Matches the indexer's window, so callers never need
/// to know the provider's range cap.
pub(super) const LOG_WINDOW: u64 = 2_000;

/// Cap on the windows one scan may expand into (about 1.2M blocks). A scan reaching further is a
/// misconfigured `from_block`, and answering it would tie up a connection for minutes.
const MAX_LOG_WINDOWS: u64 = 600;

/// The go-ethereum `eth_getLogs` error (`errBlockRangeIntoFuture`, code -32602) for a range that
/// ends past the head of the node that serves the request.
const BEHIND_HEAD: &str = "block range extends beyond current head block";

/// How many `LOG_WINDOW`s cover `[from, to]`; 0 when the range is empty.
pub(super) fn window_count(from: u64, to: u64) -> u64 {
    if from > to {
        return 0;
    }
    (to - from) / LOG_WINDOW + 1
}

/// The `LOG_WINDOW`-sized `(start, end)` windows covering `[from, to]`, in order.
pub(super) fn windows(from: u64, to: u64) -> impl Iterator<Item = (u64, u64)> {
    let mut next = Some(from).filter(|start| *start <= to);
    std::iter::from_fn(move || {
        let start = next?;
        let end = start.saturating_add(LOG_WINDOW - 1).min(to);
        next = end.checked_add(1).filter(|following| *following <= to);
        Some((start, end))
    })
}

/// Run one upstream `eth_getLogs` window, and run it again while the serving node is behind it.
///
/// The provider spreads requests over nodes, and one node can trail another by most of a block, so
/// a head that one node reports can be a block the next node has not imported. Only the
/// [`BEHIND_HEAD`] error is retried: 3 attempts, 6 s of waits in total, which keeps a retried
/// request inside the 10 s default timeout of a viem client.
pub(super) async fn upstream_window<T, F, Fut>(query: F) -> eyre::Result<T>
where
    F: Fn() -> Fut,
    Fut: Future<Output = anyhow::Result<T>>,
{
    call_with_retry("eth_getLogs window", &[BEHIND_HEAD], query)
        .await
        .map_err(|e| eyre::eyre!("{e:#}"))
}

/// Log `error` and answer 503 with `message`.
pub(super) fn unavailable(
    context: impl Display,
    error: impl Display,
    message: &str,
) -> HttpResponse {
    error!("{context}: {error}");
    json_message(StatusCode::SERVICE_UNAVAILABLE, message)
}

/// Log `error` and answer the standard upstream-unavailable 503.
pub(super) fn upstream_failed(context: impl Display, error: impl Display) -> HttpResponse {
    error!("{context}: {error}");
    upstream_unavailable()
}

/// A contract named by the caller: 400 when it does not parse, 404 when this server does not
/// serve it. The allowlist is what stops a typed route from becoming a log scanner for any
/// contract on the chain, and what bounds the per-key cache and lock maps.
pub(super) fn served_address(
    raw: &str,
    noun: &str,
    not_served: &str,
) -> Result<Address, HttpResponse> {
    let address = parse_address(raw).ok_or_else(|| {
        json_message(
            StatusCode::BAD_REQUEST,
            format!("Invalid {noun} address: {raw}"),
        )
    })?;
    if !is_allowed(&address) {
        return Err(json_message(
            StatusCode::NOT_FOUND,
            format!("{not_served} {address} is not served by this indexer"),
        ));
    }
    Ok(address)
}

/// The `from_block` refusal reasons for [`ScanCtx::open`].
pub(super) const NO_BACKFILL: &str =
    "this server does not index its logs, so it has no deployment block to scan from";
pub(super) const NOT_INDEXED: &str = "its logs are not indexed here";

/// One event, in the shape both sources can produce.
#[derive(Debug, Clone)]
pub struct ScannedLog {
    pub topics: Vec<B256>,
    pub data: Bytes,
    pub block_number: u64,
    pub transaction_hash: Option<String>,
}

/// What the local index can answer for: `(first indexed block, last applied block)`.
pub type Coverage = Option<(u64, u64)>;

/// Whether the index answers all of `[from, to]`. A range starting before indexing began, or
/// reaching past what has been applied, would come back short and look authoritative.
pub(super) fn covered(indexed: Coverage, from: u64, to: u64) -> bool {
    indexed.is_some_and(|(first, head)| from >= first && to <= head)
}

/// One contract's event stream: which contract, which event, and what the index covers for it.
pub struct Target<'a> {
    pub address: Address,
    /// The address lowercased, as the log index keys it.
    pub key: &'a str,
    pub topic0: B256,
    /// Positional filters for topics 1..3, the event's indexed arguments; `None` matches anything.
    /// Pushed down to the source so a route asking for one proposal's votes does not pull every
    /// proposal's votes.
    pub topics: [Option<B256>; 3],
    pub indexed: Coverage,
}

impl<'a> Target<'a> {
    /// A target matching every log of one event, whatever its indexed arguments.
    pub fn any(address: Address, key: &'a str, topic0: B256, indexed: Coverage) -> Self {
        Self {
            address,
            key,
            topic0,
            topics: [None, None, None],
            indexed,
        }
    }
}

/// Every log of `target.topic0` from `target.address` in `[from, to]`.
///
/// The source is chosen per call, not per block: a range straddling the index's lower bound goes
/// upstream whole, because stitching two sources would mean trusting them to agree about the
/// boundary block.
pub async fn scan_logs(
    store: &web::Data<AppData>,
    provider: &DynProvider,
    target: &Target<'_>,
    from: u64,
    to: u64,
) -> eyre::Result<Vec<ScannedLog>> {
    if from > to {
        return Ok(Vec::new());
    }

    if covered(target.indexed, from, to) {
        from_index(store, target, from, to).await
    } else {
        from_upstream(provider, target, from, to).await
    }
}

/// The indexed path: one local read per bucket, no upstream request.
async fn from_index(
    store: &web::Data<AppData>,
    target: &Target<'_>,
    from: u64,
    to: u64,
) -> eyre::Result<Vec<ScannedLog>> {
    let filters = [
        Some(format!("{:#x}", target.topic0)),
        target.topics[0].map(|topic| format!("{topic:#x}")),
        target.topics[1].map(|topic| format!("{topic:#x}")),
        target.topics[2].map(|topic| format!("{topic:#x}")),
    ];
    let stored = store.logs().query(target.key, from, to, &filters).await?;

    let mut logs = Vec::with_capacity(stored.len());
    for entry in stored {
        // A stored log whose fields will not parse is skipped, not fatal: it costs one event, not
        // the whole history.
        let Ok(topics) = entry
            .topics
            .iter()
            .map(|topic| B256::from_str(topic.trim()))
            .collect::<Result<Vec<_>, _>>()
        else {
            continue;
        };
        let Ok(data) = Bytes::from_str(entry.data.trim()) else {
            continue;
        };

        logs.push(ScannedLog {
            topics,
            data,
            block_number: entry.block_number,
            transaction_hash: entry.transaction_hash,
        });
    }

    Ok(logs)
}

/// The upstream path, windowed.
async fn from_upstream(
    provider: &DynProvider,
    target: &Target<'_>,
    from: u64,
    to: u64,
) -> eyre::Result<Vec<ScannedLog>> {
    let count = window_count(from, to);
    if count > MAX_LOG_WINDOWS {
        eyre::bail!(
            "scanning {from}-{to} would take {count} windows, more than the {MAX_LOG_WINDOWS} cap"
        );
    }

    let mut base = Filter::new()
        .address(target.address)
        .event_signature(target.topic0);
    if let Some(topic) = target.topics[0] {
        base = base.topic1(topic);
    }
    if let Some(topic) = target.topics[1] {
        base = base.topic2(topic);
    }
    if let Some(topic) = target.topics[2] {
        base = base.topic3(topic);
    }

    let mut logs = Vec::new();
    for (start, end) in windows(from, to) {
        let filter = &base
            .clone()
            .from_block(BlockNumberOrTag::Number(start))
            .to_block(BlockNumberOrTag::Number(end));

        let found = upstream_window(|| async move {
            provider.get_logs(filter).await.map_err(anyhow::Error::from)
        })
        .await?;

        logs.extend(found.into_iter().map(|log| ScannedLog {
            topics: log.topics().to_vec(),
            data: log.data().data.clone(),
            block_number: log.block_number.unwrap_or_default(),
            transaction_hash: log.transaction_hash.map(|hash| hash.to_string()),
        }));
    }

    Ok(logs)
}

/// What the index covers for an address, or `None` when it is not indexed. An unreadable store is
/// logged and treated as not indexed, which sends the caller upstream.
pub(super) async fn coverage_for(store: &web::Data<AppData>, address_key: &str) -> Coverage {
    if !is_log_indexed(address_key) {
        return None;
    }

    let repo = store.logs();
    match (repo.coverage(address_key).await, repo.indexed_head().await) {
        (Ok(Some(from)), Ok(Some(head))) => Some((from, head)),
        (Err(e), _) | (_, Err(e)) => {
            warn!("log index coverage for {address_key} is unreadable, scanning upstream: {e}");
            None
        }
        _ => None,
    }
}

/// Everything a domain route needs to scan one contract's logs up to the current head.
pub(super) struct ScanCtx {
    pub(super) address: Address,
    /// The address lowercased, as the log index keys it.
    pub(super) key: String,
    pub(super) indexed: Coverage,
    /// How far local indexing reaches. Below `block` means part of an answer came upstream.
    pub(super) indexed_head: u64,
    pub(super) scan_from: u64,
    pub(super) block: u64,
    pub(super) provider: &'static DynProvider,
}

impl ScanCtx {
    /// Resolve where to scan `scan` from, and read the head.
    ///
    /// Index coverage is not a precondition: a range it cannot cover is scanned upstream.
    /// `from_block` names where history has to start, because the server cannot know a deployment
    /// block; only a contract this server indexes has a default. `subject` and `reason` shape the
    /// 400 when neither exists.
    pub(super) async fn open(
        store: &web::Data<AppData>,
        route: &str,
        scan: Address,
        subject: Address,
        from_block: Option<u64>,
        reason: &str,
    ) -> Result<Self, HttpResponse> {
        let key = format!("{scan:#x}");
        let indexed = coverage_for(store, &key).await;

        let scan_from = from_block
            .or(indexed.map(|(from, _)| from))
            .ok_or_else(|| {
                json_message(
                    StatusCode::BAD_REQUEST,
                    format!("from_block is required for {subject}: {reason}"),
                )
            })?;

        let provider = rpc::provider()
            .await
            .map_err(|e| upstream_failed(format_args!("{route}: provider unavailable"), e))?;
        let block = provider
            .get_block_number()
            .await
            .map_err(|e| upstream_failed(format_args!("{route}: could not read the head"), e))?;

        Ok(Self {
            address: scan,
            key,
            indexed,
            indexed_head: indexed.map_or(0, |(_, head)| head),
            scan_from,
            block,
            provider,
        })
    }

    /// A target matching every log of `topic0` from the scanned contract.
    pub(super) fn target(&self, topic0: B256) -> Target<'_> {
        Target::any(self.address, &self.key, topic0, self.indexed)
    }
}

/// Per-key results plus one scan lock per key.
///
/// The lock keeps a cold cache from becoming a thundering herd: a historical scan can take tens
/// of windows and the cache is written only when it finishes, so without the lock every request
/// that arrives meanwhile would start its own. Holders queue and then find the cache warm, which
/// is why callers recheck the cache after taking the lock. Keys are allowlisted contracts, so both
/// maps stay bounded.
pub(super) struct ScanCache<V> {
    entries: RwLock<HashMap<String, V>>,
    locks: Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
}

impl<V> ScanCache<V> {
    pub(super) fn new() -> Self {
        Self {
            entries: RwLock::default(),
            locks: Mutex::default(),
        }
    }

    /// Read the entry for `key`, if any.
    pub(super) fn peek<R>(&self, key: &str, read: impl FnOnce(&V) -> Option<R>) -> Option<R> {
        let entries = self.entries.read().unwrap_or_else(PoisonError::into_inner);
        read(entries.get(key)?)
    }

    pub(super) fn insert(&self, key: String, value: V) {
        self.entries
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(key, value);
    }

    /// Wait for the scan slot of `key`.
    pub(super) async fn exclusive(&self, key: &str) -> OwnedMutexGuard<()> {
        let lock = {
            let mut locks = self.locks.lock().unwrap_or_else(PoisonError::into_inner);
            match locks.get(key) {
                Some(existing) => existing.clone(),
                None => locks.entry(key.to_owned()).or_default().clone(),
            }
        };
        lock.lock_owned().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::address;
    use alloy::providers::ProviderBuilder;
    use alloy::transports::mock::Asserter;

    #[test]
    fn windows_cover_the_range_exactly_and_never_wrap() {
        let cases: [(u64, u64, u64); 6] = [
            (5, 4, 0),
            (7, 7, 1),
            (0, LOG_WINDOW - 1, 1),
            (0, LOG_WINDOW, 2),
            (0, 600 * LOG_WINDOW - 1, 600),
            (u64::MAX - 1, u64::MAX, 1),
        ];
        for (from, to, expected) in cases {
            let spans: Vec<_> = windows(from, to).collect();
            assert_eq!(window_count(from, to), expected, "{from}-{to}");
            assert_eq!(spans.len() as u64, expected, "{from}-{to}");
            if let (Some(first), Some(last)) = (spans.first(), spans.last()) {
                assert_eq!((first.0, last.1), (from, to));
            }
            assert!(spans.windows(2).all(|pair| pair[0].1 + 1 == pair[1].0));
        }
    }

    #[tokio::test]
    async fn a_window_past_the_serving_node_head_is_retried() {
        let plugin = address!("0xb102de5f689C9af91e61702Ac24B6b9eA3E6b560");
        let topic0 = B256::repeat_byte(0xa6);
        let asserter = Asserter::new();
        let provider = ProviderBuilder::new()
            .connect_mocked_client(asserter.clone())
            .erased();

        // The node that answers first has not imported the last block of the window. The node
        // that answers the retry has it.
        asserter.push_failure(
            serde_json::from_str(
                r#"{"code":-32602,"message":"block range extends beyond current head block: requested 11863378, head 11863377"}"#,
            )
            .unwrap(),
        );
        asserter.push_success(&serde_json::json!([{
            "address": plugin,
            "topics": [topic0],
            "data": "0x",
            "blockNumber": "0xb50552",
            "blockHash": B256::repeat_byte(1),
            "transactionHash": B256::repeat_byte(2),
            "transactionIndex": "0x0",
            "logIndex": "0x0",
            "removed": false,
        }]));

        let target = Target::any(
            plugin,
            "0xb102de5f689c9af91e61702ac24b6b9ea3e6b560",
            topic0,
            None,
        );
        let logs = from_upstream(&provider, &target, 11_863_092, 11_863_378)
            .await
            .unwrap();

        assert_eq!(logs.len(), 1);
        assert_eq!(logs[0].block_number, 11_863_378);
    }
}
