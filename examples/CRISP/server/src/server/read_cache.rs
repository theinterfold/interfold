// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Deduplication of chain reads across clients, so N clients asking the same question cost one
//! upstream request.
//!
//! Contract state changes only at a block boundary, so two `eth_call`s at `latest` within one
//! block return the same bytes. The `latest` cache is keyed by block and dropped when the head
//! moves, which also bounds it to one block's distinct reads. A call pinned to a historical block
//! is immutable, so it survives block changes and only the size cap evicts it.
//!
//! The cache lives in memory, not in sled: it churns, it is worthless after a restart, and writing
//! it to the store that the indexer holds a global lock on would slow down what it speeds up.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::sync::LazyLock;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

/// How long a cached head is served before the provider is asked again. It is well under a block
/// time, so a crowd of pollers costs one upstream call every few seconds and the head is never
/// more than one block stale.
const HEAD_TTL: Duration = Duration::from_secs(3);

/// Hard cap on cached calls, so a client that enumerates distinct calldata cannot grow the cache
/// without bound between blocks.
const MAX_ENTRIES: usize = 20_000;

/// The longest `eth_call` result that the cache keeps, so large returns cannot fill memory.
const MAX_RESULT_BYTES: usize = 64 * 1024;

/// Backstop lifetime for the `latest` call cache. Block-boundary invalidation fires only when
/// something reads the head. If head refreshes stop (a client that only calls `/chain/read`, or an
/// upstream that fails `/chain/head`), old entries would otherwise serve as `latest` until restart.
/// This bounds the worst case to one stale block.
const LATEST_CALL_TTL: Duration = Duration::from_secs(6);

#[derive(Clone, Copy)]
pub struct CachedHead {
    pub block_number: u64,
    /// `None` when the head was learned from `eth_blockNumber`, which carries no timestamp.
    /// Callers that need the time must fall through rather than be handed a zero.
    pub timestamp: Option<u64>,
}

#[derive(Default)]
struct Inner {
    head: Option<(CachedHead, Instant)>,
    /// Reads at `latest`, valid only for `latest_block`.
    latest_calls: HashMap<(String, String), String>,
    latest_block: u64,
    /// When `latest_block` was last advanced, for the TTL backstop.
    latest_block_at: Option<Instant>,
    /// Reads pinned to a historical block, keyed by `(address, calldata, block)`.
    historical_calls: HashMap<(String, String, u64), String>,
}

static CACHE: LazyLock<RwLock<Inner>> = LazyLock::new(|| RwLock::new(Inner::default()));

/// The cached head, if it is still fresh.
pub async fn head() -> Option<CachedHead> {
    let (head, fetched_at) = CACHE.read().await.head?;
    (fetched_at.elapsed() < HEAD_TTL).then_some(head)
}

/// The block number of the cached head, whether or not its timestamp is known.
pub async fn head_number() -> Option<u64> {
    head().await.map(|head| head.block_number)
}

/// Record a freshly read head.
pub async fn put_head(block_number: u64, timestamp: u64) {
    store_head(block_number, Some(timestamp)).await
}

/// Record a head learned without its timestamp (the `eth_blockNumber` path).
pub async fn put_block_number(block_number: u64) {
    store_head(block_number, None).await
}

async fn store_head(block_number: u64, timestamp: Option<u64>) {
    let mut guard = CACHE.write().await;

    // A new head invalidates every `latest` call. `!=` rather than `>`: a reorg that lowers the
    // head also discards the state these results describe, and `>` would keep serving the
    // orphaned block's answers.
    if block_number != guard.latest_block {
        guard.latest_block = block_number;
        guard.latest_block_at = Some(Instant::now());
        guard.latest_calls.clear();
    }

    // A timestamped entry is worth more than a bare number for the same block, so a number-only
    // update must not overwrite one.
    if timestamp.is_none() {
        if let Some((existing, _)) = guard.head {
            if existing.block_number == block_number && existing.timestamp.is_some() {
                return;
            }
        }
    }

    guard.head = Some((
        CachedHead {
            block_number,
            timestamp,
        },
        Instant::now(),
    ));
}

/// The block the `latest` call cache is currently keyed to, for compare-and-set on insert.
pub async fn current_latest_block() -> u64 {
    CACHE.read().await.latest_block
}

fn normalise(address: &str, data: &str) -> (String, String) {
    (address.to_lowercase(), data.to_lowercase())
}

/// A cached `eth_call` result, if one is valid for the block being asked about.
pub async fn call(address: &str, data: &str, block: Option<u64>) -> Option<String> {
    let (address, data) = normalise(address, data);
    let guard = CACHE.read().await;

    match block {
        Some(block) => guard.historical_calls.get(&(address, data, block)).cloned(),
        None => {
            // A `latest` result is served only when the block it belongs to is known and was
            // confirmed recently enough for the entry to still describe the head.
            if guard.latest_block == 0
                || guard
                    .latest_block_at
                    .is_none_or(|at| at.elapsed() >= LATEST_CALL_TTL)
            {
                return None;
            }
            guard.latest_calls.get(&(address, data)).cloned()
        }
    }
}

/// Store an `eth_call` result.
///
/// `observed_at_block` is the block the `latest` cache was keyed to when the call was ISSUED. If
/// the head has moved since, the result describes the previous block, and filing it under the new
/// one would serve stale bytes as current.
pub async fn put_call(
    address: &str,
    data: &str,
    block: Option<u64>,
    result: String,
    observed_at_block: u64,
) {
    if result.len() > MAX_RESULT_BYTES {
        return;
    }
    let (address, data) = normalise(address, data);
    let mut guard = CACHE.write().await;

    match block {
        Some(block) => {
            if guard.historical_calls.len() >= MAX_ENTRIES {
                guard.historical_calls.clear();
            }
            guard
                .historical_calls
                .insert((address, data, block), result);
        }
        None => {
            if guard.latest_block == 0 || guard.latest_block != observed_at_block {
                return;
            }
            if guard.latest_calls.len() >= MAX_ENTRIES {
                guard.latest_calls.clear();
            }
            guard.latest_calls.insert((address, data), result);
        }
    }
}

/// A snapshot of the counters for the `/chain/stats` route, so the saving is observable rather
/// than asserted.
#[derive(serde::Serialize)]
pub struct Counters {
    pub call_hits: u64,
    pub call_misses: u64,
    pub head_hits: u64,
    pub head_misses: u64,
    pub log_index_hits: u64,
    pub log_upstream: u64,
}

#[derive(Default)]
struct Tally {
    call_hits: AtomicU64,
    call_misses: AtomicU64,
    head_hits: AtomicU64,
    head_misses: AtomicU64,
    log_index_hits: AtomicU64,
    log_upstream: AtomicU64,
}

static TALLY: LazyLock<Tally> = LazyLock::new(Tally::default);

fn count(hit: bool, hits: &AtomicU64, misses: &AtomicU64) {
    (if hit { hits } else { misses }).fetch_add(1, Relaxed);
}

pub fn record_call(hit: bool) {
    count(hit, &TALLY.call_hits, &TALLY.call_misses);
}

pub fn record_head(hit: bool) {
    count(hit, &TALLY.head_hits, &TALLY.head_misses);
}

pub fn record_logs(from_index: bool) {
    count(from_index, &TALLY.log_index_hits, &TALLY.log_upstream);
}

pub fn counters() -> Counters {
    Counters {
        call_hits: TALLY.call_hits.load(Relaxed),
        call_misses: TALLY.call_misses.load(Relaxed),
        head_hits: TALLY.head_hits.load(Relaxed),
        head_misses: TALLY.head_misses.load(Relaxed),
        log_index_hits: TALLY.log_index_hits.load(Relaxed),
        log_upstream: TALLY.log_upstream.load(Relaxed),
    }
}
