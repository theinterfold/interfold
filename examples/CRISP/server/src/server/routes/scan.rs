// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Reading one contract's event history, from the index where it reaches and the provider where
//! it does not.
//!
//! Shared by every domain route, because the awkward part is the same for all of them: this
//! server's coverage begins wherever IT started indexing, which on a deployment with no backfill
//! is long after the contract shipped. A route that refused what its index could not cover would
//! push the whole scan back into every browser — which is the work these routes exist to stop —
//! so the gap is fetched upstream here instead, once, for everyone.

use crate::server::app_data::AppData;

use actix_web::web;
use alloy::eips::BlockNumberOrTag;
use alloy::primitives::{Address, Bytes, B256};
use alloy::providers::{DynProvider, Provider};
use alloy::rpc::types::Filter;
use e3_sdk::evm_helpers::retry::call_with_retry;
use std::future::Future;
use std::str::FromStr;

/// Blocks per upstream `eth_getLogs` window.
///
/// Matches `/chain/logs` and the indexer's own window: the point of windowing is that the caller
/// need not know the provider's range cap.
pub const LOG_WINDOW: u64 = 2_000;

/// Cap on how many windows one scan may expand into — about 1.2M blocks.
///
/// A scan reaching further than this is a misconfigured `from_block`, not a real request, and
/// answering it would tie up a connection for minutes.
pub const MAX_LOG_WINDOWS: u64 = 600;

/// The go-ethereum `eth_getLogs` error (`errBlockRangeIntoFuture`, code -32602) for a range that
/// ends past the head of the node that serves the request.
const BEHIND_HEAD: &str = "block range extends beyond current head block";

/// Run one upstream `eth_getLogs` window, and run it again while the serving node is behind it.
///
/// The provider spreads requests over nodes, and one node can trail another by most of a block.
/// A head that one node reports, to this server or to a client, can therefore be a block that the
/// next node has not imported yet. That node refuses the range with [`BEHIND_HEAD`] until it
/// imports the block, so only that error is retried: 3 attempts, 6 s of waits in total, which
/// keeps a retried request inside the 10 s default timeout of a viem client.
pub(super) async fn upstream_window<T, F, Fut>(query: F) -> eyre::Result<T>
where
    F: Fn() -> Fut,
    Fut: Future<Output = anyhow::Result<T>>,
{
    call_with_retry("eth_getLogs window", &[BEHIND_HEAD], query)
        .await
        .map_err(|e| eyre::eyre!("{e:#}"))
}

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

/// One contract's event stream: which contract, which event, and what the index covers for it.
///
/// Bundled rather than passed as five loose parameters, because they always travel together and
/// three of them are strings and addresses that would otherwise be easy to transpose at a call
/// site.
pub struct Target<'a> {
    pub address: Address,
    /// The address lowercased, as the log index keys it.
    pub key: &'a str,
    pub topic0: B256,
    /// Positional filters for topics 1..3 — the event's indexed arguments. `None` matches
    /// anything.
    ///
    /// Pushed down to the source rather than filtered after: the whole point of an indexed
    /// argument is that the node (or the bucket read) can skip what does not match, and a route
    /// asking for one proposal's votes should not pull every proposal's votes to find them.
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
/// The choice of source is all-or-nothing per call rather than per block: a range straddling the
/// index's lower bound goes upstream whole. Stitching a partially covered range would mean
/// trusting two sources to agree about the boundary block, and the ranges these routes ask for
/// are either historical (entirely below coverage) or incremental (entirely above it).
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

    if let Some((indexed_from, indexed_head)) = target.indexed {
        if from >= indexed_from && to <= indexed_head {
            return from_index(store, target, from, to).await;
        }
    }

    from_upstream(provider, target, from, to).await
}

/// The indexed path: one local read per bucket, no upstream request at all.
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
        // A stored log whose fields will not parse is skipped rather than failing the scan: it is
        // one event missing from an answer, not a reason to refuse the whole history.
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
    let windows = (to - from) / LOG_WINDOW + 1;
    if windows > MAX_LOG_WINDOWS {
        eyre::bail!(
            "scanning {from}-{to} would take {windows} windows, more than the {MAX_LOG_WINDOWS} cap"
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
    let mut start = from;

    while start <= to {
        let end = (start + LOG_WINDOW - 1).min(to);

        let filter = &base
            .clone()
            .from_block(BlockNumberOrTag::Number(start))
            .to_block(BlockNumberOrTag::Number(end));

        let found = upstream_window(|| async move {
            provider.get_logs(filter).await.map_err(anyhow::Error::from)
        })
        .await?;

        for log in found {
            logs.push(ScannedLog {
                topics: log.topics().to_vec(),
                data: log.data().data.clone(),
                block_number: log.block_number.unwrap_or_default(),
                transaction_hash: log.transaction_hash.map(|hash| hash.to_string()),
            });
        }

        start = end + 1;
    }

    Ok(logs)
}

/// What the index covers for an address, or `None` when it is not indexed at all.
pub async fn coverage_for(store: &web::Data<AppData>, address_key: &str) -> Coverage {
    if !super::chain::is_log_indexed(address_key) {
        return None;
    }

    let repo = store.logs();
    match (repo.coverage(address_key).await, repo.indexed_head().await) {
        (Ok(Some(from)), Ok(Some(head))) => Some((from, head)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::address;
    use alloy::providers::ProviderBuilder;
    use alloy::transports::mock::Asserter;

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
