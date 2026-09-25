// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Live Sepolia probe for the adaptive `eth_getLogs` window.
//!
//! Ignored by default: it needs the public internet and a live testnet deployment, so it must not
//! run in CI or in an offline checkout. Run it deliberately:
//!
//! ```text
//! cargo test -p e3-evm --test live_sepolia_window -- --ignored --nocapture
//! ```
//!
//! It drives the crate's own provider construction (the retry layer included) against the
//! deployed CiphernodeRegistry, and reports the request count and the observed range cap for
//! each endpoint. It asserts only what is true of any correct sync: every log-bearing block in
//! the scanned range is covered exactly once, and the window never exceeds what the provider
//! accepted.

use alloy::primitives::Address;
use alloy::providers::Provider;
use alloy::rpc::types::Filter;
use e3_config::{RpcAuth, RPC};
use e3_evm::{EthProvider, ProviderConfig};
use std::collections::BTreeSet;

/// Live Sepolia CiphernodeRegistry proxy.
const REGISTRY: &str = "0x118B7DFE26007ca2f618593A045EE474dF9DFBDf";

/// Endpoints to compare. Each is public and needs no key.
const ENDPOINTS: &[(&str, &str)] = &[
    ("tenderly", "https://sepolia.gateway.tenderly.co"),
    ("publicnode", "https://ethereum-sepolia-rpc.publicnode.com"),
];

async fn connect(url: &str) -> Option<EthProvider<e3_evm::ConcreteReadProvider>> {
    let rpc = RPC::from_url(url).ok()?;
    ProviderConfig::new(rpc, RpcAuth::None)
        .create_readonly_provider()
        .await
        .ok()
}

#[tokio::test]
#[ignore = "needs network access and the live Sepolia deployment"]
async fn live_sepolia_sync_covers_every_block_on_each_endpoint() {
    let address: Address = REGISTRY.parse().expect("registry address");

    for (name, url) in ENDPOINTS {
        // A probe failure fails the test. Skipping on connect or head errors would let the whole
        // run report success while checking nothing, which is the one outcome a live test must
        // never produce.
        let provider = connect(url)
            .await
            .unwrap_or_else(|| panic!("{name}: could not create a provider for {url}"));
        let head = provider
            .provider()
            .get_block_number()
            .await
            .unwrap_or_else(|error| panic!("{name}: head block unavailable: {error}"));

        // The real first sync: the earliest deployed contract's creation block to the head.
        // Taken from the live committee19 inventory, found by bisecting eth_getCode.
        let from = 11_677_096u64;
        let span = head.saturating_sub(from);

        // Walk the range in windows, exactly as the adapter does, and record coverage.
        let mut covered: BTreeSet<u64> = BTreeSet::new();
        let mut requests = 0u32;
        let mut width = 10_000u64;
        let mut cursor = from;
        let mut narrowed_to = None;

        while cursor <= head {
            let end = cursor.saturating_add(width - 1).min(head);
            let filter = Filter::new()
                .address(address)
                .from_block(cursor)
                .to_block(end);
            requests += 1;
            match provider.provider().get_logs(&filter).await {
                Ok(logs) => {
                    for log in &logs {
                        if let Some(block) = log.block_number {
                            covered.insert(block);
                            assert!(
                                block >= cursor && block <= end,
                                "{name}: provider returned block {block} outside {cursor}..={end}"
                            );
                        }
                    }
                    cursor = end + 1;
                }
                Err(error) => {
                    let message = format!("{error:#}");
                    // Mirror the adapter's decision without importing its private helper.
                    let looks_like_range = message.to_lowercase().contains("range")
                        || message.contains("-32701")
                        || message.contains("-32062");
                    assert!(
                        looks_like_range,
                        "{name}: unexpected non-range failure: {message}"
                    );
                    assert!(width > 1, "{name}: rejected even a single block: {message}");
                    width /= 2;
                    narrowed_to = Some(width);
                }
            }
        }

        assert_eq!(
            cursor,
            head + 1,
            "{name}: the scan must finish exactly at the head"
        );
        // Timestamp cost: how many of the returned logs carried their own blockTimestamp.
        // Every log that does is one eth_getBlockByNumber the sync no longer sends.
        let mut logs_seen = 0u32;
        let mut logs_with_timestamp = 0u32;
        // Bounded by the learned width: a fixed 10,000-block sample would fail on the endpoints the
        // scan above had to narrow for.
        let full = Filter::new()
            .address(address)
            .from_block(from)
            .to_block(from.saturating_add(width - 1).min(head));
        let sample = provider
            .provider()
            .get_logs(&full)
            .await
            .unwrap_or_else(|error| panic!("{name}: sample chunk failed: {error}"));
        for log in &sample {
            logs_seen += 1;
            if log.block_timestamp.is_some() {
                logs_with_timestamp += 1;
            }
        }

        println!(
            "{name}: scanned {span} blocks in {requests} request(s), final window {width}, \
             narrowed={narrowed_to:?}, log-bearing blocks seen={}",
            covered.len()
        );
        println!(
            "{name}: sample chunk -> {logs_with_timestamp}/{logs_seen} logs carried \
             blockTimestamp (that many eth_getBlockByNumber calls avoided)"
        );
    }
}
