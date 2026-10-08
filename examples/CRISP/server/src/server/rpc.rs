// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! The process-wide HTTP client and Ethereum read providers.
//!
//! Every upstream request goes through one pooled client with a request timeout. Without the
//! timeout, a provider that accepts a connection and then stalls holds the caller until restart.

use std::sync::LazyLock;
use std::time::Duration;

use alloy::eips::BlockNumberOrTag;
use alloy::providers::{DynProvider, Provider, ProviderBuilder};
use alloy::rpc::client::RpcClient;
use alloy::transports::http::Http;
use tokio::sync::OnceCell;

use crate::config::CONFIG;

/// Upper bound on one upstream HTTP request, connection included.
pub const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(20);

/// One pooled HTTP client for every outbound request of the process.
pub static HTTP: LazyLock<reqwest::Client> = LazyLock::new(|| {
    reqwest::Client::builder()
        .timeout(UPSTREAM_TIMEOUT)
        .build()
        .unwrap_or_else(|error| {
            log::error!("Could not build the bounded HTTP client, using the default: {error}");
            reqwest::Client::new()
        })
});

/// A read provider for `url` on the shared, timeout-bounded client. Builds no connection.
pub fn http_provider(url: &str) -> eyre::Result<DynProvider> {
    let url: reqwest::Url = url
        .parse()
        .map_err(|error| eyre::eyre!("the RPC URL is not a valid URL: {error}"))?;
    let transport = Http::with_client(HTTP.clone(), url);
    Ok(ProviderBuilder::new()
        .connect_client(RpcClient::new(transport, false))
        .erased())
}

/// The read provider for `HTTP_RPC_URL`, built once.
pub async fn provider() -> eyre::Result<&'static DynProvider> {
    static PROVIDER: OnceCell<DynProvider> = OnceCell::const_new();
    PROVIDER
        .get_or_try_init(|| async { http_provider(&CONFIG.http_rpc_url) })
        .await
}

/// The timestamp of the latest block.
pub async fn latest_timestamp(provider: &impl Provider) -> eyre::Result<u64> {
    provider
        .get_block_by_number(BlockNumberOrTag::Latest)
        .await?
        .map(|block| block.header.timestamp)
        .ok_or_else(|| eyre::eyre!("the RPC returned no latest block"))
}
