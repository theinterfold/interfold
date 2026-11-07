// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use alloy::{
    network::EthereumWallet,
    providers::{
        fillers::{
            BlobGasFiller, ChainIdFiller, FillProvider, GasFiller, JoinFill, NonceFiller,
            SimpleNonceManager, WalletFiller,
        },
        Identity, Provider, ProviderBuilder, RootProvider,
    },
    rpc::client::ClientBuilder,
    signers::local::PrivateKeySigner,
    transports::{
        http::{
            reqwest::{
                header::{HeaderMap, HeaderValue, AUTHORIZATION},
                Client,
            },
            Http,
        },
        layers::RetryBackoffLayer,
        ws::{WebSocketConfig, WsConnect},
        Authorization,
    },
};
use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use e3_evm_config::{ChainConfig, RpcAuth, RPC};
use std::{future::Future, pin::Pin, sync::Arc, time::Duration};

pub trait AuthConversions {
    fn to_header_value(&self) -> Option<HeaderValue>;
    fn to_ws_auth(&self) -> Option<Authorization>;
}

impl AuthConversions for RpcAuth {
    fn to_header_value(&self) -> Option<HeaderValue> {
        match self {
            RpcAuth::None => None,
            RpcAuth::Basic { username, password } => {
                let credentials = STANDARD.encode(format!("{}:{}", username, password));
                HeaderValue::from_str(&format!("Basic {}", credentials)).ok()
            }
            RpcAuth::Bearer(token) => HeaderValue::from_str(&format!("Bearer {}", token)).ok(),
        }
    }

    fn to_ws_auth(&self) -> Option<Authorization> {
        match self {
            RpcAuth::None => None,
            RpcAuth::Basic { username, password } => Some(Authorization::basic(username, password)),
            RpcAuth::Bearer(token) => Some(Authorization::bearer(token)),
        }
    }
}

#[derive(Clone)]
pub struct EthProvider<P> {
    provider: Arc<P>,
    chain_id: u64,
}

impl<P: Provider + Clone> EthProvider<P> {
    pub async fn new(provider: P) -> Result<Self> {
        let chain_id = provider.get_chain_id().await?;
        Ok(Self {
            provider: Arc::new(provider),
            chain_id,
        })
    }

    pub fn provider(&self) -> &P {
        &self.provider
    }

    pub fn chain_id(&self) -> u64 {
        self.chain_id
    }
}

pub type ProviderFactory<P> =
    Arc<dyn Fn() -> Pin<Box<dyn Future<Output = Result<EthProvider<P>>> + Send>> + Send + Sync>;

/// Attempts for a request the provider refused with a rate limit.
///
/// A public endpoint refuses a burst but accepts the same request shortly after, so the node waits
/// rather than fails. Before this retry existed, one HTTP 429 during the first sync ended the
/// process: `eth_chainId` runs before the actor system starts, and its error reaches the top-level
/// exit path.
const RPC_RATE_LIMIT_MAX_RETRIES: u32 = 8;

/// First wait after a refused request, in milliseconds.
///
/// A provider that sends a backoff hint in the JSON-RPC error body overrides this: the transport
/// prefers the interval the provider asked for. It does not read an HTTP `Retry-After` header.
/// Without a hint the wait is this constant on every attempt, so the value must be large enough
/// for a refusal to clear on its own.
const RPC_RATE_LIMIT_INITIAL_BACKOFF_MS: u64 = 500;

/// Compute units per second the retry path assumes for pacing.
///
/// This value only spaces out requests that are already waiting after a refusal; it does not
/// throttle requests that succeed. The value matches the free tier of common hosted providers, so
/// the node recovers from a burst instead of repeating it.
const RPC_COMPUTE_UNITS_PER_SECOND: u64 = 330;

/// Retry transport layer for rate-limited providers.
///
/// The policy retries HTTP 429 and 503, and the JSON-RPC errors that report the same condition.
/// Other errors stay unretried here, because the layers above own their own recovery: a rejected
/// block range is answered by a narrower window, and a dead transport by provider recreation.
fn rate_limit_retry_layer() -> RetryBackoffLayer {
    RetryBackoffLayer::new(
        RPC_RATE_LIMIT_MAX_RETRIES,
        RPC_RATE_LIMIT_INITIAL_BACKOFF_MS,
        RPC_COMPUTE_UNITS_PER_SECOND,
    )
}

/// Poll interval of a provider built without a chain configuration. Alloy's default for a remote
/// endpoint.
const DEFAULT_RPC_POLL_INTERVAL: Duration = Duration::from_secs(7);

#[derive(Clone)]
pub struct ProviderConfig {
    rpc: RPC,
    auth: RpcAuth,
    /// Interval between the polls of an HTTP provider for a receipt or a new block. Set
    /// explicitly on every client: Alloy would otherwise poll a loopback URL every 250 ms, and a
    /// loopback URL can be a proxy to a live chain.
    poll_interval: Duration,
}

pub type ConcreteReadProvider = FillProvider<
    JoinFill<
        Identity,
        JoinFill<GasFiller, JoinFill<BlobGasFiller, JoinFill<NonceFiller, ChainIdFiller>>>,
    >,
    RootProvider,
>;

pub type ConcreteWriteProvider = FillProvider<
    JoinFill<
        JoinFill<
            JoinFill<
                alloy::providers::Identity,
                JoinFill<GasFiller, JoinFill<BlobGasFiller, JoinFill<NonceFiller, ChainIdFiller>>>,
            >,
            NonceFiller<SimpleNonceManager>,
        >,
        WalletFiller<EthereumWallet>,
    >,
    RootProvider,
>;

impl ProviderConfig {
    pub fn new(rpc: RPC, auth: RpcAuth) -> Self {
        Self {
            rpc,
            auth,
            poll_interval: DEFAULT_RPC_POLL_INTERVAL,
        }
    }

    /// The provider configuration of a configured chain: its URL, credentials and poll interval.
    pub fn for_chain(chain: &ChainConfig) -> Result<Self> {
        Ok(Self::new(chain.rpc_url()?, chain.rpc_auth.clone())
            .with_poll_interval(chain.rpc_poll_interval()?))
    }

    pub fn with_poll_interval(mut self, poll_interval: Duration) -> Self {
        self.poll_interval = poll_interval;
        self
    }

    pub async fn create_readonly_provider(&self) -> Result<EthProvider<ConcreteReadProvider>> {
        let client = if self.rpc.is_websocket() {
            ClientBuilder::default()
                .layer(rate_limit_retry_layer())
                .ws(self.create_ws_connect()?)
                .await
                .context("Failed to connect to WebSocket RPC. Check if the node is running and URL is correct.")?
                .with_poll_interval(self.poll_interval)
        } else {
            self.create_http_client()?
        };

        EthProvider::new(ProviderBuilder::new().connect_client(client)).await
    }

    pub async fn create_signer_provider(
        &self,
        signer: &PrivateKeySigner,
    ) -> Result<EthProvider<ConcreteWriteProvider>> {
        let wallet = EthereumWallet::from(signer.clone());

        let provider = ProviderBuilder::new()
            .with_simple_nonce_management()
            .wallet(wallet)
            .connect_client(self.create_http_client()?);

        EthProvider::new(provider).await
    }

    fn create_ws_connect(&self) -> Result<WsConnect> {
        let config = WebSocketConfig::default()
            .max_frame_size(Some(32 * 1024 * 1024))
            .max_message_size(Some(32 * 1024 * 1024));

        let mut ws_connect = WsConnect::new(self.rpc.as_ws_url()?).with_config(config);

        if let Some(auth) = self.auth.to_ws_auth() {
            ws_connect = ws_connect.with_auth(auth);
        }

        Ok(ws_connect)
    }

    pub fn into_read_provider_factory(self) -> ProviderFactory<ConcreteReadProvider> {
        Arc::new(move || {
            let config = self.clone();
            Box::pin(async move { config.create_readonly_provider().await })
        })
    }

    fn create_http_client(&self) -> Result<alloy::rpc::client::RpcClient> {
        let mut headers = HeaderMap::new();
        if let Some(auth_header) = self.auth.to_header_value() {
            headers.insert(AUTHORIZATION, auth_header);
        }

        let client = Client::builder()
            .default_headers(headers)
            .build()
            .context("Failed to create HTTP client")?;

        let url = self.rpc.as_http_url()?;
        let http = Http::with_client(client, url.parse()?);
        // The local flag only selects Alloy's default poll interval, and the explicit interval
        // replaces that default.
        Ok(ClientBuilder::default()
            .layer(rate_limit_retry_layer())
            .transport(http, self.rpc.is_local())
            .with_poll_interval(self.poll_interval))
    }
}

/// Read the latest block timestamp from an already resolved chain provider.
pub async fn get_current_timestamp_from_provider<P>(provider: EthProvider<P>) -> Result<u64>
where
    P: Provider + Clone,
{
    let block = provider
        .provider()
        .get_block_by_number(alloy::eips::BlockNumberOrTag::Latest)
        .await
        .context("Failed to get latest block")?
        .ok_or_else(|| anyhow::anyhow!("Latest block not found"))?;

    Ok(block.header.timestamp)
}

#[cfg(test)]
mod tests {
    use super::*;
    use e3_evm_config::{ChainConfig, Contract, ContractAddresses};

    fn loopback_chain(rpc_poll_interval_ms: Option<u64>) -> ChainConfig {
        let contract = || Contract::Full {
            address: "0x0000000000000000000000000000000000000000".to_string(),
            deploy_block: Some(1),
        };
        ChainConfig {
            enabled: Some(true),
            name: "test".to_string(),
            rpc_url: "http://127.0.0.1:8545".to_string(),
            rpc_auth: RpcAuth::default(),
            contracts: ContractAddresses {
                interfold: contract(),
                ciphernode_registry: contract(),
                bonding_registry: contract(),
                e3_program: None,
                fee_token: None,
                slashing_manager: None,
                dkg_fold_attestation_verifier: None,
                faucet: None,
            },
            finalization_ms: None,
            chain_id: Some(31337),
            ingestion_confirmations: None,
            rpc_poll_interval_ms,
            rpc_log_range_blocks: None,
            data_availability: None,
        }
    }

    #[test]
    fn a_loopback_http_client_polls_at_the_public_interval_unless_configured() {
        // Alloy would poll a loopback transport every 250 ms. A loopback URL can be a proxy to a
        // live chain, so the interval comes from the chain configuration instead.
        let client = ProviderConfig::for_chain(&loopback_chain(None))
            .unwrap()
            .create_http_client()
            .unwrap();
        assert_eq!(client.poll_interval(), Duration::from_secs(7));

        let client = ProviderConfig::for_chain(&loopback_chain(Some(250)))
            .unwrap()
            .create_http_client()
            .unwrap();
        assert_eq!(client.poll_interval(), Duration::from_millis(250));
    }

    #[test]
    fn test_rpc_conversions() -> Result<()> {
        // HTTP/HTTPS
        let http = RPC::from_url("http://localhost:8545/")?;
        assert_eq!(http.as_http_url()?, "http://localhost:8545/");
        assert_eq!(http.as_ws_url()?, "ws://localhost:8545/");
        assert!(!http.is_secure());
        assert!(!http.is_websocket());

        let https = RPC::from_url("https://example.com/")?;
        assert_eq!(https.as_http_url()?, "https://example.com/");
        assert_eq!(https.as_ws_url()?, "wss://example.com/");
        assert!(https.is_secure());
        assert!(!https.is_websocket());

        // WS/WSS
        let ws = RPC::from_url("ws://localhost:8545/")?;
        assert_eq!(ws.as_http_url()?, "http://localhost:8545/");
        assert_eq!(ws.as_ws_url()?, "ws://localhost:8545/");
        assert!(!ws.is_secure());
        assert!(ws.is_websocket());

        let wss = RPC::from_url("wss://example.com/")?;
        assert_eq!(wss.as_http_url()?, "https://example.com/");
        assert_eq!(wss.as_ws_url()?, "wss://example.com/");
        assert!(wss.is_secure());
        assert!(wss.is_websocket());

        Ok(())
    }
}
