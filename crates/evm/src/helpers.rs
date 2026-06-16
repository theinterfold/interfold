// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::error_decoder::decode_error_from_str;
use alloy::{
    network::EthereumWallet,
    providers::{
        fillers::{
            BlobGasFiller, ChainIdFiller, FillProvider, GasFiller, JoinFill, NonceFiller,
            SimpleNonceManager, WalletFiller,
        },
        Identity, Provider, ProviderBuilder, RootProvider,
    },
    rpc::types::TransactionReceipt,
    signers::local::PrivateKeySigner,
    transports::{
        http::{
            reqwest::{
                header::{HeaderMap, HeaderValue, AUTHORIZATION},
                Client,
            },
            Http,
        },
        ws::{WebSocketConfig, WsConnect},
        Authorization,
    },
};
use alloy::{primitives::Bytes, sol_types::SolValue};
use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use e3_config::{RpcAuth, RPC};
use e3_crypto::Cipher;
use e3_data::Repository;
use e3_events::Proof;
use e3_utils::{retry_with_backoff, RetryError};
use std::{env, future::Future, pin::Pin, sync::Arc};
use tracing::info;
use zeroize::{Zeroize, Zeroizing};

/// ABI-encodes a ZK proof for EVM verifiers (C5 pk, C7 decryption, etc.).
/// Format: abi.encode(rawProof, publicInputs). Public inputs as bytes32[].
pub fn encode_zk_proof(proof: &Proof) -> Result<Bytes> {
    let signals: &[u8] = &proof.public_signals;
    if signals.is_empty() {
        anyhow::bail!("public_signals must be non-empty");
    }
    if !signals.len().is_multiple_of(32) {
        anyhow::bail!(
            "public_signals length must be a multiple of 32, got {}",
            signals.len()
        );
    }
    let mut inputs = Vec::with_capacity(signals.len() / 32);
    for chunk in signals.chunks_exact(32) {
        let mut arr = [0u8; 32];
        arr.copy_from_slice(chunk);
        inputs.push(arr);
    }

    Ok(Bytes::from(
        (&proof.data.to_vec(), inputs).abi_encode_params(),
    ))
}

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

#[derive(Clone)]
pub struct ProviderConfig {
    rpc: RPC,
    auth: RpcAuth,
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
        Self { rpc, auth }
    }

    pub async fn create_readonly_provider(&self) -> Result<EthProvider<ConcreteReadProvider>> {
        let provider = if self.rpc.is_websocket() {
            ProviderBuilder::new()
                .connect_ws(self.create_ws_connect()?)
                .await
                .context("Failed to connect to WebSocket RPC. Check if the node is running and URL is correct.")?
        } else {
            ProviderBuilder::new().connect_client(self.create_http_client()?)
        };

        EthProvider::new(provider).await
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

        let http = Http::with_client(client, self.rpc.as_http_url()?.parse()?);
        Ok(alloy::rpc::client::RpcClient::new(http, false))
    }
}

pub fn load_signer_from_env(var: &str) -> Result<PrivateKeySigner> {
    let private_key = env::var(var)?;
    env::remove_var(var);
    private_key.parse().map_err(Into::into)
}

pub async fn load_signer_from_repository(
    repository: Repository<Vec<u8>>,
    cipher: &Cipher,
) -> Result<PrivateKeySigner> {
    let encrypted_key = repository
        .read()
        .await?
        .context("No private key found in repository")?;

    let mut decrypted = cipher.decrypt_data(&encrypted_key)?;
    let private_key = Zeroizing::new(hex::encode(&decrypted));
    decrypted.zeroize();
    private_key.parse().map_err(Into::into)
}

pub async fn get_current_timestamp() -> Result<u64> {
    let config = e3_config::load_config("_default", None, None)?;
    let chain = config
        .chains()
        .first()
        .ok_or_else(|| anyhow::anyhow!("No chains configured"))?;

    let rpc_url = chain.rpc_url()?;
    let provider = ProviderConfig::new(rpc_url, chain.rpc_auth.clone())
        .create_readonly_provider()
        .await?;

    let block = provider
        .provider()
        .get_block_by_number(alloy::eips::BlockNumberOrTag::Latest)
        .await
        .context("Failed to get latest block")?
        .ok_or_else(|| anyhow::anyhow!("Latest block not found"))?;

    Ok(block.header.timestamp)
}

const TX_RETRY_MAX_ATTEMPTS: u32 = 3;
const TX_RETRY_INITIAL_DELAY_MS: u64 = 2000;

fn should_retry_error(error: &str, decoded_error: Option<&str>, retry_on_errors: &[&str]) -> bool {
    if retry_on_errors.is_empty() {
        return true;
    }
    retry_on_errors.iter().any(|code| {
        error.contains(code) || decoded_error.is_some_and(|decoded| decoded.contains(code))
    })
}

pub async fn send_tx_with_retry<F, Fut>(
    operation_name: &str,
    retry_on_errors: &[&str],
    tx_fn: F,
) -> Result<TransactionReceipt>
where
    F: Fn() -> Fut,
    Fut: Future<Output = Result<TransactionReceipt>>,
{
    let op_name = operation_name.to_string();
    let retry_codes: Vec<String> = retry_on_errors.iter().map(|s| s.to_string()).collect();

    retry_with_backoff(
        || {
            let op_name = op_name.clone();
            let retry_codes = retry_codes.clone();
            let fut = tx_fn();
            async move {
                match fut.await {
                    Ok(receipt) => Ok(receipt),
                    Err(e) => {
                        let error_str = format!("{e:#}");
                        let decoded = decode_error_from_str(&error_str);
                        let display_error = decoded.as_deref().unwrap_or(&error_str);
                        let retry_refs: Vec<&str> =
                            retry_codes.iter().map(|s| s.as_str()).collect();
                        if should_retry_error(&error_str, decoded.as_deref(), &retry_refs) {
                            info!("{}: error, will retry: {}", op_name, display_error);
                            Err(RetryError::Retry(e))
                        } else {
                            info!("{}: error: {}", op_name, display_error);
                            Err(RetryError::Failure(e))
                        }
                    }
                }
            }
        },
        TX_RETRY_MAX_ATTEMPTS,
        TX_RETRY_INITIAL_DELAY_MS,
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_dyn_abi::DynSolType;
    use e3_events::{CircuitName, Proof};
    use e3_utils::ArcBytes;

    /// Verifies encode_zk_proof produces ABI: abi.decode(proof, (bytes, bytes32[]))
    #[test]
    fn test_encode_zk_proof_abi_format() {
        let raw_proof = vec![1u8, 2, 3, 4, 5];
        let public_signals: Vec<u8> = (0..64).map(|i| i as u8).collect(); // 2 × 32-byte fields
        let proof = Proof::new(
            CircuitName::PkAggregation,
            ArcBytes::from_bytes(&raw_proof),
            ArcBytes::from_bytes(&public_signals),
        );

        let encoded = encode_zk_proof(&proof).expect("encoding should succeed");

        let tuple_type = DynSolType::Tuple(vec![
            DynSolType::Bytes,
            DynSolType::Array(Box::new(DynSolType::FixedBytes(32))),
        ]);
        // Pair encode_zk_proof's abi_encode_params with abi_decode_params (not abi_decode).
        tuple_type.abi_decode_params(&encoded).expect(
            "encoded proof should decode as (bytes, bytes32[]) - matches contract abi.decode",
        );
    }

    #[test]
    fn test_encode_zk_proof_rejects_invalid() {
        let proof = Proof::new(
            CircuitName::PkAggregation,
            ArcBytes::from_bytes(&[1, 2, 3]),
            ArcBytes::from_bytes(&[0u8; 31]), // not divisible by 32
        );
        assert!(encode_zk_proof(&proof).is_err());

        let proof_empty = Proof::new(
            CircuitName::PkAggregation,
            ArcBytes::from_bytes(&[1, 2, 3]),
            ArcBytes::from_bytes(&[]),
        );
        assert!(encode_zk_proof(&proof_empty).is_err());
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
