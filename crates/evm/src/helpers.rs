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
        Identity, Provider, ProviderBuilder, RootProvider, WalletProvider,
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
use alloy::{
    primitives::{Address, Bytes},
    sol_types::SolValue,
};
use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use e3_config::{RpcAuth, RPC};
use e3_crypto::Cipher;
use e3_data::Repository;
use e3_events::Proof;
use e3_utils::{retry_with_backoff, RetryError};
use std::{
    collections::HashMap,
    env,
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex as StdMutex, OnceLock},
};
use tokio::sync::{Mutex as AsyncMutex, OwnedMutexGuard};
use tracing::{info, warn};
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

type NonceLockKey = (u64, Address);

fn nonce_lock(chain_id: u64, signer: Address) -> Arc<AsyncMutex<()>> {
    static LOCKS: OnceLock<StdMutex<HashMap<NonceLockKey, Arc<AsyncMutex<()>>>>> = OnceLock::new();
    let locks = LOCKS.get_or_init(|| StdMutex::new(HashMap::new()));
    let mut locks = locks
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    Arc::clone(
        locks
            .entry((chain_id, signer))
            .or_insert_with(|| Arc::new(AsyncMutex::new(()))),
    )
}

/// Serialize nonce lookup and submission for one signer on one chain.
///
/// Independent writer actors share a provider signer and previously raced by reading the same
/// pending nonce. Writers release the guard after the RPC accepts the transaction, before waiting
/// for a receipt, so a slow confirmation cannot block unrelated submissions indefinitely.
pub(crate) async fn transaction_nonce_guard<P>(provider: &EthProvider<P>) -> OwnedMutexGuard<()>
where
    P: Provider + WalletProvider + Clone,
{
    let signer = provider.provider().default_signer_address();
    nonce_lock(provider.chain_id(), signer).lock_owned().await
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

        // alloy's pubsub service retries a dropped WebSocket 10 × 3 s and then answers every
        // request with "backend connection task has stopped" for the life of the provider.
        // That bound is deliberate here: it is the signal the chain reader's recreate path
        // needs to backfill the blocks that were mined during the outage. Every other actor
        // that holds a provider clone must therefore own a `ProviderFactory` and reconnect
        // itself — see `RandomnessProviderSolReader` and `CommitteeFinalizer`.
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
    let encrypted_key = repository.read().await?.context(
        "no operator wallet key is stored for this node. Add one with \
         `interfold wallet set --name <node> --config <config> --private-key <key>`",
    )?;

    let mut decrypted = cipher.decrypt_data(&encrypted_key).context(
        "the stored operator wallet key could not be decrypted. This usually means the node \
         password does not match the one used to store the key",
    )?;
    let private_key = Zeroizing::new(hex::encode(&decrypted));
    decrypted.zeroize();
    private_key.parse().map_err(Into::into)
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
                            warn!(
                                "{}: permanent error, not retrying: {}",
                                op_name, display_error
                            );
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

/// Result of a transaction whose chain effect can become unnecessary.
#[derive(Debug)]
pub enum TxOutcome {
    /// The transaction was mined and its receipt reports success.
    Mined(Box<TransactionReceipt>),
    /// The transaction failed, but the operation has no remaining chain work.
    AlreadySettled,
}

impl TxOutcome {
    /// The receipt of a mined transaction, or `None` when no chain work remains.
    pub fn receipt(&self) -> Option<&TransactionReceipt> {
        match self {
            TxOutcome::Mined(receipt) => Some(receipt),
            TxOutcome::AlreadySettled => None,
        }
    }
}

/// Send a transaction whose effect can become unnecessary before it is mined.
///
/// Preflights before the transaction cannot close the window between the
/// preflight and the block that includes the transaction. A transaction that
/// loses that race is mined with a failed receipt, and the receipt carries no
/// revert reason, so [`send_tx_with_retry`] classifies it as a hard failure.
///
/// `settled` runs after such a failure. It must report whether the operation
/// has any useful chain work left. If it does not, the failure is benign and the
/// operation returns [`TxOutcome::AlreadySettled`]. In all other cases the
/// original transaction error propagates.
pub async fn send_tx_idempotent<F, Fut, S, SFut>(
    operation_name: &str,
    retry_on_errors: &[&str],
    settled: S,
    tx_fn: F,
) -> Result<TxOutcome>
where
    F: Fn() -> Fut,
    Fut: Future<Output = Result<TransactionReceipt>>,
    S: FnOnce() -> SFut,
    SFut: Future<Output = Result<bool>>,
{
    let error = match send_tx_with_retry(operation_name, retry_on_errors, tx_fn).await {
        Ok(receipt) => return Ok(TxOutcome::Mined(Box::new(receipt))),
        Err(error) => error,
    };

    match settled().await {
        Ok(true) => {
            info!(
                "{}: no chain work remains; treating the failure as benign: {}",
                operation_name,
                decode_error_from_str(&format!("{error:#}"))
                    .unwrap_or_else(|| format!("{error:#}"))
            );
            Ok(TxOutcome::AlreadySettled)
        }
        Ok(false) => Err(error),
        Err(check_error) => Err(error.context(format!(
            "the on-chain state check after the failure also failed: {check_error:#}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_dyn_abi::DynSolType;
    use e3_events::{CircuitName, Proof};
    use e3_utils::ArcBytes;
    use std::sync::atomic::{AtomicUsize, Ordering};

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

    #[tokio::test]
    async fn nonce_lock_serializes_one_signer_per_chain() {
        let key = (9_876_543, Address::repeat_byte(0x42));
        let active = Arc::new(AtomicUsize::new(0));
        let maximum = Arc::new(AtomicUsize::new(0));
        let mut tasks = Vec::new();

        for _ in 0..32 {
            let active = Arc::clone(&active);
            let maximum = Arc::clone(&maximum);
            tasks.push(tokio::spawn(async move {
                let _guard = nonce_lock(key.0, key.1).lock_owned().await;
                let now = active.fetch_add(1, Ordering::SeqCst) + 1;
                maximum.fetch_max(now, Ordering::SeqCst);
                tokio::task::yield_now().await;
                active.fetch_sub(1, Ordering::SeqCst);
            }));
        }

        for task in tasks {
            task.await.expect("nonce-lock task must not panic");
        }
        assert_eq!(maximum.load(Ordering::SeqCst), 1);
    }

    /// A mined but reverted transaction. Its message carries no revert reason,
    /// which is what makes the state check after the failure necessary.
    fn reverted_transaction() -> anyhow::Error {
        anyhow::anyhow!("finalize committee transaction 0xabcd reverted on chain")
    }

    #[tokio::test]
    async fn idempotent_send_accepts_a_state_another_sender_produced() {
        let attempts = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&attempts);

        let outcome = send_tx_idempotent(
            "finalizeCommittee",
            &["SubmissionWindowNotClosed"],
            || async { Ok(true) },
            || {
                counter.fetch_add(1, Ordering::SeqCst);
                async { Err(reverted_transaction()) }
            },
        )
        .await
        .expect("a state that another sender produced is not a failure");

        assert!(matches!(outcome, TxOutcome::AlreadySettled));
        assert!(outcome.receipt().is_none());
        // The reason is not retryable, so the transaction runs one time.
        assert_eq!(attempts.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn idempotent_send_reports_a_failure_that_left_work_to_do() {
        let error = send_tx_idempotent(
            "finalizeCommittee",
            &["SubmissionWindowNotClosed"],
            || async { Ok(false) },
            || async { Err(reverted_transaction()) },
        )
        .await
        .expect_err("an incomplete operation must stay an error");

        assert!(format!("{error:#}").contains("reverted on chain"));
    }

    #[tokio::test]
    async fn idempotent_send_keeps_the_transaction_error_when_the_check_fails() {
        let error = send_tx_idempotent(
            "finalizeCommittee",
            &["SubmissionWindowNotClosed"],
            || async { Err(anyhow::anyhow!("RPC unavailable")) },
            || async { Err(reverted_transaction()) },
        )
        .await
        .expect_err("an unreadable state must not hide the transaction failure");

        let message = format!("{error:#}");
        assert!(message.contains("reverted on chain"), "got: {message}");
        assert!(message.contains("RPC unavailable"), "got: {message}");
    }
}
