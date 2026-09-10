// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use super::{
    models::{CiphertextOutputReference, E3},
    DataStore,
};
use crate::callback_queue::CallbackQueue;
use crate::E3Repository;
use alloy::consensus::BlockHeader;
use alloy::hex;
use alloy::primitives::{keccak256, Address, Uint};
use alloy::providers::Provider;
use alloy::sol_types::{SolEvent, SolValue};
use async_trait::async_trait;
use e3_bfv_client::validate_pk_commitment;
use e3_evm_helpers::{
    block_listener::BlockListener,
    contracts::{
        InterfoldContract, InterfoldContractFactory, InterfoldRead, ProviderType, ReadOnly,
        ReadWrite,
    },
    event_listener::{EventListener, LiveProgress, NOT_PROCESSING},
    events::{
        CiphertextOutputPublished, CiphertextOutputReferencePublished,
        CommitteePublicKeyChunkPublished, CommitteePublished, PlaintextOutputPublished,
    },
};
use e3_fhe_params::{decode_bfv_params, encode_bfv_params, BfvParamSet, BfvPreset};
use eyre::eyre;
use eyre::Result;
use serde::{de::DeserializeOwned, Serialize};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::{collections::HashMap, sync::Arc};
use std::{future::Future, time::Duration};
use thiserror::Error;
use tokio::{sync::RwLock, time::sleep};
use tracing::{error, info, warn};

type E3Id = String;

const PUBLIC_KEY_CHUNK_BYTES: usize = 90 * 1024;
const MAX_PUBLIC_KEY_BYTES: usize = 512 * 1024;

#[derive(Clone, Debug, Serialize, serde::Deserialize)]
struct PublicKeyChunkAssembly {
    nodes: Vec<Address>,
    pk_commitment: [u8; 32],
    total_length: u32,
    chunk_count: u16,
    chunks: Vec<Option<Vec<u8>>>,
    invalid: bool,
    stored: bool,
}

impl PublicKeyChunkAssembly {
    fn event_shape_is_valid(event: &CommitteePublicKeyChunkPublished) -> bool {
        let total_length = event.totalLength as usize;
        if total_length == 0 || total_length > MAX_PUBLIC_KEY_BYTES {
            return false;
        }
        let expected_count = total_length.div_ceil(PUBLIC_KEY_CHUNK_BYTES);
        if expected_count != usize::from(event.chunkCount)
            || usize::from(event.chunkIndex) >= expected_count
        {
            return false;
        }
        let offset = usize::from(event.chunkIndex) * PUBLIC_KEY_CHUNK_BYTES;
        let expected_length = (total_length - offset).min(PUBLIC_KEY_CHUNK_BYTES);
        event.chunk.len() == expected_length
    }

    fn from_event(event: &CommitteePublicKeyChunkPublished) -> Self {
        Self {
            nodes: event.nodes.clone(),
            pk_commitment: event.pkCommitment.0,
            total_length: event.totalLength,
            chunk_count: event.chunkCount,
            chunks: vec![None; usize::from(event.chunkCount)],
            invalid: false,
            stored: false,
        }
    }

    fn accepts(&self, event: &CommitteePublicKeyChunkPublished) -> bool {
        self.nodes == event.nodes
            && self.pk_commitment == event.pkCommitment.0
            && self.total_length == event.totalLength
            && self.chunk_count == event.chunkCount
    }

    fn insert(&mut self, event: &CommitteePublicKeyChunkPublished) {
        if self.invalid || self.stored || !self.accepts(event) {
            self.invalid |= !self.accepts(event);
            return;
        }
        let expected_count = (self.total_length as usize).div_ceil(PUBLIC_KEY_CHUNK_BYTES);
        let offset = usize::from(event.chunkIndex) * PUBLIC_KEY_CHUNK_BYTES;
        let expected_length = (self.total_length as usize)
            .saturating_sub(offset)
            .min(PUBLIC_KEY_CHUNK_BYTES);
        if expected_count != usize::from(self.chunk_count) || event.chunk.len() != expected_length {
            self.invalid = true;
            return;
        }
        let Some(slot) = self.chunks.get_mut(usize::from(event.chunkIndex)) else {
            self.invalid = true;
            return;
        };
        if let Some(existing) = slot {
            if existing.as_slice() != event.chunk.as_ref() {
                self.invalid = true;
            }
        } else {
            *slot = Some(event.chunk.to_vec());
        }
    }

    fn bytes(&self) -> Option<Vec<u8>> {
        if self.invalid || self.stored {
            return None;
        }
        let mut bytes = Vec::with_capacity(self.total_length as usize);
        for chunk in &self.chunks {
            bytes.extend_from_slice(chunk.as_ref()?);
        }
        (bytes.len() == self.total_length as usize).then_some(bytes)
    }
}

#[derive(Error, Debug)]
pub enum IndexerError {
    #[error("E3 not found: {0}")]
    E3NotFound(E3Id),
    #[error("Object not serializable: {0}")]
    Serialization(E3Id),
}

pub struct InMemoryStore {
    data: HashMap<String, Vec<u8>>,
}

impl Default for InMemoryStore {
    fn default() -> Self {
        Self::new()
    }
}

impl InMemoryStore {
    pub fn new() -> Self {
        Self {
            data: HashMap::new(),
        }
    }
}

#[async_trait]
impl DataStore for InMemoryStore {
    type Error = eyre::Error;

    async fn insert<T: Serialize + Send + Sync>(
        &mut self,
        key: &str,
        value: &T,
    ) -> Result<(), Self::Error> {
        self.data
            .insert(key.to_string(), bincode::serialize(value)?);
        Ok(())
    }

    async fn get<T: DeserializeOwned + Send + Sync>(
        &self,
        key: &str,
    ) -> Result<Option<T>, Self::Error> {
        Ok(self
            .data
            .get(key)
            .map(|bytes| bincode::deserialize(bytes))
            .transpose()?)
    }

    async fn modify<T, F>(&mut self, key: &str, mut f: F) -> Result<Option<T>, Self::Error>
    where
        T: Serialize + DeserializeOwned + Send + Sync,
        F: FnMut(Option<T>) -> Option<T> + Send,
    {
        let current = self
            .data
            .get(key)
            .and_then(|bytes| bincode::deserialize(bytes).ok());

        match f(current) {
            Some(new_value) => {
                self.data
                    .insert(key.to_string(), bincode::serialize(&new_value)?);
                Ok(Some(new_value))
            }
            None => {
                self.data.remove(key);
                Ok(None)
            }
        }
    }
}

pub struct SharedStore<S> {
    inner: Arc<RwLock<S>>,
}

impl<S: DataStore> Clone for SharedStore<S> {
    fn clone(&self) -> Self {
        SharedStore {
            inner: Arc::clone(&self.inner),
        }
    }
}

impl<S: DataStore> SharedStore<S> {
    pub fn new(inner: Arc<RwLock<S>>) -> SharedStore<S> {
        Self { inner }
    }
}

#[async_trait]
impl<S: DataStore> DataStore for SharedStore<S> {
    type Error = S::Error;
    async fn insert<T: Serialize + Send + Sync>(
        &mut self,
        key: &str,
        value: &T,
    ) -> Result<(), Self::Error> {
        self.inner.write().await.insert(key, value).await
    }

    async fn get<T: DeserializeOwned + Send + Sync>(
        &self,
        key: &str,
    ) -> Result<Option<T>, Self::Error> {
        self.inner.read().await.get(key).await
    }

    async fn modify<T, F>(&mut self, key: &str, f: F) -> Result<Option<T>, Self::Error>
    where
        T: Serialize + DeserializeOwned + Send + Sync,
        F: FnMut(Option<T>) -> Option<T> + Send,
    {
        self.inner.write().await.modify(key, f).await
    }
}

#[derive(Clone)]
pub struct InterfoldIndexer<S: DataStore, R: ProviderType> {
    ctx: Arc<IndexerContext<S, R>>,
}

impl<S: DataStore, R: ProviderType> Drop for InterfoldIndexer<S, R> {
    fn drop(&mut self) {
        info!("InterfoldIndexer is DROPPED");
    }
}

/// Store key holding the last block whose logs have been fully applied.
///
/// Persisted so a restart resumes where it left off. Its ABSENCE is meaningful: it is what
/// distinguishes a fresh database (start at the head, preserving the historical behaviour of
/// this indexer) from a resumable one.
pub const INDEXER_CURSOR_KEY: &str = "_indexer:cursor";

/// Sentinel for "no backfill start configured" — see [`InterfoldIndexer::configure_backfill`].
const BACKFILL_UNSET: u64 = u64::MAX;

/// Default `eth_getLogs` window. Hosted providers cap the range, and 2k blocks sits under every
/// cap we have met.
const DEFAULT_BACKFILL_CHUNK: u64 = 2_000;

pub struct IndexerContext<S: DataStore, R: ProviderType> {
    store: SharedStore<S>,
    event_listener: EventListener,
    block_listener: BlockListener,
    contract: InterfoldContract<R>,
    contract_address: String,
    chain_id: u64,
    callbacks: CallbackQueue,
    /// Block to backfill from when there is no cursor, or [`BACKFILL_UNSET`] to begin at the head.
    backfill_start: AtomicU64,
    backfill_chunk: AtomicU64,
    /// Whether [`InterfoldIndexer::configure_backfill`] was ever called.
    ///
    /// Gates BOTH the catch-up and the cursor writes. Without this the cursor was written on
    /// every block for every consumer, so from the second boot onward every indexer replayed its
    /// downtime — including consumers that had opted into nothing and whose handlers are not pure
    /// (replaying `E3Requested` re-submits `setMerkleRoot` and resets the stored round).
    ///
    /// Separately reference-counted, along with the two below, so the block handler can observe
    /// them without capturing the context itself: the context owns the block listener, so a
    /// handler holding an `Arc<IndexerContext>` is a cycle and the indexer is never dropped.
    backfill_enabled: Arc<AtomicBool>,
    /// Highest block the cursor has been advanced to in this process.
    ///
    /// The block handlers are spawned rather than awaited, so two headers arriving together race
    /// on the store write and a blind insert could move the cursor BACKWARDS — which on the next
    /// restart replays blocks already applied. `fetch_max` makes the claim monotonic.
    cursor_high: Arc<AtomicU64>,
    /// Whether the catch-up has completed at least once since the last (re)connect.
    ///
    /// The cursor is a claim that everything below it has been applied; it must not advance while
    /// there is a known unreplayed gap beneath it, or the gap is sealed permanently.
    caught_up: Arc<AtomicBool>,
    /// How far the live subscription has actually applied. See [`LiveProgress`].
    ///
    /// The header stream and the log stream are independent, so a header alone says nothing about
    /// whether that block's logs have been written. This is what turns "the chain reached N" into
    /// "everything up to N has been applied", and without it a slow or failed raw handler let the
    /// cursor claim a block whose logs were still in flight.
    live_progress: Arc<LiveProgress>,
}

impl<S: DataStore, R: ProviderType> IndexerContext<S, R> {
    pub fn store(&self) -> SharedStore<S> {
        self.store.clone()
    }

    pub fn event_listener(&self) -> EventListener {
        self.event_listener.clone()
    }

    pub fn block_listener(&self) -> BlockListener {
        self.block_listener.clone()
    }

    pub fn contract(&self) -> InterfoldContract<R> {
        self.contract.clone()
    }
    pub fn interfold_address(&self) -> String {
        self.contract_address.clone()
    }

    pub fn chain_id(&self) -> u64 {
        self.chain_id
    }

    /// Schedule a callback to execute as or after a block with the given timestamp is processed.
    ///
    /// Useful for handling deadlines or expirations. The callback receives the scheduled
    /// timestamp and a reference to the indexer context.
    pub fn do_later<F, Fut>(self: &Arc<Self>, timestamp: u64, callback: F)
    where
        F: Fn(u64, Arc<Self>) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<()>> + Send + 'static,
    {
        let callback = Arc::new(callback);
        let ctx = Arc::clone(self);
        self.callbacks.push(timestamp, move || {
            info!("Running callback: time={}", timestamp);
            let callback = Arc::clone(&callback);
            let ctx = Arc::clone(&ctx);
            async move {
                callback(timestamp, ctx).await?;
                Ok(())
            }
        })
    }
}

impl<R: ProviderType> InterfoldIndexer<InMemoryStore, R> {
    pub async fn new_with_in_mem_store(
        event_listener: EventListener,
        contract: InterfoldContract<R>,
    ) -> Result<InterfoldIndexer<InMemoryStore, R>> {
        let store = InMemoryStore::new();

        InterfoldIndexer::new(event_listener, contract, store).await
    }
}

impl InterfoldIndexer<InMemoryStore, ReadOnly> {
    /// Creates an `InterfoldIndexer` with an in-memory store.
    ///
    /// Note: `addresses[0]` must be the interfold contract address.
    pub async fn from_endpoint_address_in_mem(rpc_url: &str, addresses: &[&str]) -> Result<Self> {
        let event_listener = EventListener::create_contract_listener(rpc_url, addresses).await?;
        let contract = InterfoldContractFactory::create_read(rpc_url, addresses[0]).await?;
        InterfoldIndexer::<InMemoryStore, ReadOnly>::new_with_in_mem_store(event_listener, contract)
            .await
    }

    /// Creates an `InterfoldIndexer` with a provided in-memory store.
    ///
    /// Note: `addresses[0]` must be the interfold contract address.
    pub async fn from_endpoint_address(
        rpc_url: &str,
        addresses: &[&str],
        store: InMemoryStore,
    ) -> Result<Self> {
        let event_listener = EventListener::create_contract_listener(rpc_url, addresses).await?;
        let contract = InterfoldContractFactory::create_read(rpc_url, addresses[0]).await?;
        InterfoldIndexer::new(event_listener, contract, store).await
    }
}

impl<S: DataStore> InterfoldIndexer<S, ReadWrite> {
    /// Creates a new InterfoldIndexer with a writeable contract.
    pub async fn new_with_write_contract(
        rpc_url: &str,
        addresses: &[&str], // First address must be contract_address
        store: S,
        private_key: &str,
    ) -> Result<Self> {
        let Some(contract_address) = addresses.first() else {
            return Err(eyre::eyre!("No addresses provided"));
        };
        let event_listener = EventListener::create_contract_listener(rpc_url, addresses).await?;
        InterfoldIndexer::new(
            event_listener,
            InterfoldContractFactory::create_write(rpc_url, contract_address, private_key).await?,
            store,
        )
        .await
    }
}

async fn store_committee_public_key<S: DataStore, R: ProviderType>(
    event: CommitteePublished,
    ctx: Arc<IndexerContext<S, R>>,
    ignore_invalid_candidate: bool,
) -> Result<bool> {
    let contract = ctx.contract();
    let db = ctx.store();
    let interfold_address = ctx.interfold_address();
    let e3_id = event.e3Id.to_string();

    info!(
        "CommitteePublished: id={}, public_key_len={}, proof_len={}",
        event.e3Id,
        event.publicKey.len(),
        event.proof.len()
    );

    let e3 = contract.get_e3(event.e3Id).await?;
    let params_preset = BfvPreset::from_on_chain_param_set(e3.paramSet).ok_or_else(|| {
        eyre!(
            "unsupported BFV parameter set {} for E3 {e3_id}",
            e3.paramSet
        )
    })?;
    let e3_params = encode_bfv_params(&BfvParamSet::from(params_preset).build_arc());
    let crypto_config_id = keccak256(
        (
            keccak256(b"fhe.rs:BFV"),
            keccak256(&e3_params),
            keccak256(b"interfold-bfv-v1"),
        )
            .abi_encode(),
    );
    let request_crypto_config_id = contract.get_e3_crypto_config_id(event.e3Id).await?;
    if request_crypto_config_id != crypto_config_id {
        return Err(eyre!(
            "local circuit configuration does not match request-time config for E3 {e3_id}"
        ));
    }
    if e3.encryptionSchemeId == keccak256("fhe.rs:BFV") {
        let decoded_params = decode_bfv_params(&e3_params)
            .map_err(|error| eyre!("invalid BFV parameters for E3 {e3_id}: {error}"))?;
        if let Err(error) = validate_pk_commitment(
            &event.publicKey,
            event.pkCommitment.0,
            decoded_params.degree(),
            decoded_params.plaintext(),
            decoded_params.moduli().to_vec(),
        ) {
            if ignore_invalid_candidate {
                warn!("Ignoring unbound committee public-key candidate for E3 {e3_id}: {error}");
                return Ok(false);
            }
            return Err(eyre!(
                "rejecting unbound CommitteePublished public key for E3 {e3_id}: {error}"
            ));
        }
    }
    let seed = e3.seed.to_be_bytes();
    let request_block = u64_try_from(e3.requestBlock)?;
    let input_window = [
        u64_try_from(e3.inputWindow[0])?,
        u64_try_from(e3.inputWindow[1])?,
    ];

    let e3_obj = E3 {
        chain_id: ctx.chain_id(),
        ciphertext_inputs: vec![],
        ciphertext_output: vec![],
        ciphertext_output_reference: None,
        ciphertext_commitment: vec![],
        committee_public_key: event.publicKey.to_vec(),
        committee_public_key_hash: event.pkCommitment.to_vec(),
        custom_params: e3.customParams.to_vec(),
        e3_params: e3_params.to_vec(),
        interfold_address,
        encryption_scheme_id: e3.encryptionSchemeId.to_vec(),
        crypto_config_id: crypto_config_id.to_vec(),
        id: e3_id.clone(),
        plaintext_output: vec![],
        request_block,
        seed,
        input_window,
        committee_size: e3.committeeSize,
        requester: e3.requester.to_string(),
    };

    let mut repo = E3Repository::new(db, &e3_id);
    if repo.set_e3_if_absent(e3_obj).await? {
        info!("E3 {} created and stored", e3_id);
    } else {
        info!("E3 {} already has a verified committee key", e3_id);
    }
    Ok(true)
}

async fn mark_public_key_assembly<S: DataStore>(
    store: &mut SharedStore<S>,
    key: &str,
    stored: bool,
) -> Result<()> {
    store
        .modify(key, move |current: Option<PublicKeyChunkAssembly>| {
            current.map(|mut assembly| {
                assembly.stored = stored;
                assembly.invalid = !stored;
                // The verified E3 record now owns the complete key. Keep only the small
                // completion marker so duplicate or replayed chunks remain idempotent.
                assembly.chunks.clear();
                assembly
            })
        })
        .await
        .map_err(|error| eyre!("updating public-key chunk assembly failed: {error}"))?;
    Ok(())
}

impl<S: DataStore, R: ProviderType> InterfoldIndexer<S, R> {
    pub async fn new(
        mut event_listener: EventListener,
        contract: InterfoldContract<R>,
        store: S,
    ) -> Result<Self> {
        let chain_id = contract.provider.get_chain_id().await?;
        let contract_address = contract.address().to_string();
        let block_listener = BlockListener::new(event_listener.provider());

        // The listener reports what it has actually applied; the block handler below reads it
        // before claiming anything, so a raw handler that is slow or failing holds the cursor back
        // rather than being raced by the header stream.
        let live_progress = Arc::new(LiveProgress::default());
        event_listener.set_progress(live_progress.clone());

        let mut instance = Self {
            ctx: Arc::new(IndexerContext {
                store: SharedStore::new(Arc::new(RwLock::new(store))),
                contract,
                event_listener,
                block_listener,
                contract_address,
                chain_id,
                callbacks: CallbackQueue::new(),
                backfill_start: AtomicU64::new(BACKFILL_UNSET),
                backfill_chunk: AtomicU64::new(DEFAULT_BACKFILL_CHUNK),
                backfill_enabled: Arc::new(AtomicBool::new(false)),
                cursor_high: Arc::new(AtomicU64::new(0)),
                caught_up: Arc::new(AtomicBool::new(false)),
                live_progress,
            }),
        };
        instance.setup_listeners().await?;
        info!("InterfoldIndexer has been configured");
        Ok(instance)
    }

    /// Listen for contract events from all contracts.
    /// Callback will provide the event and a context object.
    pub async fn add_event_handler<E, F, Fut>(&self, handler: F)
    where
        E: SolEvent + Send + Clone + 'static,
        F: Fn(E, Arc<IndexerContext<S, R>>) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<()>> + Send + 'static,
    {
        let handler = Arc::new(handler);
        let ctx = self.ctx.clone();
        // In order to avoid a memory leak we create a weak reference here
        let ctx_weak = Arc::downgrade(&ctx);

        self.ctx
            .event_listener
            .add_event_handler(move |e: E| {
                let handler = Arc::clone(&handler);
                let ctx_weak = ctx_weak.clone();

                async move {
                    // We check the weak reference if it can be upgraded
                    // if not it must have been destroyed
                    if let Some(ctx) = ctx_weak.upgrade() {
                        handler(e, ctx).await
                    } else {
                        warn!("Context was dropped!");
                        Ok(())
                    }
                }
            })
            .await;
    }

    /// Register a handler that receives every log this indexer sees, undecoded.
    ///
    /// For consumers that need to retain events this crate has no ABI for — an index serving a
    /// client's own queries, rather than a reaction to a known event.
    pub async fn add_raw_log_handler<F, Fut>(&self, handler: F)
    where
        F: Fn(alloy::rpc::types::Log, Arc<IndexerContext<S, R>>) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<()>> + Send + 'static,
    {
        let handler = Arc::new(handler);
        let ctx = self.ctx.clone();
        let ctx_weak = Arc::downgrade(&ctx);

        self.ctx
            .event_listener
            .add_raw_handler(move |log: alloy::rpc::types::Log| {
                let handler = Arc::clone(&handler);
                let ctx_weak = ctx_weak.clone();

                async move {
                    if let Some(ctx) = ctx_weak.upgrade() {
                        handler(log, ctx).await
                    } else {
                        warn!("Context was dropped!");
                        Ok(())
                    }
                }
            })
            .await;
    }

    async fn register_committee_published(&mut self) -> Result<()> {
        self.add_event_handler(move |e: CommitteePublished, ctx| async move {
            // A bad legacy candidate must not hold the indexer cursor. Every candidate still passes
            // the same semantic DKG commitment check before storage.
            store_committee_public_key(e, ctx, true).await?;
            Ok(())
        })
        .await;
        Ok(())
    }

    async fn register_committee_public_key_chunks(&mut self) -> Result<()> {
        self.add_event_handler(
            move |event: CommitteePublicKeyChunkPublished, ctx| async move {
                if !PublicKeyChunkAssembly::event_shape_is_valid(&event) {
                    warn!(
                        "Ignoring malformed public-key chunk from {} for E3 {}",
                        event.publisher, event.e3Id
                    );
                    return Ok(());
                }
                let publisher_key = format!(
                    "_pk_candidate:{}:{}",
                    event.e3Id, event.publisher
                );
                let candidate_hash = event.candidateHash.0;
                let mut store = ctx.store();
                let selected = store
                    .modify(&publisher_key, move |current: Option<[u8; 32]>| {
                        Some(current.unwrap_or(candidate_hash))
                    })
                    .await
                    .map_err(|error| eyre!("saving public-key candidate failed: {error}"))?
                    .ok_or_else(|| eyre!("public-key candidate selection disappeared"))?;
                if selected != event.candidateHash.0 {
                    warn!(
                        "Ignoring a second public-key candidate from {} for E3 {}",
                        event.publisher, event.e3Id
                    );
                    return Ok(());
                }
                let assembly_key = format!(
                    "_pk_chunk:{}:{}:{:#x}",
                    event.e3Id, event.publisher, event.candidateHash
                );
                let event_for_update = event.clone();
                let assembly = store
                    .modify(&assembly_key, move |current: Option<PublicKeyChunkAssembly>| {
                        let mut current = current
                            .unwrap_or_else(|| PublicKeyChunkAssembly::from_event(&event_for_update));
                        current.insert(&event_for_update);
                        Some(current)
                    })
                    .await
                    .map_err(|error| eyre!("saving public-key chunk failed: {error}"))?
                    .ok_or_else(|| eyre!("public-key chunk assembly disappeared"))?;

                if assembly.invalid || assembly.stored {
                    return Ok(());
                }
                let Some(public_key) = assembly.bytes() else {
                    return Ok(());
                };
                if keccak256(&public_key) != event.candidateHash {
                    warn!(
                        "Ignoring chunked committee public key with a mismatched content hash for E3 {}",
                        event.e3Id
                    );
                    mark_public_key_assembly(&mut store, &assembly_key, false).await?;
                    return Ok(());
                }

                let synthetic = CommitteePublished {
                    e3Id: event.e3Id,
                    nodes: assembly.nodes,
                    publicKey: public_key.into(),
                    pkCommitment: assembly.pk_commitment.into(),
                    proof: Vec::new().into(),
                };
                let stored = store_committee_public_key(synthetic, ctx, true).await?;
                mark_public_key_assembly(&mut store, &assembly_key, stored).await?;
                Ok(())
            },
        )
        .await;
        Ok(())
    }

    async fn register_ciphertext_output_published(&mut self) -> Result<()> {
        self.add_event_handler(move |e: CiphertextOutputPublished, ctx| async move {
            let store = ctx.store();
            info!(
                "CiphertextOutputPublished: e3_id={}, output=0x{}...",
                e.e3Id,
                hex::encode(&e.ciphertextOutput[..8.min(e.ciphertextOutput.len())])
            );
            let e3_id = e.e3Id.to_string();

            let mut repo = E3Repository::new(store, e3_id);
            repo.set_ciphertext_output(e.ciphertextOutput.to_vec())
                .await?;
            repo.set_ciphertext_commitment(e.ciphertextCommitment.to_vec())
                .await?;

            Ok(())
        })
        .await;
        Ok(())
    }

    async fn register_ciphertext_output_reference_published(&mut self) -> Result<()> {
        self.add_event_handler(
            move |event: CiphertextOutputReferencePublished, ctx| async move {
                info!(
                    "CiphertextOutputReferencePublished: e3_id={}, block={}, leaf_index={}",
                    event.e3Id, event.availabilityBlock, event.availabilityLeafIndex
                );
                let mut repo = E3Repository::new(ctx.store(), event.e3Id.to_string());
                repo.set_ciphertext_output_reference(
                    CiphertextOutputReference {
                        content_hash: event.contentHash.to_vec(),
                        availability_block: event.availabilityBlock,
                        availability_leaf_index: event.availabilityLeafIndex,
                    },
                    event.ciphertextCommitment.to_vec(),
                )
                .await
            },
        )
        .await;
        Ok(())
    }

    async fn register_plaintext_output_published(&mut self) -> Result<()> {
        self.add_event_handler(move |e: PlaintextOutputPublished, ctx| async move {
            let store = ctx.store();
            info!(
                "PlaintextOutputPublished: e3_id={}, output=0x{}..., proof_len={}",
                e.e3Id,
                hex::encode(&e.plaintextOutput[..8.min(e.plaintextOutput.len())]),
                e.proof.len()
            );
            let e3_id = e.e3Id.to_string();
            let mut repo = E3Repository::new(store, e3_id);
            repo.set_plaintext_output(e.plaintextOutput.to_vec())
                .await?;

            Ok(())
        })
        .await;
        Ok(())
    }

    async fn register_blocktime_callback_handler(&mut self) -> Result<()> {
        let callbacks = self.ctx.callbacks.clone();
        let store = self.ctx.store();
        // Only the shared flags, never `self.ctx`: the context owns this block listener, so a
        // handler that captured the context would form a cycle and the indexer would never drop.
        let backfill_enabled = self.ctx.backfill_enabled.clone();
        let caught_up = self.ctx.caught_up.clone();
        let cursor_high = self.ctx.cursor_high.clone();
        let live_progress = self.ctx.live_progress.clone();
        self.ctx
            .block_listener
            .add_block_handler(move |block| {
                let timestamp = block.timestamp();
                let blockheight = block.number();
                let callbacks = callbacks.clone();
                let mut store = store.clone();
                let backfill_enabled = backfill_enabled.clone();
                let caught_up = caught_up.clone();
                let cursor_high = cursor_high.clone();
                let live_progress = live_progress.clone();
                async move {
                    info!("ON BLOCK: {}:{}", blockheight, timestamp);

                    // Advance the cursor as the chain moves, not only during backfill. Without
                    // this it freezes at the block catch-up ended on: the live subscription keeps
                    // applying logs, but anything asking "how far has this been applied?" is told
                    // a number that never grows — so a reader can never trust the index for
                    // recent blocks, and a restart re-scans everything since boot.
                    //
                    // Only for consumers that asked for backfill, and only once the catch-up has
                    // actually completed. Writing it unconditionally made every consumer resumable
                    // whether or not they opted in, and writing it with a gap still unreplayed
                    // beneath would seal that gap permanently.
                    let tracking = backfill_enabled.load(Ordering::Relaxed)
                        && caught_up.load(Ordering::Relaxed);

                    // A header says the CHAIN reached this block, not that its logs have been
                    // applied — those arrive on a separate subscription. `blockheight - 1` is only
                    // a one-block hedge against that, and it is not enough on its own: a raw
                    // handler that is slow (or has failed) leaves earlier logs unwritten while
                    // headers keep arriving, and the cursor would claim them anyway. So the claim
                    // is capped by what the listener reports it has actually finished.
                    let ceiling = blockheight
                        .checked_sub(1)
                        .and_then(|hedged| live_progress.applied_ceiling(hedged));

                    if let (true, Some(applied)) = (tracking, ceiling) {
                        // Handlers are spawned, so headers can be processed out of order. Only a
                        // strictly higher claim is persisted — a lower one would move the cursor
                        // backwards and make the next restart replay applied blocks.
                        let previous = cursor_high.fetch_max(applied, Ordering::Relaxed);
                        if applied > previous {
                            if let Err(e) = store.insert(INDEXER_CURSOR_KEY, &applied).await {
                                warn!("Could not advance the indexer cursor: {e}");
                            }
                        }
                    }

                    callbacks.execute_until_including(timestamp).await?;
                    Ok(())
                }
            })
            .await;
        Ok(())
    }

    async fn setup_listeners(&mut self) -> Result<()> {
        info!("Setting up listeners for InterfoldIndexer...");
        self.register_committee_published().await?;
        self.register_committee_public_key_chunks().await?;
        self.register_ciphertext_output_published().await?;
        self.register_ciphertext_output_reference_published()
            .await?;
        self.register_plaintext_output_published().await?;
        self.register_blocktime_callback_handler().await?;
        info!("Listeners have been setup!");
        Ok(())
    }

    /// The current chain head, read through the SAME provider the catch-up uses.
    ///
    /// Exposed so a caller can pin `configure_backfill` to a head it has already observed. Reading
    /// the head from a second endpoint and assuming the two agree is a silent hole: the other read
    /// is at a different moment, possibly against a different node, and any caller recording where
    /// indexing begins would record a block the catch-up then starts above.
    pub async fn head_block(&self) -> Result<u64> {
        self.ctx.event_listener.head_block().await
    }

    /// Configure historical catch-up. Call before [`Self::listen`].
    ///
    /// **Calling this at all opts in.** An indexer that never calls it keeps the original
    /// behaviour exactly: no cursor is written, nothing is replayed, and the subscription starts
    /// at the head. That distinction is the whole safety argument, because the handlers are not
    /// pure — replaying `E3Requested` re-submits `setMerkleRoot` on chain and resets the stored
    /// round — so a consumer must never acquire replay by upgrading the crate.
    ///
    /// `start_block` is used only when the store holds no cursor — i.e. on a fresh database.
    /// Passing `None` there starts at the chain head, so a caller can opt into cursor tracking
    /// (and therefore into resuming after a restart) without asking for history. Once a cursor
    /// exists it always wins, so a restart replays exactly the gap and nothing else.
    pub fn configure_backfill(&self, start_block: Option<u64>, chunk: Option<u64>) {
        self.ctx
            .backfill_start
            .store(start_block.unwrap_or(BACKFILL_UNSET), Ordering::Relaxed);
        if let Some(chunk) = chunk.filter(|c| *c > 0) {
            self.ctx.backfill_chunk.store(chunk, Ordering::Relaxed);
        }
        // Release-ordered so the values above are visible to any thread that observes the flag.
        self.ctx.backfill_enabled.store(true, Ordering::Release);
    }

    /// Replay every log between the stored cursor and the current head.
    ///
    /// Runs before the subscription on every (re)connect: `subscribe_logs` starts at the head and
    /// has no memory, so without this each restart or dropped socket leaves a permanent hole in
    /// the store. The cursor is persisted per window, so an interrupted catch-up resumes from the
    /// last window that fully applied rather than starting over or skipping ahead.
    async fn catch_up_to_head(&self) -> Result<()> {
        let mut store = self.ctx.store();

        let cursor: Option<u64> = store
            .get(INDEXER_CURSOR_KEY)
            .await
            .map_err(|e| eyre!("reading the indexer cursor failed: {e}"))?;

        let mut head = self.ctx.event_listener.head_block().await?;

        let mut window_start = match cursor {
            Some(cursor) => cursor.saturating_add(1),
            None => match self.ctx.backfill_start.load(Ordering::Relaxed) {
                // No history was asked for, so there is nothing to replay yet — but the cursor is
                // persisted anyway, at `head - 1`. That is what gives the overlap pass a lower
                // bound to work from: without it the pass would take this same branch again and
                // the blocks mined before the subscription came up would be replayed by nobody.
                BACKFILL_UNSET => {
                    let applied = head.saturating_sub(1);
                    store
                        .insert(INDEXER_CURSOR_KEY, &applied)
                        .await
                        .map_err(|e| eyre!("persisting the indexer cursor failed: {e}"))?;
                    self.ctx.cursor_high.fetch_max(applied, Ordering::Relaxed);
                    return Ok(());
                }
                configured => configured,
            },
        };

        let chunk = self.ctx.backfill_chunk.load(Ordering::Relaxed).max(1);
        let mut total = 0u64;

        // Re-reads the head after each pass rather than aiming at the one read at the start.
        // A backfill from a deployment block takes minutes to hours, and every block mined while
        // it ran was in neither the replay nor the subscription that starts afterwards — a
        // permanent hole that the coverage record would then claim was indexed.
        loop {
            if window_start > head {
                let latest = self.ctx.event_listener.head_block().await?;
                // Converged: the chain has not moved past what has been applied. This is NOT yet
                // the end of the story — the subscription is not up at this point, so blocks
                // mined between here and its arrival are still uncovered. `listen` runs this
                // function a second time once the subscription is live, and that pass is what
                // makes the overlap real.
                if latest <= head {
                    break;
                }
                head = latest;
                continue;
            }

            info!("Backfilling logs from block {window_start} to {head}...");

            let window_end = window_start.saturating_add(chunk - 1).min(head);

            total += self
                .ctx
                .event_listener
                .catch_up(window_start, window_end, chunk)
                .await?;

            // Only after the window's handlers have all succeeded: the cursor is a claim that
            // everything up to here has been applied, and advancing it past a failed handler
            // would turn a retryable error into a silent gap.
            store
                .insert(INDEXER_CURSOR_KEY, &window_end)
                .await
                .map_err(|e| eyre!("persisting the indexer cursor failed: {e}"))?;
            self.ctx
                .cursor_high
                .fetch_max(window_end, Ordering::Relaxed);

            window_start = window_end.saturating_add(1);
        }

        info!("Backfill complete: {total} log(s) applied up to block {head}");
        Ok(())
    }

    pub async fn listen(&self) -> Result<()> {
        info!("Starting InterfoldIndexer listening...");

        // How many times a backfill may fail before the indexer subscribes anyway.
        //
        // `catch_up` propagates handler errors so a failed window does not advance the cursor —
        // correct on its own, but combined with an unconditional retry it meant one permanently
        // failing historical event (a revert, an exhausted API key) stopped the indexer from ever
        // subscribing. That converts a gap into a total outage. After this many attempts, live
        // indexing resumes with `caught_up` still false, so the cursor stays put and the gap is
        // replayed on a later attempt rather than being sealed.
        const MAX_BACKFILL_ATTEMPTS: u32 = 5;

        let mut backfill_failures = 0u32;

        let backfill_enabled = self.ctx.backfill_enabled.clone();

        loop {
            self.ctx.caught_up.store(false, Ordering::Relaxed);
            // Reset synchronously, before the futures below are built: left set from the previous
            // iteration, the overlap pass would fire against a subscription that no longer exists.
            self.ctx.live_progress.mark_unsubscribed();
            self.ctx.live_progress.healthy.store(true, Ordering::SeqCst);
            self.ctx
                .live_progress
                .processing_block
                .store(NOT_PROCESSING, Ordering::SeqCst);

            // The bulk of the replay runs before subscribing, so a long backfill is not held open
            // by a live socket. It cannot close the gap by itself, though: it converges on a head
            // read taken while nothing is subscribed. The overlap pass below finishes the job.
            if backfill_enabled.load(Ordering::Acquire) {
                match self.catch_up_to_head().await {
                    Ok(()) => backfill_failures = 0,
                    Err(e) => {
                        backfill_failures += 1;
                        if backfill_failures < MAX_BACKFILL_ATTEMPTS {
                            error!(
                                "Backfill failed ({backfill_failures}/{MAX_BACKFILL_ATTEMPTS}): \
                                 {e}. Retrying in 5s..."
                            );
                            sleep(Duration::from_secs(5)).await;
                            continue;
                        }
                        error!(
                            "Backfill has failed {backfill_failures} times: {e}. Subscribing to \
                             live logs anyway; the cursor stays put, so the unreplayed range is \
                             NOT claimed as indexed and will be retried on the next reconnect."
                        );
                    }
                }
            }

            // Replay once more, this time from inside the subscription's lifetime.
            //
            // The pass above ends on a head read taken while nothing was subscribed, and the
            // subscription only comes up a moment later. Blocks mined in between were in NEITHER —
            // and the cursor then advanced past them from the header stream, so nothing ever went
            // back for them. Silent, permanent, and reported as covered.
            //
            // Waiting for `mark_subscribed` before replaying makes the overlap the code has always
            // claimed real: this range is now delivered by the subscription, by this replay, or by
            // both. Duplicates are the intended cost — the store's `append` is idempotent on
            // (block, log_index) precisely for this.
            //
            // `caught_up` is set only when this succeeds, so the cursor cannot advance while the
            // handoff range is still outstanding.
            let overlap = async {
                if !backfill_enabled.load(Ordering::Acquire) {
                    return std::future::pending::<Result<()>>().await;
                }

                self.ctx.live_progress.wait_subscribed().await;

                // Retried until it succeeds, rather than attempted once. Giving up here left
                // `caught_up` false for the life of the connection, and a healthy subscription can
                // run for days without reconnecting — so the cursor would freeze that whole time,
                // a restart would replay everything since the last good window, and any reader
                // asking how far the index has been applied would be told a number hours stale.
                // Nothing here is worth failing permanently over: the range is still on chain.
                loop {
                    match self.catch_up_to_head().await {
                        Ok(()) => {
                            info!("Handoff replay complete; the index is live and contiguous.");
                            self.ctx.caught_up.store(true, Ordering::Relaxed);
                            break;
                        }
                        Err(e) => {
                            error!(
                                "Handoff replay failed: {e}. The cursor stays put, so the handoff \
                                 range is not claimed as indexed. Retrying in 5s..."
                            );
                            sleep(Duration::from_secs(5)).await;
                        }
                    }
                }

                // Never resolves, so this branch cannot win the select and cancel the listeners.
                std::future::pending::<Result<()>>().await
            };

            let res = tokio::select! {
                res = self.ctx.event_listener.listen() => {
                    match &res {
                        Ok(_) => warn!("EventListener curiously halted naturally."),
                        Err(e) => error!("EventListener halted with an error: {e}")
                    };
                    res
                }
                res = self.ctx.block_listener.listen() => {
                    match &res {
                        Ok(_) => warn!("BlockListener curiously halted naturally."),
                        Err(e) => error!("BlockListener halted with an error: {e}")
                    };
                    res
                }
                res = overlap => res,
            };

            let secs = res.map(|_| 1).unwrap_or(5);
            warn!("Restarting listeners in {}s...", secs);
            sleep(Duration::from_secs(secs)).await
        }
    }

    pub async fn get_e3(&self, e3_id: impl ToString) -> Result<E3, IndexerError> {
        let (e3, _) = get_e3(self.ctx.store.inner.clone(), e3_id).await?;
        Ok(e3)
    }

    pub fn get_store(&self) -> SharedStore<S> {
        self.ctx.store.clone()
    }

    /// Schedule a timestamp callback without requiring an event-handler context.
    pub fn schedule_at<F, Fut>(&self, timestamp: u64, callback: F)
    where
        F: Fn(u64, Arc<IndexerContext<S, R>>) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<()>> + Send + 'static,
    {
        self.ctx.do_later(timestamp, callback);
    }
}

pub async fn get_e3(
    store: Arc<RwLock<impl DataStore>>,
    e3_id: impl ToString,
) -> Result<(E3, String), IndexerError> {
    let e3_id = e3_id.to_string();
    let key = format!("_e3:{}", e3_id);
    match store
        .read()
        .await
        .get::<E3>(&key)
        .await
        .map_err(|_| IndexerError::Serialization(e3_id.clone()))?
    {
        Some(e3) => Ok((e3, key)),
        None => Err(IndexerError::E3NotFound(e3_id)),
    }
}

fn u64_try_from(input: Uint<256, 4>) -> Result<u64> {
    u64::try_from(input).map_err(|_| eyre!("larger than 64-bit"))
}

#[cfg(test)]
mod public_key_chunk_tests {
    use super::{
        mark_public_key_assembly, DataStore, InMemoryStore, PublicKeyChunkAssembly, SharedStore,
    };
    use alloy::primitives::Address;
    use std::sync::Arc;
    use tokio::sync::RwLock;

    #[tokio::test]
    async fn completed_assembly_drops_temporary_chunk_bytes() {
        let mut store = SharedStore::new(Arc::new(RwLock::new(InMemoryStore::new())));
        let key = "_pk_chunk:1:publisher:candidate";
        let assembly = PublicKeyChunkAssembly {
            nodes: vec![Address::ZERO],
            pk_commitment: [1; 32],
            total_length: 4,
            chunk_count: 2,
            chunks: vec![Some(vec![2; 2]), Some(vec![3; 2])],
            invalid: false,
            stored: false,
        };
        store.insert(key, &assembly).await.unwrap();

        mark_public_key_assembly(&mut store, key, true)
            .await
            .unwrap();

        let completed = store
            .get::<PublicKeyChunkAssembly>(key)
            .await
            .unwrap()
            .unwrap();
        assert!(completed.stored);
        assert!(!completed.invalid);
        assert!(completed.chunks.is_empty());
    }
}
