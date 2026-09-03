// SPDX-License-Identifier: LGPL-3.0-only

//! Durable per-chunk log of received CKKS relin-ceremony shares.
//!
//! The machine's chunk collectors are `serde(skip)` (re-serializing up to
//! ~100 MB of buffered chunks into the recovery snapshot after EVERY event
//! filled disks live). This log restores them after a restart: each
//! received chunk is written ONCE under its own key, an index of keys is
//! kept in a single small record, and recovery reads the index and feeds
//! every chunk back into the rebuilt machine (idempotent ingestion). Write
//! volume equals the event log's — one copy per chunk — instead of the
//! quadratic snapshot growth.
//!
//! Keys are scoped under
//! `//threshold_keyshare_ckks_ceremony/v1/<e3_id>/` (see
//! `ThresholdKeyshareRepositoryFactory::threshold_keyshare_ckks_ceremony`).
//! The index is loaded ONCE (async, at hydrate) and kept in memory so the
//! actor's synchronous event path records chunks without a store read.

use anyhow::{Context, Result};
use e3_data::DataStore;
use e3_events::{EventContext, RelinCeremonyShare, Sequenced};
use e3_utils::ArcBytes;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// Identity of one chunk within an E3's ceremony.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ChunkKey {
    /// Ceremony round (1 or 2).
    pub round: u8,
    /// Multiplication level.
    pub level: u32,
    /// Sender's 1-based machine party id.
    pub party_id_machine: u64,
    /// Chunk index within the (round, level) payload.
    pub chunk_index: u32,
}

impl ChunkKey {
    fn of(msg: &RelinCeremonyShare) -> Self {
        Self {
            round: msg.round,
            level: msg.level,
            party_id_machine: msg.party_id,
            chunk_index: msg.chunk_index,
        }
    }

    fn scope(&self) -> String {
        format!(
            "c/{}/{}/{}/{}",
            self.round, self.level, self.party_id_machine, self.chunk_index
        )
    }
}

/// Stored form of one chunk (everything the machine needs to re-ingest).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredChunk {
    /// Chunk identity.
    pub key: ChunkKey,
    /// Total chunk count advertised for the payload.
    pub chunk_count: u32,
    /// keccak256 of the complete payload.
    pub payload_keccak: [u8; 32],
    /// The chunk bytes.
    pub bytes: ArcBytes,
}

const INDEX_SCOPE: &str = "index";

/// The log for one E3, with its index resident in memory.
#[derive(Clone, Debug)]
pub struct CeremonyChunkLog {
    store: DataStore,
    index: BTreeSet<ChunkKey>,
}

impl CeremonyChunkLog {
    /// Open the log over the E3-scoped store, loading its index and every
    /// recorded chunk (returned for replay into a rebuilt machine).
    pub async fn open(store: DataStore) -> Result<(Self, Vec<StoredChunk>)> {
        let index: BTreeSet<ChunkKey> = store
            .scope(INDEX_SCOPE)
            .read::<BTreeSet<ChunkKey>>()
            .await
            .context("reading relin ceremony chunk index")?
            .unwrap_or_default();
        let mut chunks = Vec::with_capacity(index.len());
        for key in &index {
            match store.scope(key.scope()).read::<StoredChunk>().await? {
                Some(chunk) => chunks.push(chunk),
                None => tracing::warn!(?key, "relin ceremony chunk listed in index but missing"),
            }
        }
        Ok((Self { store, index }, chunks))
    }

    /// Open an EMPTY log over the store without reading (fresh E3).
    pub fn fresh(store: DataStore) -> Self {
        Self {
            store,
            index: BTreeSet::new(),
        }
    }

    /// Record one received chunk. Idempotent per key: a repeat is a no-op.
    /// The writes ride the event's snapshot batch, so they commit together
    /// with the machine snapshot for the same event.
    pub fn record(&mut self, msg: &RelinCeremonyShare, ec: &EventContext<Sequenced>) -> Result<()> {
        let key = ChunkKey::of(msg);
        if !self.index.insert(key.clone()) {
            return Ok(());
        }
        let stored = StoredChunk {
            key: key.clone(),
            chunk_count: msg.chunk_count,
            payload_keccak: msg.payload_keccak,
            bytes: msg.chunk.clone(),
        };
        self.store
            .scope(key.scope())
            .write_with_context(&stored, ec)
            .context("recording relin ceremony chunk")?;
        self.store
            .scope(INDEX_SCOPE)
            .write_with_context(&self.index, ec)
            .context("recording relin ceremony chunk index")?;
        Ok(())
    }

    /// Number of recorded chunks.
    pub fn len(&self) -> usize {
        self.index.len()
    }

    /// True when nothing is recorded.
    pub fn is_empty(&self) -> bool {
        self.index.is_empty()
    }

    /// Forget every recorded chunk (ceremony complete: the joint keys are
    /// derived and the chunks are dead weight). The index is the reader's
    /// only entry point, so clearing it empties the log; chunk values are
    /// reclaimed when the E3's store scope is purged.
    pub fn clear(&mut self, ec: &EventContext<Sequenced>) -> Result<()> {
        self.index.clear();
        self.store
            .scope(INDEX_SCOPE)
            .write_with_context(&self.index, ec)
            .context("clearing relin ceremony chunk index")
    }
}
