// SPDX-License-Identifier: LGPL-3.0-only

use alloy::primitives::U256;
use anyhow::{Context, Result};
use e3_events::E3id;
use e3_request::canonical_key::CanonicalPublicKeys;
use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, OnceLock,
    },
};

type Key = [u8; 40]; // chain and canonical uint256 request number
type Bounds = (u64, u64);
pub(super) type SpillIo = Box<dyn FnOnce() -> Result<()> + Send>;
const MEMORY_IDS: usize = 256;

#[derive(Debug)]
pub(super) struct SpillFailure;

impl std::fmt::Display for SpillFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("early share index unavailable")
    }
}

pub(super) async fn finish(io: Option<SpillIo>) -> Result<()> {
    if let Some(io) = io {
        tokio::task::spawn_blocking(io)
            .await
            .context(SpillFailure)?
            .context(SpillFailure)?;
    }
    Ok(())
}

/// Only exact request IDs get a journal hint. The bounded memory tier covers ordinary early
/// arrivals; overflow is a disposable index, rebuilt from the journal rather than trusted on boot.
#[derive(Default)]
pub(super) struct EarlyShares {
    memory: HashMap<Key, Bounds>,
    spill: Option<Arc<Spill>>,
}

impl EarlyShares {
    fn key(id: &E3id) -> Option<Key> {
        let text = id.e3_id();
        if text.is_empty()
            || text.len() > 78
            || (text.len() > 1 && text.starts_with('0'))
            || !text.bytes().all(|b| b.is_ascii_digit())
        {
            return None;
        }
        let mut key = [0; 40];
        key[..8].copy_from_slice(&id.chain_id().to_be_bytes());
        key[8..].copy_from_slice(&U256::from_str_radix(text, 10).ok()?.to_be_bytes::<32>());
        Some(key)
    }

    pub(super) fn note(&mut self, id: &E3id, seq: u64) -> Option<SpillIo> {
        let key = Self::key(id)?;
        if let Some((first, last)) = self.memory.get_mut(&key) {
            *first = (*first).min(seq);
            *last = (*last).max(seq);
            return None;
        }
        // While overflow is populated, keep new keys there: a request must never be split
        // between the two tiers as in-memory slots are freed.
        if self.memory.len() < MEMORY_IDS && self.spill.as_ref().is_none_or(|s| s.is_empty()) {
            self.memory.insert(key, (seq, seq));
            return None;
        }
        let spill = self.spill.get_or_insert_with(Default::default).clone();
        Some(Box::new(move || spill.note(key, seq)))
    }

    pub(super) fn take(
        &mut self,
        id: &E3id,
        target: Option<&CanonicalPublicKeys>,
    ) -> Option<SpillIo> {
        let key = Self::key(id)?;
        let publish = |keys: &CanonicalPublicKeys, id: &E3id, (first, last): Bounds| {
            keys.note_synchronized_candidate(id, first);
            keys.note_synchronized_candidate(id, last);
        };
        if let Some(bounds) = self.memory.remove(&key) {
            if let Some(keys) = target {
                publish(keys, id, bounds);
            }
            return None;
        }
        let spill = self.spill.as_ref().filter(|s| !s.is_empty())?.clone();
        let (target, id) = (target.cloned(), id.clone());
        Some(Box::new(move || {
            if let (Some(keys), Some(bounds)) = (target, spill.take(key)?) {
                publish(&keys, &id, bounds);
            }
            Ok(())
        }))
    }
}

/// The projection awaits one operation before processing the next journal event. Only the
/// blocking worker opens/accesses the index; an empty spill costs no disk reads.
#[derive(Default)]
struct Spill {
    store: OnceLock<(sled::Db, tempfile::TempDir)>,
    entries: AtomicUsize,
}

impl Spill {
    fn is_empty(&self) -> bool {
        self.entries.load(Ordering::Relaxed) == 0
    }

    fn db(&self) -> Result<&sled::Db> {
        if let Some((db, _)) = self.store.get() {
            return Ok(db);
        }
        let dir = tempfile::Builder::new()
            .prefix("interfold-early-shares-")
            .tempdir()?;
        let db = sled::Config::new()
            .path(dir.path())
            .cache_capacity(1024 * 1024)
            .open()?;
        Ok(&self.store.get_or_init(|| (db, dir)).0)
    }

    fn bounds(bytes: &[u8]) -> Result<Bounds> {
        let (first, last) = bytes
            .split_first_chunk::<8>()
            .context("invalid early share hint")?;
        Ok((
            u64::from_be_bytes(*first),
            u64::from_be_bytes(last.try_into()?),
        ))
    }

    fn note(&self, key: Key, seq: u64) -> Result<()> {
        let db = self.db()?;
        let old = db.get(key)?;
        let (first, last) = old
            .as_deref()
            .map(Self::bounds)
            .transpose()?
            .unwrap_or((seq, seq));
        let mut bytes = [0; 16];
        bytes[..8].copy_from_slice(&first.min(seq).to_be_bytes());
        bytes[8..].copy_from_slice(&last.max(seq).to_be_bytes());
        db.insert(key, &bytes)?;
        if old.is_none() {
            self.entries.fetch_add(1, Ordering::Relaxed);
        }
        Ok(())
    }

    fn take(&self, key: Key) -> Result<Option<Bounds>> {
        let Some(bytes) = self.db()?.remove(key)? else {
            return Ok(None);
        };
        self.entries.fetch_sub(1, Ordering::Relaxed);
        Ok(Some(Self::bounds(&bytes)?))
    }
}
