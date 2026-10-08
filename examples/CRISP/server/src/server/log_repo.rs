// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! A generic log index for the contracts on the `/chain/*` allowlist.
//!
//! Logs are stored as they arrive, without a handler per event, so the server needs no knowledge
//! of what an event means and a client can ask for any event. Logs are bucketed by block because
//! the store only reads and writes whole values: a key per log makes a range query a scan, and a
//! key per address makes every append rewrite the whole history.

use super::database::store_error;
use e3_sdk::indexer::{DataStore, SharedStore, INDEXER_CURSOR_KEY};
use eyre::{eyre, Result};
use serde::{Deserialize, Serialize};

/// Blocks per bucket. At ~12s blocks this is roughly a day and a half of history per key, so a
/// query spanning a typical deployment's lifetime reads tens of keys, not thousands.
const BUCKET_SIZE: u64 = 10_000;

/// The most buckets one query reads. It bounds the work for a range that no chain reaches.
const MAX_QUERY_BUCKETS: u64 = 100_000;

/// One indexed log, in the shape the `/chain/logs` route returns.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredLog {
    /// True when the node reported this log as orphaned by a reorg. Stored entries are never
    /// `removed`: the flag only travels far enough to delete what it supersedes.
    #[serde(default)]
    pub removed: bool,
    pub address: String,
    pub topics: Vec<String>,
    pub data: String,
    pub block_number: u64,
    pub transaction_hash: Option<String>,
    pub log_index: u64,
    /// Both `#[serde(default)]` so entries written before these were stored still deserialize.
    ///
    /// They belong to the mined-log shape `eth_getLogs` returns, and a client must not be able to
    /// tell an indexed answer from a forwarded one. An entry that lacks either is served upstream
    /// instead (`logs_from_index`).
    #[serde(default)]
    pub block_hash: Option<String>,
    #[serde(default)]
    pub transaction_index: Option<u64>,
}

/// The first block indexed for one address. A query that starts earlier cannot be served from the
/// store, however much it holds.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct LogCoverage {
    from_block: u64,
}

pub struct LogRepository<S: DataStore> {
    store: SharedStore<S>,
}

impl<S: DataStore> LogRepository<S> {
    pub fn new(store: SharedStore<S>) -> Self {
        Self { store }
    }

    /// Addresses are lowercased in keys so a checksummed request and an indexed log agree.
    fn bucket_key(address: &str, bucket: u64) -> String {
        format!("_logs:{}:{}", address.to_lowercase(), bucket)
    }

    fn coverage_key(address: &str) -> String {
        format!("_logs:{}:coverage", address.to_lowercase())
    }

    /// Record a log, replacing any entry already stored at the same position.
    ///
    /// Idempotent on `(block_number, log_index)`: the indexer catches up to the head and then
    /// subscribes, and the overlap between the two is deliberate, because a gap is worse than a
    /// duplicate.
    ///
    /// REPLACES rather than skips, because that position is where a reorg puts the canonical log
    /// that supersedes an orphaned one. Skipping the second arrival would pin the orphan. A log
    /// with `removed: true` deletes the entry it names, so the index never asserts an event that no
    /// longer happened.
    ///
    /// The bucket changes in one atomic `modify`, because handlers append concurrently and two logs
    /// of one bucket must both survive.
    pub async fn append(&mut self, log: StoredLog) -> Result<()> {
        let key = Self::bucket_key(&log.address, log.block_number / BUCKET_SIZE);
        let mut applied = false;
        self.store
            .modify(&key, |bucket: Option<Vec<StoredLog>>| {
                let position = bucket.as_deref().and_then(|entries| {
                    entries.iter().position(|entry| {
                        entry.block_number == log.block_number && entry.log_index == log.log_index
                    })
                });
                applied = !log.removed || position.is_some();
                match (log.removed, position) {
                    (true, None) => bucket,
                    (true, Some(position)) => {
                        let mut entries = bucket?;
                        entries.remove(position);
                        Some(entries)
                    }
                    (false, position) => {
                        let mut entries = bucket.unwrap_or_default();
                        match position {
                            Some(position) => entries[position] = log.clone(),
                            // Appended unsorted: `query` orders its result, so sorting here would
                            // pay O(n log n) per log for an order only the reader needs.
                            None => entries.push(log.clone()),
                        }
                        Some(entries)
                    }
                }
            })
            .await
            .map_err(store_error("update the log bucket", &key))?;

        if applied {
            self.update_coverage(&log.address, |from| {
                from.is_none_or(|from| log.block_number < from)
                    .then_some(log.block_number)
            })
            .await?;
        }
        Ok(())
    }

    /// Atomically replace the first indexed block of an address by what `next` returns for the
    /// stored one. `None` leaves the record as it is.
    async fn update_coverage(
        &mut self,
        address: &str,
        mut next: impl FnMut(Option<u64>) -> Option<u64> + Send,
    ) -> Result<()> {
        let key = Self::coverage_key(address);
        self.store
            .modify(&key, |current: Option<LogCoverage>| {
                match next(current.as_ref().map(|coverage| coverage.from_block)) {
                    Some(from_block) => Some(LogCoverage { from_block }),
                    None => current,
                }
            })
            .await
            .map(drop)
            .map_err(store_error("update the log coverage", &key))
    }

    /// Declare that indexing for an address began at `from_block`, even before any log arrives.
    ///
    /// Without this a contract that has emitted nothing yet looks uncovered forever, and every
    /// query for it falls through to the upstream provider although the index is complete. An
    /// existing record is never overwritten.
    pub async fn ensure_coverage_from(&mut self, address: &str, from_block: u64) -> Result<()> {
        self.update_coverage(address, |current| current.is_none().then_some(from_block))
            .await
    }

    /// Re-base an address's coverage to `from_block`, discarding an earlier claim.
    ///
    /// Coverage outlives the configuration that produced it. An address dropped from
    /// `INDEX_LOG_CONTRACTS` and later restored still carries the record of its first run, which
    /// claims history from before the gap, when nothing was indexed. Reads are gated on the live
    /// configuration, so the stale record is not served while the address is absent, but the claim
    /// must narrow to what will be there when the address returns.
    ///
    /// Only ever narrows: a record that starts later is left alone.
    pub async fn rebase_coverage(&mut self, address: &str, from_block: u64) -> Result<()> {
        self.update_coverage(address, |current| {
            current
                .is_some_and(|current| current < from_block)
                .then_some(from_block)
        })
        .await
    }

    /// The highest block the indexer has fully applied: the upper bound of what the store can
    /// answer. A query that reaches past it would report "no logs" for blocks nobody has read yet,
    /// which is worse than forwarding the question upstream.
    pub async fn indexed_head(&self) -> Result<Option<u64>> {
        self.store
            .get(INDEXER_CURSOR_KEY)
            .await
            .map_err(store_error("read the indexer cursor", INDEXER_CURSOR_KEY))
    }

    /// The first block indexed for an address, if any.
    pub async fn coverage(&self, address: &str) -> Result<Option<u64>> {
        let key = Self::coverage_key(address);
        let coverage: Option<LogCoverage> = self
            .store
            .get(&key)
            .await
            .map_err(store_error("read the log coverage", &key))?;
        Ok(coverage.map(|coverage| coverage.from_block))
    }

    /// Logs for an address in `[from, to]`, optionally filtered by positional topics.
    ///
    /// `None` in a topic position matches anything, as in `eth_getLogs`, so a caller can pass the
    /// same filter to either source and get the same answer.
    pub async fn query(
        &self,
        address: &str,
        from: u64,
        to: u64,
        topics: &[Option<String>],
    ) -> Result<Vec<StoredLog>> {
        if from > to {
            return Ok(Vec::new());
        }
        let (first, last) = (from / BUCKET_SIZE, to / BUCKET_SIZE);
        if last - first >= MAX_QUERY_BUCKETS {
            return Err(eyre!("blocks {from} to {to} span too many log buckets"));
        }

        let mut found = Vec::new();
        for bucket in first..=last {
            let key = Self::bucket_key(address, bucket);
            let entries: Vec<StoredLog> = self
                .store
                .get(&key)
                .await
                .map_err(store_error("read the log bucket", &key))?
                .unwrap_or_default();

            found.extend(entries.into_iter().filter(|entry| {
                (from..=to).contains(&entry.block_number)
                    && topics.iter().enumerate().all(|(position, wanted)| {
                        wanted.as_ref().is_none_or(|wanted| {
                            entry
                                .topics
                                .get(position)
                                .is_some_and(|actual| actual.eq_ignore_ascii_case(wanted))
                        })
                    })
            }));
        }

        found.sort_by_key(|entry| (entry.block_number, entry.log_index));
        Ok(found)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use e3_sdk::indexer::InMemoryStore;
    use std::sync::Arc;
    use tokio::sync::RwLock;

    const TOKEN: &str = "0xAbC0000000000000000000000000000000000001";
    const OTHER: &str = "0xdef0000000000000000000000000000000000002";

    fn repo() -> LogRepository<InMemoryStore> {
        let store = SharedStore::new(Arc::new(RwLock::new(InMemoryStore::new())));
        LogRepository::new(store)
    }

    fn log(address: &str, block_number: u64, log_index: u64, topic: &str) -> StoredLog {
        StoredLog {
            removed: false,
            address: address.to_string(),
            topics: vec![topic.to_string()],
            data: String::new(),
            block_number,
            transaction_hash: None,
            log_index,
            block_hash: None,
            transaction_index: None,
        }
    }

    /// A query returns the logs of its address inside its range, across buckets, in chain order,
    /// and applies the topic filter case-insensitively.
    #[tokio::test]
    async fn a_query_is_scoped_to_its_address_range_and_topics() {
        let mut repo = repo();
        for entry in [
            log(TOKEN, 10_005, 0, "0xAA"),
            log(TOKEN, 9_999, 1, "0xaa"),
            log(TOKEN, 9_999, 0, "0xbb"),
            log(TOKEN, 20_000, 0, "0xaa"),
            log(OTHER, 9_999, 2, "0xaa"),
        ] {
            repo.append(entry).await.unwrap();
        }

        let found = repo
            .query(&TOKEN.to_lowercase(), 0, 15_000, &[])
            .await
            .unwrap();
        let positions: Vec<_> = found
            .iter()
            .map(|l| (l.block_number, l.log_index))
            .collect();
        assert_eq!(positions, [(9_999, 0), (9_999, 1), (10_005, 0)]);

        let wanted = [Some("0xAA".to_string())];
        let found = repo.query(TOKEN, 0, 15_000, &wanted).await.unwrap();
        let positions: Vec<_> = found
            .iter()
            .map(|l| (l.block_number, l.log_index))
            .collect();
        assert_eq!(positions, [(9_999, 1), (10_005, 0)]);

        assert!(repo
            .query(TOKEN, 10_000, 9_999, &[])
            .await
            .unwrap()
            .is_empty());
        assert!(repo.query(TOKEN, 0, u64::MAX, &[]).await.is_err());
    }

    /// A log at a stored position replaces the entry, which is where a reorg puts the canonical
    /// log. A `removed` log deletes it, and one that names no entry changes nothing, coverage
    /// included.
    #[tokio::test]
    async fn a_reorg_replaces_or_removes_the_log_at_its_position() {
        let mut repo = repo();
        let orphan_removal = StoredLog {
            removed: true,
            ..log(TOKEN, 7, 0, "0xaa")
        };
        repo.append(orphan_removal.clone()).await.unwrap();
        assert_eq!(repo.coverage(TOKEN).await.unwrap(), None);

        repo.append(log(TOKEN, 7, 0, "0xaa")).await.unwrap();
        repo.append(log(TOKEN, 7, 0, "0xbb")).await.unwrap();
        let found = repo.query(TOKEN, 0, 100, &[]).await.unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].topics, ["0xbb"]);

        repo.append(orphan_removal).await.unwrap();
        assert!(repo.query(TOKEN, 0, 100, &[]).await.unwrap().is_empty());
    }

    /// Coverage widens downward as older logs arrive, `ensure` fills only a gap, and `rebase` only
    /// narrows.
    #[tokio::test]
    async fn coverage_widens_fills_gaps_and_only_narrows_on_rebase() {
        let mut repo = repo();
        repo.ensure_coverage_from(TOKEN, 50).await.unwrap();
        repo.ensure_coverage_from(TOKEN, 10).await.unwrap();
        assert_eq!(repo.coverage(TOKEN).await.unwrap(), Some(50));

        repo.append(log(TOKEN, 80, 0, "0xaa")).await.unwrap();
        assert_eq!(repo.coverage(TOKEN).await.unwrap(), Some(50));
        repo.append(log(TOKEN, 20, 0, "0xaa")).await.unwrap();
        assert_eq!(repo.coverage(TOKEN).await.unwrap(), Some(20));

        repo.rebase_coverage(TOKEN, 5).await.unwrap();
        assert_eq!(repo.coverage(TOKEN).await.unwrap(), Some(20));
        repo.rebase_coverage(TOKEN, 60).await.unwrap();
        assert_eq!(repo.coverage(TOKEN).await.unwrap(), Some(60));
        repo.rebase_coverage(OTHER, 60).await.unwrap();
        assert_eq!(repo.coverage(OTHER).await.unwrap(), None);
    }
}
