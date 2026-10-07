// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! The DHT puts that this node runs, from the command to their one result.
//!
//! Kademlia acknowledges an inbound put before the receiving application decides whether to store
//! the record, so an acknowledged upload does not show that a peer stores it. After the upload, the
//! node looks the key up, and the put counts as stored only when another peer serves the record
//! back. The puts are owned here, independently of the command correlator and its expiry, until
//! the library reports the end of their last query.

use super::dht_put_summary::DhtPutSummary;
use crate::ContentHash;
use e3_events::CorrelationId;
use libp2p::kad;
use std::collections::HashMap;
use std::time::Instant;

/// Puts that the interface runs at once, also ended ones whose queries Kademlia still holds. The
/// publisher runs one replication at a time, so only puts that it cancelled or stopped waiting for
/// add more.
pub(crate) const MAX_DHT_PUTS: usize = 16;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    /// The put looks up the peers closest to the key and uploads the record to them.
    Upload,
    /// A lookup of the key checks that another peer stores the record.
    Check,
}

struct DhtPut {
    key: ContentHash,
    phase: Phase,
    query: kad::QueryId,
    /// The caller's deadline for the result.
    deadline: Instant,
    /// Whether the caller has the result. A reported put keeps its place until Kademlia reports
    /// the end of its query: a finished query holds its record until the swarm polls it out.
    reported: bool,
}

/// The result that a put reports once.
#[derive(Clone, Debug)]
pub(crate) enum DhtPutResult {
    /// Another peer served the record back.
    Stored,
    /// The upload failed.
    UploadFailed(kad::PutRecordError),
    /// The upload ended, but no other peer served the record back.
    NotReplicated,
    /// The put did not end by its deadline.
    Expired,
    /// This node cancelled the put.
    Cancelled,
}

impl DhtPutResult {
    /// How the upload summary counts the result: stored, failed, or not at all.
    pub(crate) fn counted_as_stored(&self) -> Option<bool> {
        match self {
            Self::Stored => Some(true),
            Self::UploadFailed(_) | Self::NotReplicated | Self::Expired => Some(false),
            Self::Cancelled => None,
        }
    }
}

/// What the interface does next for a put.
#[derive(Debug)]
pub(crate) enum DhtPutStep {
    /// Look `key` up to check the upload, then call [`DhtPuts::checking`] with the query.
    Check {
        correlation_id: CorrelationId,
        key: ContentHash,
    },
    /// Send the result to the caller and count it.
    Report {
        correlation_id: CorrelationId,
        key: ContentHash,
        result: DhtPutResult,
    },
}

/// A query that the interface ends because nobody waits for its put any more. The interface
/// finishes a check lookup, and an upload only in its upload phase: finishing the closest-peer
/// lookup would make Kademlia upload the record at once.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct EndedQuery {
    pub query: kad::QueryId,
    pub checking: bool,
}

#[derive(Default)]
pub(crate) struct DhtPuts {
    puts: HashMap<CorrelationId, DhtPut>,
    by_query: HashMap<kad::QueryId, CorrelationId>,
    /// Every result is counted here once, when the put reports it.
    summary: DhtPutSummary,
}

impl DhtPuts {
    /// The stored and failed counts since the last call; see [`DhtPutSummary::take`].
    pub(crate) fn take_summary(&mut self) -> Option<(usize, usize)> {
        self.summary.take()
    }

    fn report(
        &mut self,
        correlation_id: CorrelationId,
        key: ContentHash,
        result: DhtPutResult,
    ) -> DhtPutStep {
        if let Some(stored) = result.counted_as_stored() {
            self.summary.record(stored);
        }
        DhtPutStep::Report {
            correlation_id,
            key,
            result,
        }
    }

    /// Whether no put runs.
    #[cfg(test)]
    pub(crate) fn is_empty(&self) -> bool {
        self.puts.is_empty() && self.by_query.is_empty()
    }

    /// Whether another put fits.
    pub(crate) fn has_room(&self) -> bool {
        self.puts.len() < MAX_DHT_PUTS
    }

    /// Whether `query` belongs to a put, as its upload or its check.
    pub(crate) fn owns(&self, query: &kad::QueryId) -> bool {
        self.by_query.contains_key(query)
    }

    /// The key that `query` checks, if it is the check of a put.
    pub(crate) fn checked_key(&self, query: &kad::QueryId) -> Option<&ContentHash> {
        let put = self.puts.get(self.by_query.get(query)?)?;
        (put.phase == Phase::Check).then_some(&put.key)
    }

    /// Own a put whose upload query started. It reports its result by `deadline`.
    pub(crate) fn start(
        &mut self,
        correlation_id: CorrelationId,
        key: ContentHash,
        query: kad::QueryId,
        deadline: Instant,
    ) {
        self.by_query.insert(query, correlation_id);
        self.puts.insert(
            correlation_id,
            DhtPut {
                key,
                phase: Phase::Upload,
                query,
                deadline,
                reported: false,
            },
        );
    }

    /// A put command that the interface took after its caller's deadline: it reports expired at
    /// once and starts no query.
    pub(crate) fn expired_before_start(
        &mut self,
        correlation_id: CorrelationId,
        key: ContentHash,
    ) -> DhtPutStep {
        self.report(correlation_id, key, DhtPutResult::Expired)
    }

    /// The upload query of a put ended. A successful upload is checked next.
    pub(crate) fn upload_ended(
        &mut self,
        query: kad::QueryId,
        result: Result<(), kad::PutRecordError>,
    ) -> Option<DhtPutStep> {
        let correlation_id = self.by_query.remove(&query)?;
        let put = self.puts.get(&correlation_id)?;
        if put.reported {
            // Cancelled or expired: nobody waits for it, and it counts no more.
            self.puts.remove(&correlation_id);
            return None;
        }
        match result {
            Ok(()) => Some(DhtPutStep::Check {
                correlation_id,
                key: put.key.clone(),
            }),
            Err(error) => {
                let put = self.puts.remove(&correlation_id)?;
                Some(self.report(correlation_id, put.key, DhtPutResult::UploadFailed(error)))
            }
        }
    }

    /// The check lookup of a put started.
    pub(crate) fn checking(&mut self, correlation_id: CorrelationId, query: kad::QueryId) {
        if let Some(put) = self.puts.get_mut(&correlation_id) {
            put.phase = Phase::Check;
            put.query = query;
            self.by_query.insert(query, correlation_id);
        }
    }

    /// Another peer served the record that a check looks for. The put is stored; its query still
    /// reports its end.
    pub(crate) fn served_by_peer(&mut self, query: &kad::QueryId) -> Option<DhtPutStep> {
        let correlation_id = *self.by_query.get(query)?;
        let put = self.puts.get_mut(&correlation_id)?;
        if put.reported || put.phase != Phase::Check {
            return None;
        }
        put.reported = true;
        let key = put.key.clone();
        Some(self.report(correlation_id, key, DhtPutResult::Stored))
    }

    /// A check query progressed. At its last step the put ends, and a put that no other peer served
    /// is not replicated.
    pub(crate) fn check_progressed(
        &mut self,
        query: &kad::QueryId,
        last: bool,
    ) -> Option<DhtPutStep> {
        if !last {
            return None;
        }
        let correlation_id = self.by_query.remove(query)?;
        let put = self.puts.remove(&correlation_id)?;
        (!put.reported).then(|| self.report(correlation_id, put.key, DhtPutResult::NotReplicated))
    }

    /// Cancel the puts of `key`. Each reports that it was cancelled, now, and its later events
    /// count nothing.
    pub(crate) fn cancel(&mut self, key: &ContentHash) -> (Vec<EndedQuery>, Vec<DhtPutStep>) {
        self.end_where(|put| &put.key == key, DhtPutResult::Cancelled)
    }

    /// End the puts that passed their deadline. Each keeps its place until its query ends.
    pub(crate) fn expire(&mut self, now: Instant) -> (Vec<EndedQuery>, Vec<DhtPutStep>) {
        self.end_where(|put| now >= put.deadline, DhtPutResult::Expired)
    }

    fn end_where(
        &mut self,
        ends: impl Fn(&DhtPut) -> bool,
        result: DhtPutResult,
    ) -> (Vec<EndedQuery>, Vec<DhtPutStep>) {
        let mut queries = Vec::new();
        let mut ended = Vec::new();
        for (correlation_id, put) in &mut self.puts {
            if put.reported || !ends(put) {
                continue;
            }
            put.reported = true;
            queries.push(EndedQuery {
                query: put.query,
                checking: put.phase == Phase::Check,
            });
            ended.push((*correlation_id, put.key.clone()));
        }
        let steps = ended
            .into_iter()
            .map(|(correlation_id, key)| self.report(correlation_id, key, result.clone()))
            .collect();
        (queries, steps)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    const DEADLINE: Duration = Duration::from_secs(240);

    fn queries(count: usize) -> Vec<kad::QueryId> {
        let local = libp2p::PeerId::random();
        let mut kademlia = kad::Behaviour::new(local, kad::store::MemoryStore::new(local));
        (0..count)
            .map(|_| kademlia.get_closest_peers(libp2p::PeerId::random()))
            .collect()
    }

    fn reported(step: Option<DhtPutStep>) -> Option<(CorrelationId, String)> {
        match step? {
            DhtPutStep::Report {
                correlation_id,
                result,
                ..
            } => Some((correlation_id, format!("{result:?}"))),
            DhtPutStep::Check { .. } => None,
        }
    }

    #[test]
    fn an_acknowledged_upload_is_checked_and_counts_only_when_a_peer_serves_it() {
        let [upload, check, other_upload, other_check] = queries(4).try_into().unwrap();
        let (stored, missing) = (CorrelationId::new(), CorrelationId::new());
        let mut puts = DhtPuts::default();
        let now = Instant::now();
        let deadline = now + DEADLINE;
        puts.start(stored, ContentHash(vec![1]), upload, deadline);
        puts.start(missing, ContentHash(vec![2]), other_upload, deadline);

        for (put, upload, check) in [
            (stored, upload, check),
            (missing, other_upload, other_check),
        ] {
            assert!(matches!(
                puts.upload_ended(upload, Ok(())),
                Some(DhtPutStep::Check { correlation_id, .. }) if correlation_id == put
            ));
            puts.checking(put, check);
        }

        // A peer serves the first record. The query still ends later and reports nothing more.
        assert_eq!(
            reported(puts.served_by_peer(&check)),
            Some((stored, "Stored".to_string()))
        );
        assert!(puts.served_by_peer(&check).is_none());
        assert!(puts.check_progressed(&check, true).is_none());
        // The second check ends without a peer's copy.
        assert!(puts.check_progressed(&other_check, false).is_none());
        assert_eq!(
            reported(puts.check_progressed(&other_check, true)),
            Some((missing, "NotReplicated".to_string()))
        );
        assert!(!puts.owns(&check) && !puts.owns(&other_check));
        assert!(puts.puts.is_empty());
        assert_eq!(puts.take_summary(), Some((1, 1)));
    }

    #[test]
    fn a_cancelled_put_reports_once_and_starts_no_check() {
        // Query IDs count per behaviour, so all of them come from one.
        let [lookup, upload, check_query] = queries(3).try_into().unwrap();
        let (in_lookup, in_check) = (CorrelationId::new(), CorrelationId::new());
        let key = ContentHash(vec![7]);
        let mut puts = DhtPuts::default();
        let now = Instant::now();
        puts.start(in_lookup, key.clone(), lookup, now + DEADLINE);
        puts.start(in_check, key.clone(), upload, now + DEADLINE);
        assert!(puts.upload_ended(upload, Ok(())).is_some());
        puts.checking(in_check, check_query);

        let (ended, steps) = puts.cancel(&key);
        assert_eq!(ended.len(), 2);
        assert!(ended.contains(&EndedQuery {
            query: check_query,
            checking: true
        }));
        assert!(ended.contains(&EndedQuery {
            query: lookup,
            checking: false
        }));
        assert_eq!(steps.len(), 2);
        assert!(steps.iter().all(|step| matches!(
            step,
            DhtPutStep::Report {
                result: DhtPutResult::Cancelled,
                ..
            }
        )));
        // The upload that ends later starts no check, and the check's end reports nothing.
        assert!(puts.upload_ended(lookup, Ok(())).is_none());
        assert!(puts.check_progressed(&check_query, true).is_none());
        assert!(puts.cancel(&key).1.is_empty());
        assert!(puts.puts.is_empty());
        // A cancelled put is neither stored nor a failed upload.
        assert_eq!(puts.take_summary(), None);
    }

    #[test]
    fn a_put_past_its_deadline_reports_once_and_keeps_its_place_while_its_query_runs() {
        let [upload] = queries(1).try_into().unwrap();
        let put = CorrelationId::new();
        let mut puts = DhtPuts::default();
        let start = Instant::now();
        puts.start(put, ContentHash(vec![3]), upload, start + DEADLINE);

        assert!(puts.expire(start + DEADLINE / 2).1.is_empty());
        let (ended, steps) = puts.expire(start + DEADLINE);
        assert_eq!(
            ended,
            vec![EndedQuery {
                query: upload,
                checking: false
            }]
        );
        assert!(matches!(
            steps.as_slice(),
            [DhtPutStep::Report {
                result: DhtPutResult::Expired,
                ..
            }]
        ));
        assert!(puts.expire(start + DEADLINE).1.is_empty());
        // Until its query ends, it keeps its place in the capacity, however long that takes.
        puts.expire(start + DEADLINE * 100);
        assert!(puts.owns(&upload));
        assert!(puts.upload_ended(upload, Ok(())).is_none());
        assert!(puts.puts.is_empty());
    }

    #[test]
    fn a_put_taken_after_its_deadline_reports_expired_and_counts_as_failed() {
        let mut puts = DhtPuts::default();
        let put = CorrelationId::new();
        assert!(matches!(
            puts.expired_before_start(put, ContentHash(vec![4])),
            DhtPutStep::Report {
                correlation_id,
                result: DhtPutResult::Expired,
                ..
            } if correlation_id == put
        ));
        assert!(puts.is_empty());
        assert_eq!(puts.take_summary(), Some((0, 1)));
    }

    #[test]
    fn a_failed_upload_reports_its_error_and_the_capacity_is_bounded() {
        let ids = queries(MAX_DHT_PUTS + 1);
        let mut puts = DhtPuts::default();
        let now = Instant::now();
        for query in &ids[..MAX_DHT_PUTS] {
            assert!(puts.has_room());
            puts.start(
                CorrelationId::new(),
                ContentHash(vec![0]),
                *query,
                now + DEADLINE,
            );
        }
        assert!(!puts.has_room());
        let error = kad::PutRecordError::QuorumFailed {
            key: kad::RecordKey::new(&[0u8]),
            success: vec![],
            quorum: std::num::NonZeroUsize::new(1).unwrap(),
        };
        assert!(matches!(
            puts.upload_ended(ids[0], Err(error)),
            Some(DhtPutStep::Report {
                result: DhtPutResult::UploadFailed(_),
                ..
            })
        ));
        assert!(puts.has_room());
    }
}
