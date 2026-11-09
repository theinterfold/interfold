// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Which blob to ask which peer for next. Reads run a few at a time: no peer gets more than its
//! share of them, and the sender with the fewest running goes next, so one member's message cannot
//! starve another's. A blob's bytes count only while its read runs.

use crate::NetworkError;
use alloy_primitives::{Address, B256};
use e3_protocol::{
    node::{PeerMessage, MAX_MESSAGE_BLOBS},
    BlobRef, E3Id,
};
use std::{
    collections::{BTreeMap, HashMap, VecDeque},
    hash::Hash,
    time::{Duration, Instant},
};
use tokio::sync::oneshot;

pub(crate) type Done = oneshot::Sender<Result<(), NetworkError>>;

const MAX_ACTIVE: usize = 8;
const MAX_ACTIVE_PER_PEER: usize = 2;
const MAX_ACTIVE_BYTES: u64 = 256 * 1024 * 1024;
const MAX_WAITING: usize = 4_096;
/// No honest message names more: a dealer's shares for one member are the largest.
const MAX_BLOBS: usize = MAX_MESSAGE_BLOBS;
const MAX_MESSAGE_BYTES: u64 = 512 * 1024 * 1024;
/// A fetch that long in the queue ends, and the sender's re-send starts another.
const LONGEST_FETCH: Duration = Duration::from_secs(10 * 60);

/// One read to start.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Read<P> {
    pub(crate) ticket: u64,
    pub(crate) e3: E3Id,
    pub(crate) hash: B256,
    pub(crate) peer: P,
}

/// What the driver asks the fetcher to take on.
pub(crate) struct Wanted<P> {
    pub(crate) message: PeerMessage,
    pub(crate) missing: Vec<BlobRef>,
    pub(crate) peers: Vec<P>,
}

struct Fetch<P> {
    id: B256,
    e3: E3Id,
    sender: Address,
    peers: Vec<P>,
    /// Each blob with no read running, and the peer to ask for it next.
    waiting: VecDeque<(BlobRef, usize)>,
    /// The blobs not stored yet.
    outstanding: usize,
    done: Vec<Done>,
    started: Instant,
}

struct Ticket<P> {
    fetch: u64,
    sender: Address,
    blob: BlobRef,
    peer_index: usize,
    peer: P,
}

pub(crate) struct Fetcher<P> {
    fetches: BTreeMap<u64, Fetch<P>>,
    of_message: HashMap<B256, u64>,
    tickets: HashMap<u64, Ticket<P>>,
    next_fetch: u64,
    next_ticket: u64,
    active_bytes: u64,
    per_peer: HashMap<P, usize>,
    per_sender: HashMap<Address, usize>,
}

impl<P> Default for Fetcher<P> {
    fn default() -> Self {
        Self {
            fetches: BTreeMap::new(),
            of_message: HashMap::new(),
            tickets: HashMap::new(),
            next_fetch: 0,
            next_ticket: 0,
            active_bytes: 0,
            per_peer: HashMap::new(),
            per_sender: HashMap::new(),
        }
    }
}

impl<P: Copy + Eq + Hash> Fetcher<P> {
    /// Answers `done` too when the fetch of message `id` is on its way; otherwise gives it back.
    pub(crate) fn join(&mut self, id: &B256, done: Done) -> Option<Done> {
        let Some(fetch) = self
            .of_message
            .get(id)
            .and_then(|f| self.fetches.get_mut(f))
        else {
            return Some(done);
        };
        fetch.done.push(done);
        None
    }

    /// Takes on `wanted`, or answers `done` that the node cannot now.
    pub(crate) fn add(&mut self, wanted: Wanted<P>, done: Done, now: Instant) {
        let bytes = wanted
            .missing
            .iter()
            .fold(0u64, |sum, blob| sum.saturating_add(blob.len));
        if self.fetches.len() >= MAX_WAITING
            || wanted.missing.len() > MAX_BLOBS
            || bytes > MAX_MESSAGE_BYTES
        {
            let _ = done.send(Err(NetworkError::Busy));
            return;
        }
        let fetch = self.next_fetch;
        self.next_fetch += 1;
        let id = wanted.message.id();
        self.of_message.insert(id, fetch);
        self.fetches.insert(
            fetch,
            Fetch {
                id,
                e3: wanted.message.e3,
                sender: wanted.message.sender,
                peers: wanted.peers,
                outstanding: wanted.missing.len(),
                waiting: wanted.missing.into_iter().map(|blob| (blob, 0)).collect(),
                done: vec![done],
                started: now,
            },
        );
    }

    /// The reads to start now. Each is running until `stored` or `failed` names its ticket.
    pub(crate) fn next_reads(&mut self) -> Vec<Read<P>> {
        let mut reads = Vec::new();
        while self.tickets.len() < MAX_ACTIVE {
            let Some(fetch) = self.next_fetch_to_read() else {
                break;
            };
            let state = self.fetches.get_mut(&fetch).expect("just chosen");
            let (blob, peer_index) = state.waiting.pop_front().expect("it has a waiting blob");
            let peer = state.peers[peer_index];
            let (e3, sender) = (state.e3, state.sender);
            let ticket = self.next_ticket;
            self.next_ticket += 1;
            self.active_bytes += blob.len;
            *self.per_peer.entry(peer).or_default() += 1;
            *self.per_sender.entry(sender).or_default() += 1;
            let running = Ticket {
                fetch,
                sender,
                blob,
                peer_index,
                peer,
            };
            self.tickets.insert(ticket, running);
            reads.push(Read {
                ticket,
                e3,
                hash: blob.hash,
                peer,
            });
        }
        reads
    }

    /// The fetch whose next blob can run, of the sender with the fewest reads running.
    fn next_fetch_to_read(&self) -> Option<u64> {
        self.fetches
            .iter()
            .filter(|(_, fetch)| {
                fetch.waiting.front().is_some_and(|(blob, peer_index)| {
                    let peer = fetch.peers[*peer_index];
                    self.active_bytes.saturating_add(blob.len) <= MAX_ACTIVE_BYTES
                        && self.per_peer.get(&peer).copied().unwrap_or_default()
                            < MAX_ACTIVE_PER_PEER
                })
            })
            .min_by_key(|(number, fetch)| {
                let running = self.per_sender.get(&fetch.sender).copied();
                (running.unwrap_or_default(), **number)
            })
            .map(|(number, _)| *number)
    }

    /// The blob a running read asks for, while its fetch is on its way.
    pub(crate) fn expected(&self, ticket: u64) -> Option<(E3Id, BlobRef)> {
        let running = self.tickets.get(&ticket)?;
        Some((self.fetches.get(&running.fetch)?.e3, running.blob))
    }

    fn release(&mut self, ticket: u64) -> Option<Ticket<P>> {
        let running = self.tickets.remove(&ticket)?;
        self.active_bytes -= running.blob.len;
        if let Some(count) = self.per_peer.get_mut(&running.peer) {
            *count -= 1;
            if *count == 0 {
                self.per_peer.remove(&running.peer);
            }
        }
        if let Some(count) = self.per_sender.get_mut(&running.sender) {
            *count -= 1;
            if *count == 0 {
                self.per_sender.remove(&running.sender);
            }
        }
        Some(running)
    }

    /// The read's blob is in the store.
    pub(crate) fn stored(&mut self, ticket: u64) {
        let Some(running) = self.release(ticket) else {
            return;
        };
        let Some(fetch) = self.fetches.get_mut(&running.fetch) else {
            return;
        };
        fetch.outstanding -= 1;
        if fetch.outstanding == 0 {
            self.finish(running.fetch, Ok(()));
        }
    }

    /// The read's peer could not give the blob: the next one gets its turn, or the fetch ends.
    pub(crate) fn failed(&mut self, ticket: u64) {
        let Some(running) = self.release(ticket) else {
            return;
        };
        let Some(fetch) = self.fetches.get_mut(&running.fetch) else {
            return;
        };
        let next = running.peer_index + 1;
        if next < fetch.peers.len() {
            fetch.waiting.push_front((running.blob, next));
        } else {
            self.finish(running.fetch, Err(NetworkError::Unavailable));
        }
    }

    /// Storing a blob failed, which no other peer can change.
    pub(crate) fn abort(&mut self, ticket: u64, failure: NetworkError) {
        if let Some(running) = self.release(ticket) {
            self.finish(running.fetch, Err(failure));
        }
    }

    /// Ends the fetches that have run too long.
    pub(crate) fn expire(&mut self, now: Instant) {
        let late: Vec<u64> = self
            .fetches
            .iter()
            .filter(|(_, fetch)| now.saturating_duration_since(fetch.started) >= LONGEST_FETCH)
            .map(|(number, _)| *number)
            .collect();
        for fetch in late {
            self.finish(fetch, Err(NetworkError::Unavailable));
        }
    }

    fn finish(&mut self, number: u64, result: Result<(), NetworkError>) {
        let Some(fetch) = self.fetches.remove(&number) else {
            return;
        };
        self.of_message.remove(&fetch.id);
        // Reads still running keep their place: their bytes are still coming.
        for done in fetch.done {
            let _ = done.send(result.clone());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use e3_protocol::{
        dkg::DkgMessage,
        node::Body,
        testing::{address, e3},
    };
    use tokio::sync::oneshot::Receiver;

    fn blob(n: u64, len: u64) -> BlobRef {
        BlobRef {
            hash: B256::from(alloy_primitives::U256::from(n)),
            len,
        }
    }

    /// A distinct message from `sender`, named by `n`.
    fn message(sender: u64, n: u8) -> PeerMessage {
        let member = alloy_primitives::Address::repeat_byte(n);
        PeerMessage {
            e3: e3(1),
            sender: address(sender),
            body: Body::Dkg(DkgMessage::Ready(vec![e3_protocol::dkg::Dealer {
                member,
                contribution: B256::ZERO,
            }])),
        }
    }

    fn add(
        fetcher: &mut Fetcher<u8>,
        sender: u64,
        n: u8,
        blobs: Vec<BlobRef>,
        peers: Vec<u8>,
    ) -> Receiver<Result<(), NetworkError>> {
        let (done, result) = oneshot::channel();
        let wanted = Wanted {
            message: message(sender, n),
            missing: blobs,
            peers,
        };
        fetcher.add(wanted, done, Instant::now());
        result
    }

    fn blobs(start: u64, count: u64) -> Vec<BlobRef> {
        (start..start + count).map(|n| blob(n, 10)).collect()
    }

    #[test]
    fn at_most_eight_reads_run_and_a_peer_gets_at_most_two() {
        let mut fetcher = Fetcher::default();
        add(&mut fetcher, 1, 1, blobs(0, 20), vec![9]);
        assert_eq!(fetcher.next_reads().len(), MAX_ACTIVE_PER_PEER);
        for peer in 10..20 {
            add(
                &mut fetcher,
                1,
                peer,
                blobs(100 + peer as u64 * 100, 20),
                vec![peer],
            );
        }
        assert_eq!(fetcher.next_reads().len(), MAX_ACTIVE - MAX_ACTIVE_PER_PEER);
        assert!(fetcher.next_reads().is_empty());
    }

    /// A member with a lot to send cannot make the node read only its blobs.
    #[test]
    fn the_sender_with_the_fewest_reads_running_goes_next() {
        let mut fetcher = Fetcher::default();
        add(&mut fetcher, 1, 1, blobs(0, 20), vec![1, 2, 3, 4]);
        let mut first = fetcher.next_reads();
        assert_eq!(first.len(), MAX_ACTIVE_PER_PEER);
        let (done, _result) = oneshot::channel();
        let quiet = Wanted {
            message: message(2, 2),
            missing: blobs(50, 1),
            peers: vec![7],
        };
        fetcher.add(quiet, done, Instant::now());
        let ticket = first.pop().unwrap().ticket;
        fetcher.stored(ticket);
        let next = fetcher.next_reads();
        assert_eq!(next[0].peer, 7, "the sender with none running goes first");
    }

    #[test]
    fn bytes_count_only_while_a_read_runs() {
        let mut fetcher: Fetcher<u8> = Fetcher::default();
        let big = MAX_ACTIVE_BYTES / 2 + 1;
        let (a, b) = (blob(1, big), blob(2, big));
        add(&mut fetcher, 1, 1, vec![a], vec![1]);
        add(&mut fetcher, 2, 2, vec![b], vec![2]);
        let reads = fetcher.next_reads();
        assert_eq!(reads.len(), 1, "both would pass the limit");
        fetcher.stored(reads[0].ticket);
        assert_eq!(fetcher.next_reads().len(), 1, "room came back");
    }

    #[tokio::test]
    async fn a_failed_read_asks_the_next_peer_then_ends_the_fetch() {
        let mut fetcher = Fetcher::default();
        let result = add(&mut fetcher, 1, 1, blobs(0, 1), vec![1, 2]);
        let first = fetcher.next_reads();
        assert_eq!(first[0].peer, 1);
        fetcher.failed(first[0].ticket);
        let second = fetcher.next_reads();
        assert_eq!(second[0].peer, 2);
        fetcher.failed(second[0].ticket);
        assert!(matches!(
            result.await.unwrap(),
            Err(NetworkError::Unavailable)
        ));
        assert!(fetcher.next_reads().is_empty());
    }

    #[tokio::test]
    async fn every_blob_stored_ends_the_fetch() {
        let mut fetcher = Fetcher::default();
        let result = add(&mut fetcher, 1, 1, blobs(0, 2), vec![1]);
        for read in fetcher.next_reads() {
            fetcher.stored(read.ticket);
        }
        result.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn another_caller_joins_a_fetch_on_its_way() {
        let mut fetcher: Fetcher<u8> = Fetcher::default();
        let first = add(&mut fetcher, 1, 1, blobs(0, 1), vec![1]);
        let (done, second) = oneshot::channel();
        let id = message(1, 1).id();
        assert!(fetcher.join(&id, done).is_none());
        let reads = fetcher.next_reads();
        fetcher.stored(reads[0].ticket);
        first.await.unwrap().unwrap();
        second.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn a_fetch_too_long_in_the_queue_ends_and_frees_its_reads() {
        let mut fetcher = Fetcher::default();
        let started = Instant::now();
        let result = add(&mut fetcher, 1, 1, blobs(0, 1), vec![1]);
        let reads = fetcher.next_reads();
        fetcher.expire(started + LONGEST_FETCH + Duration::from_secs(1));
        assert!(matches!(
            result.await.unwrap(),
            Err(NetworkError::Unavailable)
        ));
        fetcher.stored(reads[0].ticket);
        add(&mut fetcher, 2, 2, blobs(10, 8), vec![1, 2, 3, 4]);
        assert_eq!(fetcher.next_reads().len(), MAX_ACTIVE_PER_PEER);
    }

    #[tokio::test]
    async fn a_message_that_names_too_much_is_refused() {
        let mut fetcher = Fetcher::default();
        for missing in [
            blobs(0, MAX_BLOBS as u64 + 1),
            vec![blob(1, MAX_MESSAGE_BYTES + 1)],
        ] {
            let (done, result) = oneshot::channel();
            let wanted = Wanted {
                message: message(1, 1),
                missing,
                peers: vec![1u8],
            };
            fetcher.add(wanted, done, Instant::now());
            assert!(matches!(result.await.unwrap(), Err(NetworkError::Busy)));
        }
    }
}
