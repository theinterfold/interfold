// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Which blob request to answer next. Blobs go only to the members of their E3's committee, each
//! with as many requests out as an honest node sends one peer, so the line is never longer than
//! the committees are small. A committee asks for its blobs all at once: past the places in use a
//! request waits its turn, so a burst slows down instead of failing.

use crate::fetcher::MAX_ACTIVE_PER_PEER;
use alloy_primitives::{Address, B256};
use e3_protocol::{wire::PeerProof, E3Id};
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, VecDeque},
    hash::Hash,
};

/// The blobs served at once, from the disk read until the peer has them. A member that stops
/// reading holds its places only until the request times out.
const MAX_SERVING: usize = 8;

/// A request for one public blob of an E3, and the requester's word for who it is.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct BlobRequest {
    pub(crate) e3: E3Id,
    pub(crate) hash: B256,
    pub(crate) requester: PeerProof,
}

struct Waiting<Id, Job> {
    id: Id,
    member: Address,
    job: Job,
}

/// Every request is in one of three places: the line, a disk read, or on its way to the peer.
pub(crate) struct Serving<Id, Job> {
    line: VecDeque<Waiting<Id, Job>>,
    reading: HashMap<Id, Address>,
    sending: HashMap<Id, Address>,
    asked_by: HashMap<Address, usize>,
}

impl<Id, Job> Default for Serving<Id, Job> {
    fn default() -> Self {
        Self {
            line: VecDeque::new(),
            reading: HashMap::new(),
            sending: HashMap::new(),
            asked_by: HashMap::new(),
        }
    }
}

impl<Id: Copy + Eq + Hash, Job> Serving<Id, Job> {
    /// Puts a member's request in line, or gives it back when the member has its share out.
    pub(crate) fn ask(&mut self, id: Id, member: Address, job: Job) -> Result<(), Job> {
        let asked = self.asked_by.entry(member).or_default();
        if *asked >= MAX_ACTIVE_PER_PEER {
            return Err(job);
        }
        *asked += 1;
        self.line.push_back(Waiting { id, member, job });
        Ok(())
    }

    /// The request whose disk read should start, while a place is free.
    pub(crate) fn next_turn(&mut self) -> Option<(Id, Job)> {
        if self.reading.len() + self.sending.len() >= MAX_SERVING {
            return None;
        }
        let Waiting { id, member, job } = self.line.pop_front()?;
        self.reading.insert(id, member);
        Some((id, job))
    }

    /// The disk read of `id` came back, and its response is on its way.
    pub(crate) fn read(&mut self, id: Id) {
        if let Some(member) = self.reading.remove(&id) {
            self.sending.insert(id, member);
        }
    }

    /// `id` is over: the peer has its response, or stopped waiting for it. A disk read under way
    /// keeps its place until it comes back, since its bytes are still being read.
    pub(crate) fn end(&mut self, id: Id) {
        let member = match self.line.iter().position(|waiting| waiting.id == id) {
            Some(place) => self.line.remove(place).map(|waiting| waiting.member),
            None => self.sending.remove(&id),
        };
        let Some(member) = member else {
            return;
        };
        if let Some(asked) = self.asked_by.get_mut(&member) {
            *asked -= 1;
            if *asked == 0 {
                self.asked_by.remove(&member);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use e3_protocol::testing::address;

    fn turns(serving: &mut Serving<u64, ()>) -> Vec<u64> {
        std::iter::from_fn(|| serving.next_turn().map(|(id, ())| id)).collect()
    }

    /// Eighteen members ask at once. None is refused; each gets its turn in the order asked.
    #[test]
    fn a_burst_past_the_places_waits_its_turn_in_order() {
        let mut serving = Serving::default();
        for id in 0..18 {
            assert!(serving.ask(id, address(id + 1), ()).is_ok());
        }
        assert_eq!(turns(&mut serving), (0..8).collect::<Vec<_>>());
        for id in 0..8 {
            serving.read(id);
            serving.end(id);
            assert_eq!(turns(&mut serving), [id + 8]);
        }
    }

    #[test]
    fn a_member_past_its_share_is_refused_until_one_of_its_requests_ends() {
        let mut serving = Serving::default();
        let member = address(1);
        assert!(serving.ask(1, member, ()).is_ok());
        assert!(serving.ask(2, member, ()).is_ok());
        assert!(serving.ask(3, member, ()).is_err());
        assert!(serving.ask(4, address(2), ()).is_ok(), "others still ask");

        assert_eq!(turns(&mut serving), [1, 2, 4]);
        serving.read(1);
        serving.end(1);
        assert!(serving.ask(3, member, ()).is_ok());
    }

    /// A peer that stopped waiting leaves the line, and its share comes back.
    #[test]
    fn a_request_given_up_in_line_is_never_served() {
        let mut serving = Serving::default();
        let member = address(1);
        for id in 0..8 {
            assert!(serving.ask(id, address(id + 10), ()).is_ok());
        }
        assert_eq!(turns(&mut serving).len(), 8);
        assert!(serving.ask(8, member, ()).is_ok());
        assert!(serving.ask(9, member, ()).is_ok());

        serving.end(8);
        assert!(serving.ask(10, member, ()).is_ok());
        serving.read(0);
        serving.end(0);
        assert_eq!(turns(&mut serving), [9]);
    }

    /// The bytes of a read under way are in memory, so its place is not free until it comes back.
    #[test]
    fn a_read_under_way_keeps_its_place_after_its_peer_gave_up() {
        let mut serving = Serving::default();
        for id in 0..9 {
            assert!(serving.ask(id, address(id + 1), ()).is_ok());
        }
        assert_eq!(turns(&mut serving).len(), 8);

        serving.end(0);
        assert!(turns(&mut serving).is_empty());

        serving.read(0);
        serving.end(0);
        assert_eq!(turns(&mut serving), [8]);
    }
}
