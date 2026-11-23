// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Bounded hold for peer messages that arrive before the chain fact that lets the node judge them,
//! and bounded memory of ended E3 IDs. Both maintain O(1) in-memory indices while preserving the
//! exact bincode wire/snapshot layout of their underlying queues.

use crate::{node::PeerMessage, E3Id, UnixSecs};
use alloy_primitives::{Address, B256};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::collections::{HashMap, HashSet, VecDeque};

pub(crate) const HOLD_FOR: UnixSecs = 10 * 60;
pub(crate) const HOLD_PER_SENDER_MESSAGES: usize = 64;
const HOLD_PER_SENDER_BYTES: u64 = 128 * 1024 * 1024;
const HOLD_PER_E3_MESSAGES: usize = 512;
const HOLD_PER_E3_BYTES: u64 = 128 * 1024 * 1024;
const HOLD_TOTAL_MESSAGES: usize = 1_024;
const HOLD_TOTAL_BYTES: u64 = 256 * 1024 * 1024;

/// How many ended E3s the node remembers, to drop late peer messages for them.
const ENDED_MEMORY: usize = 1_024;

#[derive(Clone, Debug, Default, Eq)]
pub(crate) struct Ended {
    queue: VecDeque<E3Id>,
    set: HashSet<E3Id>,
}

impl PartialEq for Ended {
    fn eq(&self, other: &Self) -> bool {
        self.queue == other.queue
    }
}

impl Serialize for Ended {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.queue.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Ended {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let queue = VecDeque::<E3Id>::deserialize(deserializer)?;
        let set = queue.iter().copied().collect();
        Ok(Self { queue, set })
    }
}

impl Ended {
    pub(crate) fn contains(&self, e3: &E3Id) -> bool {
        self.set.contains(e3)
    }

    pub(crate) fn record(&mut self, e3: E3Id) {
        self.queue.push_back(e3);
        self.set.insert(e3);
        if self.queue.len() > ENDED_MEMORY {
            if let Some(evicted) = self.queue.pop_front() {
                if !self.queue.contains(&evicted) {
                    self.set.remove(&evicted);
                }
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct Held {
    message: PeerMessage,
    expires: UnixSecs,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Usage {
    messages: usize,
    bytes: u64,
}

impl Usage {
    fn fits(self, max_messages: usize, max_bytes: u64, incoming: u64) -> bool {
        self.messages < max_messages && self.bytes.saturating_add(incoming) <= max_bytes
    }

    fn add(&mut self, bytes: u64) {
        self.messages += 1;
        self.bytes = self.bytes.saturating_add(bytes);
    }

    fn sub(&mut self, bytes: u64) {
        self.messages = self.messages.saturating_sub(1);
        self.bytes = self.bytes.saturating_sub(bytes);
    }
}

/// Persisted layout of [`Hold`], kept identical to the original struct definition so snapshots
/// remain byte-for-byte compatible.
#[derive(Serialize, Deserialize)]
struct HoldRepr {
    messages: VecDeque<Held>,
}

/// Peer messages that wait for a chain fact, in arrival order. A message that would pass its
/// sender's, its E3's, or the node's share is refused, so no sender can push out another's: the
/// sender's re-send brings it again. A message that waits too long goes, so stale ones cannot
/// hold the room.
#[derive(Clone, Debug, Default, Eq)]
pub(crate) struct Hold {
    messages: VecDeque<Held>,
    /// Derived O(1) metadata aligned 1:1 with `messages`: `(id, size)`.
    meta: VecDeque<(B256, u64)>,
    ids: HashSet<B256>,
    per_sender: HashMap<Address, Usage>,
    per_e3: HashMap<E3Id, Usage>,
    total: Usage,
}

impl PartialEq for Hold {
    fn eq(&self, other: &Self) -> bool {
        self.messages == other.messages
    }
}

impl Serialize for Hold {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        HoldRepr {
            messages: self.messages.clone(),
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Hold {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let repr = HoldRepr::deserialize(deserializer)?;
        let mut hold = Self::default();
        for held in repr.messages {
            let id = held.message.id();
            let size = held.message.size();
            hold.index_add(&held.message, id, size);
            hold.messages.push_back(held);
            hold.meta.push_back((id, size));
        }
        Ok(hold)
    }
}

impl Hold {
    fn index_add(&mut self, message: &PeerMessage, id: B256, size: u64) {
        self.ids.insert(id);
        self.per_sender.entry(message.sender).or_default().add(size);
        self.per_e3.entry(message.e3).or_default().add(size);
        self.total.add(size);
    }

    fn index_remove(&mut self, message: &PeerMessage, id: B256, size: u64) {
        self.ids.remove(&id);
        if let Some(usage) = self.per_sender.get_mut(&message.sender) {
            usage.sub(size);
            if usage.messages == 0 {
                self.per_sender.remove(&message.sender);
            }
        }
        if let Some(usage) = self.per_e3.get_mut(&message.e3) {
            usage.sub(size);
            if usage.messages == 0 {
                self.per_e3.remove(&message.e3);
            }
        }
        self.total.sub(size);
    }

    /// Whether a copy of `message` waits here already: its re-sends cost nothing.
    pub(crate) fn holds(&self, message: &PeerMessage) -> bool {
        if self.messages.is_empty() {
            return false;
        }
        self.ids.contains(&message.id())
    }

    /// Whether every share `message` would count against has room for it.
    pub(crate) fn has_room(&self, message: &PeerMessage) -> bool {
        let size = message.size();
        let sender = self
            .per_sender
            .get(&message.sender)
            .copied()
            .unwrap_or_default();
        let e3 = self.per_e3.get(&message.e3).copied().unwrap_or_default();
        sender.fits(HOLD_PER_SENDER_MESSAGES, HOLD_PER_SENDER_BYTES, size)
            && e3.fits(HOLD_PER_E3_MESSAGES, HOLD_PER_E3_BYTES, size)
            && self.total.fits(HOLD_TOTAL_MESSAGES, HOLD_TOTAL_BYTES, size)
    }

    pub(crate) fn hold(&mut self, now: UnixSecs, message: PeerMessage) {
        let id = message.id();
        let size = message.size();
        self.index_add(&message, id, size);
        self.messages.push_back(Held {
            message,
            expires: now.saturating_add(HOLD_FOR),
        });
        self.meta.push_back((id, size));
    }

    pub(crate) fn take(&mut self, e3: &E3Id) -> Vec<PeerMessage> {
        if !self.per_e3.contains_key(e3) {
            return Vec::new();
        }
        let mut taken = Vec::new();
        let mut kept_messages = VecDeque::with_capacity(self.messages.len());
        let mut kept_meta = VecDeque::with_capacity(self.meta.len());
        while let (Some(held), Some((id, size))) =
            (self.messages.pop_front(), self.meta.pop_front())
        {
            if &held.message.e3 == e3 {
                self.index_remove(&held.message, id, size);
                taken.push(held.message);
            } else {
                kept_messages.push_back(held);
                kept_meta.push_back((id, size));
            }
        }
        self.messages = kept_messages;
        self.meta = kept_meta;
        taken
    }

    pub(crate) fn pass_deadlines(&mut self, now: UnixSecs) {
        if self.messages.is_empty() {
            return;
        }
        let mut kept_messages = VecDeque::with_capacity(self.messages.len());
        let mut kept_meta = VecDeque::with_capacity(self.meta.len());
        while let (Some(held), Some((id, size))) =
            (self.messages.pop_front(), self.meta.pop_front())
        {
            if now < held.expires {
                kept_messages.push_back(held);
                kept_meta.push_back((id, size));
            } else {
                self.index_remove(&held.message, id, size);
            }
        }
        self.messages = kept_messages;
        self.meta = kept_meta;
    }

    pub(crate) fn next_deadline(&self) -> Option<UnixSecs> {
        self.messages.iter().map(|held| held.expires).min()
    }
}
