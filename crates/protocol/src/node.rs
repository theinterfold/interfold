// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! The whole node as one machine: admission of E3s from chain facts, routing of peer messages,
//! and the end of each E3's work.

use crate::{
    dkg::{Dkg, DkgMessage},
    E3Id, Machine, Tick, UnixSecs,
};
use alloy_primitives::Address;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, VecDeque};

/// A failed E3 that may still see accusations keeps its work for this long after the failure,
/// plus the chain's maximum vote validity: longer than the DKG and decryption windows in which
/// peers can still accuse, plus five minutes for votes.
const SLASHABLE_FAILURE_GRACE: UnixSecs = 24 * 60 * 60 + 5 * 60;

/// How many ended E3s the node remembers, to drop late peer messages for them.
const ENDED_MEMORY: usize = 1_024;

/// Where a chain fact sits in its chain's confirmed log.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct LogPosition {
    pub chain_id: u64,
    pub block: u64,
    pub log_index: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Stage {
    Requested,
    CommitteeFinalized,
    KeyPublished,
    CiphertextReady,
    Complete,
    Failed,
}

/// The contract's `FailureReason`, in declaration order.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FailureReason {
    None,
    CommitteeFormationTimeout,
    InsufficientCommitteeMembers,
    DkgTimeout,
    DkgInvalidShares,
    NoInputsReceived,
    ComputeTimeout,
    ComputeProviderExpired,
    ComputeProviderFailed,
    RequesterCancelled,
    DecryptionTimeout,
    DecryptionInvalidShares,
    VerificationFailed,
}

impl FailureReason {
    /// A deadline passed or the request was withdrawn; no peer acted against the protocol, so no
    /// accusation can follow.
    fn ends_without_slashing(self) -> bool {
        matches!(
            self,
            Self::CommitteeFormationTimeout
                | Self::DkgTimeout
                | Self::ComputeTimeout
                | Self::DecryptionTimeout
                | Self::NoInputsReceived
                | Self::ComputeProviderExpired
                | Self::ComputeProviderFailed
                | Self::RequesterCancelled
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChainFact {
    E3Requested {
        e3: E3Id,
    },
    CommitteeFinalized {
        e3: E3Id,
        members: Vec<Address>,
    },
    StageChanged {
        e3: E3Id,
        stage: Stage,
    },
    Failed {
        e3: E3Id,
        reason: FailureReason,
    },
    /// The chain's maximum accusation vote validity, in seconds.
    VoteValidity {
        secs: u64,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainEvent {
    pub at: LogPosition,
    pub fact: ChainFact,
}

/// A message from a peer. The network edge has already recovered `sender` from its signature.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerMessage {
    pub e3: E3Id,
    pub sender: Address,
    pub body: Body,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Body {
    Dkg(DkgMessage),
}

impl PeerMessage {
    fn size(&self) -> u64 {
        match &self.body {
            Body::Dkg(message) => message.size(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Input {
    Chain(ChainEvent),
    Peer(PeerMessage),
    Tick,
}

impl From<Tick> for Input {
    fn from(_: Tick) -> Self {
        Input::Tick
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Effect {}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct E3 {
    pub stage: Stage,
    /// The finalized committee, ascending by address; a party's ID is its index.
    pub members: Option<Vec<Address>>,
    /// When a failed E3's accusation work ends.
    pub ends_at: Option<UnixSecs>,
    pub dkg: Dkg,
}

impl E3 {
    fn new() -> Self {
        Self {
            stage: Stage::Requested,
            members: None,
            ends_at: None,
            dkg: Dkg::default(),
        }
    }

    fn receive(&mut self, message: PeerMessage) {
        if self.stage == Stage::Failed {
            return;
        }
        match message.body {
            Body::Dkg(body) => self.dkg.receive(message.sender, body),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Node {
    me: Address,
    e3s: BTreeMap<E3Id, E3>,
    held: Hold,
    ended: VecDeque<E3Id>,
    applied: BTreeMap<u64, LogPosition>,
    vote_validity: BTreeMap<u64, u64>,
}

impl Node {
    pub fn new(me: Address) -> Self {
        Self {
            me,
            e3s: BTreeMap::new(),
            held: Hold::default(),
            ended: VecDeque::new(),
            applied: BTreeMap::new(),
            vote_validity: BTreeMap::new(),
        }
    }

    pub fn e3(&self, e3: &E3Id) -> Option<&E3> {
        self.e3s.get(e3)
    }

    fn apply_chain(&mut self, now: UnixSecs, event: ChainEvent) {
        // The chain adapter delivers each chain's confirmed log in order; a position at or before
        // the last applied one is a re-read of the same history.
        if self
            .applied
            .get(&event.at.chain_id)
            .is_some_and(|last| event.at <= *last)
        {
            return;
        }
        self.applied.insert(event.at.chain_id, event.at);
        match event.fact {
            ChainFact::E3Requested { e3 } => self.admit(e3),
            ChainFact::CommitteeFinalized { e3, mut members } => {
                members.sort();
                members.dedup();
                if members.binary_search(&self.me).is_err() {
                    self.end(e3);
                } else if let Some(state) = self.e3s.get_mut(&e3) {
                    state.dkg.keep_only(&members);
                    state.members = Some(members);
                    state.stage = Stage::CommitteeFinalized;
                }
            }
            ChainFact::StageChanged { e3, stage } => match stage {
                Stage::Complete => self.end(e3),
                stage => {
                    if let Some(state) = self.e3s.get_mut(&e3) {
                        state.stage = stage;
                    }
                }
            },
            ChainFact::Failed { e3, reason } => {
                if reason.ends_without_slashing() {
                    self.end(e3);
                } else if let Some(state) = self.e3s.get_mut(&e3) {
                    let vote_validity = self
                        .vote_validity
                        .get(&event.at.chain_id)
                        .copied()
                        .unwrap_or_default();
                    state.stage = Stage::Failed;
                    state.ends_at = Some(now + SLASHABLE_FAILURE_GRACE + vote_validity);
                }
            }
            ChainFact::VoteValidity { secs } => {
                self.vote_validity.insert(event.at.chain_id, secs);
            }
        }
    }

    fn admit(&mut self, e3: E3Id) {
        if self.e3s.contains_key(&e3) || self.ended.contains(&e3) {
            return;
        }
        let mut state = E3::new();
        for message in self.held.take(&e3) {
            state.receive(message);
        }
        self.e3s.insert(e3, state);
    }

    fn end(&mut self, e3: E3Id) {
        if self.e3s.remove(&e3).is_none() {
            return;
        }
        self.held.take(&e3);
        self.ended.push_back(e3);
        if self.ended.len() > ENDED_MEMORY {
            self.ended.pop_front();
        }
    }

    fn apply_peer(&mut self, message: PeerMessage) {
        if self.ended.contains(&message.e3) {
            return;
        }
        match self.e3s.get_mut(&message.e3) {
            Some(state) => state.receive(message),
            None => self.held.hold(message),
        }
    }

    fn apply_tick(&mut self, now: UnixSecs) {
        let due: Vec<E3Id> = self
            .e3s
            .iter()
            .filter(|(_, state)| state.ends_at.is_some_and(|at| at <= now))
            .map(|(e3, _)| *e3)
            .collect();
        for e3 in due {
            self.end(e3);
        }
    }
}

impl Machine for Node {
    type Input = Input;
    type Effect = Effect;

    fn step(&mut self, now: UnixSecs, input: Input) -> Vec<Effect> {
        match input {
            Input::Chain(event) => self.apply_chain(now, event),
            Input::Peer(message) => self.apply_peer(message),
            Input::Tick => self.apply_tick(now),
        }
        Vec::new()
    }

    fn next_deadline(&self) -> Option<UnixSecs> {
        self.e3s.values().filter_map(|state| state.ends_at).min()
    }
}

/// Peer messages for E3s the chain has not admitted yet, in arrival order. When a bound is full the
/// oldest goes first: the E3's oldest for the per-E3 bound, the oldest of all for the total.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
struct Hold {
    messages: VecDeque<PeerMessage>,
}

const HOLD_PER_E3_MESSAGES: usize = 512;
const HOLD_PER_E3_BYTES: u64 = 128 * 1024 * 1024;
const HOLD_TOTAL_MESSAGES: usize = 1_024;
const HOLD_TOTAL_BYTES: u64 = 256 * 1024 * 1024;

impl Hold {
    fn hold(&mut self, message: PeerMessage) {
        let size = message.size();
        if size > HOLD_PER_E3_BYTES {
            return;
        }
        while self
            .usage(Some(&message.e3))
            .is_full(HOLD_PER_E3_MESSAGES, HOLD_PER_E3_BYTES, size)
        {
            let oldest = self
                .messages
                .iter()
                .position(|held| held.e3 == message.e3)
                .expect("a full E3 holds a message");
            self.messages.remove(oldest);
        }
        while self
            .usage(None)
            .is_full(HOLD_TOTAL_MESSAGES, HOLD_TOTAL_BYTES, size)
        {
            self.messages.pop_front();
        }
        self.messages.push_back(message);
    }

    fn take(&mut self, e3: &E3Id) -> Vec<PeerMessage> {
        let (taken, kept) = self.messages.drain(..).partition(|held| &held.e3 == e3);
        self.messages = kept;
        taken.into()
    }

    fn usage(&self, e3: Option<&E3Id>) -> Usage {
        self.messages
            .iter()
            .filter(|held| e3.is_none_or(|e3| &held.e3 == e3))
            .fold(Usage::default(), |usage, held| Usage {
                messages: usage.messages + 1,
                bytes: usage.bytes + held.size(),
            })
    }
}

#[derive(Default)]
struct Usage {
    messages: usize,
    bytes: u64,
}

impl Usage {
    fn is_full(&self, max_messages: usize, max_bytes: u64, incoming: u64) -> bool {
        self.messages > 0 && (self.messages >= max_messages || self.bytes + incoming > max_bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::BlobRef;
    use alloy_primitives::{B256, U256};

    const ME: Address = Address::repeat_byte(0xaa);

    fn e3(number: u64) -> E3Id {
        E3Id {
            chain_id: 1,
            number: U256::from(number),
        }
    }

    fn sender(n: u64) -> Address {
        Address::left_padding_from(&n.to_be_bytes())
    }

    fn key(e3: E3Id, sender: Address, hash: u8) -> Input {
        Input::Peer(PeerMessage {
            e3,
            sender,
            body: Body::Dkg(DkgMessage::EncryptionKey(BlobRef {
                hash: B256::repeat_byte(hash),
                len: 10,
            })),
        })
    }

    fn chain(block: u64, fact: ChainFact) -> Input {
        Input::Chain(ChainEvent {
            at: LogPosition {
                chain_id: 1,
                block,
                log_index: 0,
            },
            fact,
        })
    }

    fn keys_of(node: &Node, id: E3Id) -> Vec<Address> {
        node.e3(&id).unwrap().dkg.keys().keys().copied().collect()
    }

    #[test]
    fn a_peer_message_never_creates_an_e3() {
        let mut node = Node::new(ME);
        node.step(0, key(e3(1), sender(1), 1));
        assert!(node.e3(&e3(1)).is_none());
    }

    #[test]
    fn held_messages_reach_the_e3_when_the_chain_admits_it() {
        let mut node = Node::new(ME);
        node.step(0, key(e3(1), sender(1), 1));
        node.step(0, key(e3(1), sender(1), 2));
        node.step(0, key(e3(1), sender(2), 3));
        node.step(0, chain(10, ChainFact::E3Requested { e3: e3(1) }));
        let keys = node.e3(&e3(1)).unwrap().dkg.keys();
        assert_eq!(keys.len(), 2);
        assert_eq!(keys[&sender(1)].hash, B256::repeat_byte(1));
    }

    #[test]
    fn a_full_e3_hold_drops_its_oldest_message() {
        let mut node = Node::new(ME);
        for n in 1..=513 {
            node.step(0, key(e3(1), sender(n), 1));
        }
        node.step(0, chain(10, ChainFact::E3Requested { e3: e3(1) }));
        let keys = keys_of(&node, e3(1));
        assert_eq!(keys.len(), 512);
        assert!(!keys.contains(&sender(1)));
    }

    #[test]
    fn a_full_hold_drops_the_oldest_message_of_any_e3() {
        let mut node = Node::new(ME);
        for n in 1..=512 {
            node.step(0, key(e3(1), sender(n), 1));
            node.step(0, key(e3(2), sender(n), 1));
        }
        node.step(0, key(e3(3), sender(1), 1));
        node.step(0, chain(10, ChainFact::E3Requested { e3: e3(1) }));
        let keys = keys_of(&node, e3(1));
        assert_eq!(keys.len(), 511);
        assert!(!keys.contains(&sender(1)));
    }

    #[test]
    fn a_chain_fact_read_again_changes_nothing() {
        let mut node = Node::new(ME);
        node.step(0, chain(10, ChainFact::E3Requested { e3: e3(1) }));
        let failure = chain(
            11,
            ChainFact::Failed {
                e3: e3(1),
                reason: FailureReason::DkgInvalidShares,
            },
        );
        node.step(100, failure.clone());
        node.step(500, failure);
        assert_eq!(node.next_deadline(), Some(100 + SLASHABLE_FAILURE_GRACE));
    }

    #[test]
    fn a_failure_without_slashing_ends_the_e3_at_once() {
        let mut node = Node::new(ME);
        node.step(0, chain(10, ChainFact::E3Requested { e3: e3(1) }));
        node.step(
            0,
            chain(
                11,
                ChainFact::Failed {
                    e3: e3(1),
                    reason: FailureReason::DkgTimeout,
                },
            ),
        );
        assert!(node.e3(&e3(1)).is_none());
    }

    #[test]
    fn a_slashable_failure_keeps_the_e3_until_the_grace_and_vote_validity_pass() {
        let mut node = Node::new(ME);
        node.step(0, chain(9, ChainFact::VoteValidity { secs: 600 }));
        node.step(0, chain(10, ChainFact::E3Requested { e3: e3(1) }));
        node.step(
            1_000,
            chain(
                11,
                ChainFact::Failed {
                    e3: e3(1),
                    reason: FailureReason::DkgInvalidShares,
                },
            ),
        );
        let deadline = 1_000 + SLASHABLE_FAILURE_GRACE + 600;
        assert_eq!(node.next_deadline(), Some(deadline));
        node.step(deadline - 1, Input::Tick);
        assert!(node.e3(&e3(1)).is_some());
        node.step(deadline, Input::Tick);
        assert!(node.e3(&e3(1)).is_none());
        assert_eq!(node.next_deadline(), None);
    }

    #[test]
    fn a_node_outside_the_committee_has_no_work_in_the_e3() {
        let mut node = Node::new(ME);
        node.step(0, chain(10, ChainFact::E3Requested { e3: e3(1) }));
        node.step(
            0,
            chain(
                11,
                ChainFact::CommitteeFinalized {
                    e3: e3(1),
                    members: vec![sender(1), sender(2)],
                },
            ),
        );
        assert!(node.e3(&e3(1)).is_none());
    }

    #[test]
    fn finalization_drops_what_non_members_sent() {
        let mut node = Node::new(ME);
        node.step(0, key(e3(1), sender(1), 1));
        node.step(0, key(e3(1), sender(9), 1));
        node.step(0, chain(10, ChainFact::E3Requested { e3: e3(1) }));
        node.step(
            0,
            chain(
                11,
                ChainFact::CommitteeFinalized {
                    e3: e3(1),
                    members: vec![sender(1), ME],
                },
            ),
        );
        assert_eq!(keys_of(&node, e3(1)), vec![sender(1)]);
    }

    #[test]
    fn a_late_message_for_an_ended_e3_takes_no_hold_space() {
        let mut node = Node::new(ME);
        node.step(0, chain(10, ChainFact::E3Requested { e3: e3(1) }));
        node.step(
            0,
            chain(
                11,
                ChainFact::StageChanged {
                    e3: e3(1),
                    stage: Stage::Complete,
                },
            ),
        );
        for n in 1..=512 {
            node.step(0, key(e3(2), sender(n), 1));
            node.step(0, key(e3(3), sender(n), 1));
        }
        node.step(0, key(e3(1), sender(1), 1));
        node.step(0, chain(12, ChainFact::E3Requested { e3: e3(2) }));
        assert_eq!(keys_of(&node, e3(2)).len(), 512);
    }
}
