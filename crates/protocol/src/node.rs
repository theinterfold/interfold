// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! The whole node as one machine: admission of E3s from chain facts, routing of peer messages,
//! jobs and signatures, and the end of each E3's work.

use crate::{
    dkg::{Dkg, DkgMessage, DkgSignature, DkgTiming, DkgWork, DkgWorkResult},
    E3Id, Machine, Tick, UnixSecs,
};
use alloy_primitives::{Address, Bytes, B256};
use e3_committee::CiphernodesCommitteeSize;
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
        committee_size: CiphernodesCommitteeSize,
    },
    CommitteeFinalized {
        e3: E3Id,
        members: Vec<Address>,
        dkg: DkgTiming,
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

/// A message between committee members. On receipt, the network edge has already recovered
/// `sender` from the envelope signature.
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

/// Work for the job runner. Its result returns as [`Input::Job`] and is journaled before anything
/// uses it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Job {
    pub e3: E3Id,
    pub work: Work,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Work {
    Dkg(DkgWork),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobDone {
    pub e3: E3Id,
    pub result: WorkResult,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum WorkResult {
    Dkg(DkgWorkResult),
}

/// A hash for the operator key to sign. The signature returns as [`Input::Signed`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Signing {
    pub e3: E3Id,
    pub purpose: Purpose,
    pub hash: B256,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Purpose {
    Dkg(DkgSignature),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Signed {
    pub e3: E3Id,
    pub purpose: Purpose,
    pub signature: Bytes,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Input {
    Chain(ChainEvent),
    Peer(PeerMessage),
    Job(JobDone),
    Signed(Signed),
    /// Wakes the machine at its next deadline. Every input first applies the deadlines that have
    /// passed, so a late wake-up changes nothing.
    Tick,
}

impl From<Tick> for Input {
    fn from(_: Tick) -> Self {
        Input::Tick
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Effect {
    Run(Job),
    Sign(Signing),
    Gossip(PeerMessage),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct E3 {
    pub stage: Stage,
    pub committee_size: CiphernodesCommitteeSize,
    /// From the committee's finalization on; a node outside the committee ends the E3 instead.
    pub dkg: Option<Dkg>,
    /// When a failed E3's accusation work ends.
    pub ends_at: Option<UnixSecs>,
}

impl E3 {
    fn new(committee_size: CiphernodesCommitteeSize) -> Self {
        Self {
            stage: Stage::Requested,
            committee_size,
            dkg: None,
            ends_at: None,
        }
    }

    /// The DKG runs from the committee's finalization until the chain fails the E3; after a
    /// failure only accusation work remains.
    fn dkg(&mut self) -> Option<&mut Dkg> {
        let running = self.running();
        self.dkg.as_mut().filter(|_| running)
    }

    fn running(&self) -> bool {
        self.stage != Stage::Failed
    }

    fn receive(&mut self, message: PeerMessage) -> Vec<Effect> {
        let Some(dkg) = self.dkg() else {
            return Vec::new();
        };
        match message.body {
            Body::Dkg(body) => dkg.receive(message.sender, body),
        }
    }

    fn next_deadline(&self) -> Option<UnixSecs> {
        let dkg = self.dkg.as_ref().filter(|_| self.running());
        self.ends_at
            .into_iter()
            .chain(dkg.and_then(Dkg::next_deadline))
            .min()
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

    fn apply_chain(&mut self, now: UnixSecs, event: ChainEvent) -> Vec<Effect> {
        // The chain adapter delivers each chain's confirmed log in order; a position at or before
        // the last applied one is a re-read of the same history.
        if self
            .applied
            .get(&event.at.chain_id)
            .is_some_and(|last| event.at <= *last)
        {
            return Vec::new();
        }
        self.applied.insert(event.at.chain_id, event.at);
        match event.fact {
            ChainFact::E3Requested { e3, committee_size } => self.admit(e3, committee_size),
            ChainFact::CommitteeFinalized {
                e3,
                mut members,
                dkg,
            } => {
                members.sort();
                members.dedup();
                if members.binary_search(&self.me).is_err() {
                    self.end(e3);
                    return Vec::new();
                }
                let Some(state) = self.e3s.get_mut(&e3) else {
                    return Vec::new();
                };
                let h = state.committee_size.values().h;
                let (dkg, mut effects) = Dkg::start(e3, self.me, members, h, dkg, now);
                state.dkg = Some(dkg);
                state.stage = Stage::CommitteeFinalized;
                for message in self.held.take(&e3) {
                    effects.extend(state.receive(message));
                }
                return effects;
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
        Vec::new()
    }

    fn admit(&mut self, e3: E3Id, committee_size: CiphernodesCommitteeSize) {
        if self.e3s.contains_key(&e3) || self.ended.contains(&e3) {
            return;
        }
        self.e3s.insert(e3, E3::new(committee_size));
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

    /// Until the chain names the committee nothing can say whether a sender may speak, so its
    /// messages wait in the bounded hold.
    fn apply_peer(&mut self, message: PeerMessage) -> Vec<Effect> {
        if self.ended.contains(&message.e3) {
            return Vec::new();
        }
        match self.e3s.get_mut(&message.e3) {
            Some(state) if state.dkg.is_some() => state.receive(message),
            _ => {
                self.held.hold(message);
                Vec::new()
            }
        }
    }

    fn apply_job(&mut self, done: JobDone) -> Vec<Effect> {
        let Some(dkg) = self.e3s.get_mut(&done.e3).and_then(E3::dkg) else {
            return Vec::new();
        };
        match done.result {
            WorkResult::Dkg(result) => dkg.job_done(result),
        }
    }

    fn apply_signed(&mut self, signed: Signed) -> Vec<Effect> {
        let Some(dkg) = self.e3s.get_mut(&signed.e3).and_then(E3::dkg) else {
            return Vec::new();
        };
        match signed.purpose {
            Purpose::Dkg(purpose) => dkg.signed(purpose, signed.signature),
        }
    }

    fn pass_deadlines(&mut self, now: UnixSecs) {
        for dkg in self.e3s.values_mut().filter_map(E3::dkg) {
            dkg.pass_deadlines(now);
        }
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
        self.pass_deadlines(now);
        match input {
            Input::Chain(event) => self.apply_chain(now, event),
            Input::Peer(message) => self.apply_peer(message),
            Input::Job(done) => self.apply_job(done),
            Input::Signed(signed) => self.apply_signed(signed),
            Input::Tick => Vec::new(),
        }
    }

    fn next_deadline(&self) -> Option<UnixSecs> {
        self.e3s.values().filter_map(E3::next_deadline).min()
    }
}

/// Peer messages for E3s whose committee the chain has not finalized yet, in arrival order. When a bound is full the
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
    use crate::testing::*;

    fn node() -> Node {
        Node::new(address(ME))
    }

    fn members(operators: impl IntoIterator<Item = u64>) -> Vec<Address> {
        operators.into_iter().chain([ME]).map(address).collect()
    }

    #[test]
    fn a_peer_message_never_creates_an_e3() {
        let mut node = node();
        node.step(0, key_from(e3(1), 1));
        assert!(node.e3(&e3(1)).is_none());
    }

    #[test]
    fn keys_sent_before_the_committee_is_known_are_checked_once_it_is() {
        let mut node = node();
        node.step(0, key_from(e3(1), 1));
        node.step(0, requested(10, e3(1)));
        node.step(0, key_from(e3(1), 2));
        let effects = node.step(0, finalized(11, e3(1), members([1, 2])));
        assert_eq!(key_checks(&effects), vec![address(1), address(2)]);
    }

    #[test]
    fn a_full_e3_hold_drops_its_oldest_message() {
        let mut node = node();
        for n in 1..=513 {
            node.step(0, key_from(e3(1), n));
        }
        node.step(0, requested(10, e3(1)));
        let checked = key_checks(&node.step(0, finalized(11, e3(1), members(1..=513))));
        assert_eq!(checked.len(), 512);
        assert!(!checked.contains(&address(1)));
    }

    #[test]
    fn a_full_hold_drops_the_oldest_message_of_any_e3() {
        let mut node = node();
        for n in 1..=512 {
            node.step(0, key_from(e3(1), n));
            node.step(0, key_from(e3(2), n));
        }
        node.step(0, key_from(e3(3), 1));
        node.step(0, requested(10, e3(1)));
        let checked = key_checks(&node.step(0, finalized(11, e3(1), members(1..=512))));
        assert_eq!(checked.len(), 511);
        assert!(!checked.contains(&address(1)));
    }

    #[test]
    fn a_chain_fact_read_again_changes_nothing() {
        let mut node = node();
        node.step(0, requested(10, e3(1)));
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
        let mut node = node();
        node.step(0, requested(10, e3(1)));
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
        let mut node = node();
        node.step(0, chain(9, ChainFact::VoteValidity { secs: 600 }));
        node.step(0, requested(10, e3(1)));
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
    fn after_a_slashable_failure_the_dkg_does_no_more_work() {
        let mut node = node();
        for (block, number) in [(10, 1), (12, 2)] {
            node.step(0, requested(block, e3(number)));
            node.step(0, finalized(block + 1, e3(number), members([1])));
        }
        let effects = node.step(0, key_made(e3(2), own_key(0xee)));
        let fail = |block, number| {
            chain(
                block,
                ChainFact::Failed {
                    e3: e3(number),
                    reason: FailureReason::DkgInvalidShares,
                },
            )
        };
        node.step(100, fail(20, 1));
        node.step(100, fail(21, 2));
        assert!(node.step(100, key_made(e3(1), own_key(0xee))).is_empty());
        assert!(node.step(100, sign(ME, signing(&effects))).is_empty());
        assert!(node.step(100, key_from(e3(2), 1)).is_empty());
        assert_eq!(node.next_deadline(), Some(100 + SLASHABLE_FAILURE_GRACE));
    }

    #[test]
    fn a_node_outside_the_committee_has_no_work_in_the_e3() {
        let mut node = node();
        node.step(0, requested(10, e3(1)));
        node.step(0, finalized(11, e3(1), vec![address(1), address(2)]));
        assert!(node.e3(&e3(1)).is_none());
    }

    #[test]
    fn finalization_drops_what_non_members_sent() {
        let mut node = node();
        node.step(0, key_from(e3(1), 1));
        node.step(0, key_from(e3(1), 9));
        node.step(0, requested(10, e3(1)));
        let effects = node.step(0, finalized(11, e3(1), members([1])));
        assert_eq!(key_checks(&effects), vec![address(1)]);
    }

    #[test]
    fn a_late_message_for_an_ended_e3_takes_no_hold_space() {
        let mut node = node();
        node.step(0, requested(10, e3(1)));
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
            node.step(0, key_from(e3(2), n));
            node.step(0, key_from(e3(3), n));
        }
        node.step(0, key_from(e3(1), 1));
        node.step(0, requested(12, e3(2)));
        let checked = key_checks(&node.step(0, finalized(13, e3(2), members(1..=512))));
        assert_eq!(checked.len(), 512);
    }
}
