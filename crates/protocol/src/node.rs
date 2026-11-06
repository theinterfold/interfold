// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! The whole node as one machine: admission of E3s from chain facts, routing of peer messages,
//! jobs and signatures, and the end of each E3's work.

pub use crate::e3::E3;

use crate::{
    decryption::{
        DecryptionMessage, DecryptionSignature, DecryptionWork, DecryptionWorkResult,
        PlaintextPublication,
    },
    dkg::{
        AttestationContext, DkgMessage, DkgSignature, DkgTiming, DkgWork, DkgWorkResult,
        KeyPublication,
    },
    registry::Registry,
    selection::{candidate_owners, candidates},
    BlobRef, E3Id, Machine, Tick, UnixSecs,
};
use alloy_primitives::{Address, Bytes, B256, U256};
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

/// What a request fixed for its E3's cryptography. Every job gets it: the job runner maps the
/// contract's parameter set to BFV parameters and derives the error size from them and the
/// committee size; the seed is the E3's shared randomness.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CryptoParams {
    pub param_set: u8,
    pub committee_size: CiphernodesCommitteeSize,
    pub seed: B256,
}

/// What the registry froze for a request's committee selection (`CommitteeRequested`, and
/// `CommitteeBondOwnerCapEnabled` when the same transaction emits it).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommitteeRequest {
    /// T, the request's timestamp (the contracts call it `requestBlock`); selection reads the
    /// registry at T−1.
    pub time: UnixSecs,
    pub ticket_price: U256,
    /// The contract keeps one candidate per request-time bond owner.
    pub owner_cap: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChainFact {
    /// `interfold` is the contract that emitted `E3Requested`. The chain adapter takes
    /// `attestation` from the `DkgFoldAttestationContextEstablished` log that the same transaction
    /// emits just before it, and delivers no request whose crypto configuration this node does
    /// not support.
    E3Requested {
        e3: E3Id,
        params: CryptoParams,
        interfold: Address,
        attestation: AttestationContext,
        request: CommitteeRequest,
    },
    /// The registry accepted the request's randomness: the committee seed, and the deadline by
    /// which tickets must arrive. The chain adapter reads both from the registry at the
    /// fulfillment's block.
    SeedReady {
        e3: E3Id,
        seed: U256,
        committee_deadline: UnixSecs,
    },
    CommitteeFinalized {
        e3: E3Id,
        members: Vec<Address>,
        dkg: DkgTiming,
    },
    /// `CommitteeProofPublished`: the registry's committee in its order, the roster (the selected
    /// party IDs that the proof's public inputs carry), and the key commitment.
    KeyPublished {
        e3: E3Id,
        committee: Vec<Address>,
        roster: Vec<Address>,
        commitment: B256,
    },
    /// `CiphertextOutputReferencePublished`: where the ciphertext's bytes are, and the decryption
    /// deadline.
    CiphertextReady {
        e3: E3Id,
        ciphertext: DataRef,
        deadline: UnixSecs,
    },
    StageChanged {
        e3: E3Id,
        stage: Stage,
    },
    Failed {
        e3: E3Id,
        reason: FailureReason,
    },
    /// The chain slashed a committee member and removed it from the E3.
    MemberExpelled {
        e3: E3Id,
        member: Address,
    },
    /// The chain's maximum accusation vote validity, in seconds.
    VoteValidity {
        secs: u64,
    },
    /// `OperatorActivationChanged`.
    OperatorActive {
        operator: Address,
        active: bool,
    },
    /// `TicketBalanceUpdated`.
    TicketBalance {
        operator: Address,
        balance: U256,
    },
    /// `BondOwnerSet`.
    BondOwner {
        operator: Address,
        owner: Address,
    },
    /// A new eligibility configuration: every operator is inactive until it refreshes.
    EligibilityReset,
    /// Whether bond owners need an identity credential.
    IdentityPolicy {
        required: bool,
    },
}

/// Bytes the chain names by their Keccak-256 hash and an availability layer holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DataRef {
    pub hash: B256,
    /// The availability layer's block and blob leaf that hold the bytes.
    pub block: u32,
    pub leaf: u128,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainEvent {
    pub at: LogPosition,
    /// The block's timestamp.
    pub time: UnixSecs,
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
    Decryption(DecryptionMessage),
}

impl PeerMessage {
    fn size(&self) -> u64 {
        match &self.body {
            Body::Dkg(message) => message.size(),
            Body::Decryption(message) => message.size(),
        }
    }
}

/// Work for the job runner. Its result returns as [`Input::Job`] and is journaled before anything
/// uses it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Job {
    pub e3: E3Id,
    pub params: CryptoParams,
    pub work: Work,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Work {
    Dkg(DkgWork),
    Decryption(DecryptionWork),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobDone {
    pub e3: E3Id,
    pub result: WorkResult,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum WorkResult {
    Dkg(DkgWorkResult),
    Decryption(DecryptionWorkResult),
}

/// Hashes for the operator key to sign. The signatures return in the same order as
/// [`Input::Signed`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Signing {
    pub e3: E3Id,
    pub purpose: Purpose,
    pub hashes: Vec<B256>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Purpose {
    Dkg(DkgSignature),
    Decryption(DecryptionSignature),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Signed {
    pub e3: E3Id,
    pub purpose: Purpose,
    pub signatures: Vec<Bytes>,
}

/// Bytes for the fetcher to copy from their availability layer into the blob store, checked
/// against their hash. The blob returns as [`Input::Fetched`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Fetch {
    pub e3: E3Id,
    pub data: DataRef,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Fetched {
    pub e3: E3Id,
    pub blob: BlobRef,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Input {
    Chain(ChainEvent),
    Peer(PeerMessage),
    Job(JobDone),
    Signed(Signed),
    Fetched(Fetched),
    /// Wakes the machine at its next deadline. Every input first applies the deadlines that have
    /// passed, so a late wake-up changes nothing.
    Tick,
}

impl From<Tick> for Input {
    fn from(_: Tick) -> Self {
        Input::Tick
    }
}

/// A transaction for the chain writer, which checks chain state before it submits and retries
/// temporary failures.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Submission {
    pub e3: E3Id,
    pub transaction: Transaction,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Transaction {
    /// `publishCommittee`, then the key's chunks. Another aggregator's equal commitment completes
    /// it.
    PublishCommittee(KeyPublication),
    /// `publishPlaintextOutput`. Another aggregator's plaintext on chain completes it.
    PublishPlaintext(PlaintextPublication),
    /// This node's ticket for the committee.
    SubmitTicket { ticket: u64 },
    /// `finalizeCommittee`, after the committee deadline.
    FinalizeCommittee,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Effect {
    Run(Job),
    Sign(Signing),
    Gossip(PeerMessage),
    Submit(Submission),
    Fetch(Fetch),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Node {
    me: Address,
    e3s: BTreeMap<E3Id, E3>,
    /// Each chain's operator registry over time.
    registries: BTreeMap<u64, Registry>,
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
            registries: BTreeMap::new(),
            held: Hold::default(),
            ended: VecDeque::new(),
            applied: BTreeMap::new(),
            vote_validity: BTreeMap::new(),
        }
    }

    pub fn e3(&self, e3: &E3Id) -> Option<&E3> {
        self.e3s.get(e3)
    }

    /// The position of the last fact this node applied from chain `chain_id`.
    pub fn applied(&self, chain_id: u64) -> Option<LogPosition> {
        self.applied.get(&chain_id).copied()
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
        let (chain_id, time) = (event.at.chain_id, event.time);
        let registry = self.registries.entry(chain_id).or_default();
        match event.fact {
            ChainFact::E3Requested {
                e3,
                params,
                interfold,
                attestation,
                request,
            } => {
                if !self.e3s.contains_key(&e3) && !self.ended.contains(&e3) {
                    let state = E3::new(e3, self.me, params, interfold, attestation, request);
                    self.e3s.insert(e3, state);
                }
                Vec::new()
            }
            ChainFact::SeedReady {
                e3,
                seed,
                committee_deadline,
            } => self.select(now, e3, seed, committee_deadline),
            ChainFact::OperatorActive { operator, active } => {
                registry.set_active(time, operator, active);
                Vec::new()
            }
            ChainFact::TicketBalance { operator, balance } => {
                registry.set_balance(time, operator, balance);
                Vec::new()
            }
            ChainFact::BondOwner { operator, owner } => {
                registry.set_owner(time, operator, owner);
                Vec::new()
            }
            ChainFact::EligibilityReset => {
                registry.reset_activity(time);
                Vec::new()
            }
            ChainFact::IdentityPolicy { required } => {
                registry.set_identity_required(time, required);
                Vec::new()
            }
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
                let mut effects = state.finalize(now, members, dkg);
                effects.extend(self.release_held(now, e3));
                effects
            }
            ChainFact::KeyPublished {
                e3,
                committee,
                roster,
                commitment,
            } => {
                if let Some(state) = self.e3s.get_mut(&e3) {
                    state.key_published(committee, roster, commitment);
                }
                self.release_held(now, e3)
            }
            ChainFact::CiphertextReady {
                e3,
                ciphertext,
                deadline,
            } => match self.e3s.get_mut(&e3) {
                Some(state) => state.ciphertext_ready(now, ciphertext, deadline),
                None => Vec::new(),
            },
            ChainFact::StageChanged { e3, stage } => {
                match (stage, self.e3s.get_mut(&e3)) {
                    (Stage::Complete, _) => self.end(e3),
                    (stage, Some(state)) => state.stage = stage,
                    (_, None) => {}
                }
                Vec::new()
            }
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
                Vec::new()
            }
            ChainFact::MemberExpelled { e3, member } => match self.e3s.get_mut(&e3) {
                Some(state) => state.expel(now, member),
                None => Vec::new(),
            },
            ChainFact::VoteValidity { secs } => {
                self.vote_validity.insert(event.at.chain_id, secs);
                Vec::new()
            }
        }
    }

    /// Rank the request's candidates from the registry at T−1 and submit this node's ticket if it
    /// is one of them, before the committee deadline. Under a required identity policy the node
    /// cannot tell which owners hold a credential, so it ranks every eligible operator, and the
    /// contract rejects the others. A node takes at most as many E3s at once as it has tickets.
    fn select(
        &mut self,
        now: UnixSecs,
        e3: E3Id,
        seed: U256,
        committee_deadline: UnixSecs,
    ) -> Vec<Effect> {
        let active_jobs = self
            .e3s
            .values()
            .filter(|state| state.ticket().is_some())
            .count() as u64;
        let Some(state) = self.e3s.get(&e3) else {
            return Vec::new();
        };
        if state.ticket().is_some() || now >= committee_deadline {
            return Vec::new();
        }
        let request = state.request;
        let at = request.time.saturating_sub(1);
        let registry = self.registries.entry(e3.chain_id).or_default();
        let eligible = registry.eligible_at(at, request.ticket_price);
        let owner_cap = request.owner_cap && !registry.identity_required_at(at);
        let committee = state.params.committee_size.values();
        let owners = candidate_owners(committee.n, committee.threshold);
        let ranked = candidates(e3, seed, &eligible, owner_cap, owners);
        let tickets = eligible
            .iter()
            .find(|operator| operator.operator == self.me)
            .map_or(0, |operator| operator.tickets);
        let Some((rank, mine)) = ranked
            .iter()
            .enumerate()
            .find(|(_, candidate)| candidate.operator == self.me)
        else {
            return Vec::new();
        };
        if active_jobs >= tickets {
            return Vec::new();
        }
        let ticket = mine.ticket;
        match self.e3s.get_mut(&e3) {
            Some(state) => state.submit_ticket(ticket, rank, committee_deadline),
            None => Vec::new(),
        }
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

    /// A message waits in the bounded hold until the chain fact that lets the node judge it:
    /// the committee's finalization for the DKG, the key's publication for decryption.
    fn apply_peer(&mut self, now: UnixSecs, message: PeerMessage) -> Vec<Effect> {
        if self.ended.contains(&message.e3) {
            return Vec::new();
        }
        match self.e3s.get_mut(&message.e3) {
            Some(state) if state.routes(&message.body) => state.receive(now, message),
            _ => {
                self.held.hold(message);
                Vec::new()
            }
        }
    }

    fn release_held(&mut self, now: UnixSecs, e3: E3Id) -> Vec<Effect> {
        let held = self.held.take(&e3);
        held.into_iter()
            .flat_map(|message| self.apply_peer(now, message))
            .collect()
    }

    fn apply_job(&mut self, now: UnixSecs, done: JobDone) -> Vec<Effect> {
        match self.e3s.get_mut(&done.e3) {
            Some(state) => state.job_done(now, done.result),
            None => Vec::new(),
        }
    }

    fn apply_signed(&mut self, now: UnixSecs, signed: Signed) -> Vec<Effect> {
        match self.e3s.get_mut(&signed.e3) {
            Some(state) => state.signed(now, signed.purpose, signed.signatures),
            None => Vec::new(),
        }
    }

    fn pass_deadlines(&mut self, now: UnixSecs) -> Vec<Effect> {
        let effects = self
            .e3s
            .values_mut()
            .flat_map(|state| state.pass_deadlines(now))
            .collect();
        let due: Vec<E3Id> = self
            .e3s
            .iter()
            .filter(|(_, state)| state.ends_at.is_some_and(|at| at <= now))
            .map(|(e3, _)| *e3)
            .collect();
        for e3 in due {
            self.end(e3);
        }
        effects
    }
}

impl Machine for Node {
    type Input = Input;
    type Effect = Effect;

    fn step(&mut self, now: UnixSecs, input: Input) -> Vec<Effect> {
        let mut effects = self.pass_deadlines(now);
        effects.extend(match input {
            Input::Chain(event) => self.apply_chain(now, event),
            Input::Peer(message) => self.apply_peer(now, message),
            Input::Job(done) => self.apply_job(now, done),
            Input::Signed(signed) => self.apply_signed(now, signed),
            Input::Fetched(fetched) => match self.e3s.get_mut(&fetched.e3) {
                Some(state) => state.fetched(now, fetched.blob),
                None => Vec::new(),
            },
            Input::Tick => Vec::new(),
        });
        effects
    }

    fn next_deadline(&self) -> Option<UnixSecs> {
        self.e3s.values().filter_map(E3::next_deadline).min()
    }
}

/// Peer messages that wait for a chain fact, in arrival order. When a bound is full the
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
    use crate::{selection::Eligible, testing::*};

    fn node() -> Node {
        Node::new(address(ME))
    }

    fn members(operators: impl IntoIterator<Item = u64>) -> Vec<Address> {
        operators.into_iter().chain([ME]).map(address).collect()
    }

    /// Operators active from timestamp 0 with `balance` tokens (tickets at one token each), each
    /// its own bond owner.
    fn registered(node: &mut Node, operators: &[u64], balance: u64) {
        for (index, operator) in operators.iter().enumerate() {
            let facts = [
                ChainFact::OperatorActive {
                    operator: address(*operator),
                    active: true,
                },
                ChainFact::TicketBalance {
                    operator: address(*operator),
                    balance: U256::from(balance),
                },
                ChainFact::BondOwner {
                    operator: address(*operator),
                    owner: address(*operator),
                },
            ];
            for (offset, fact) in facts.into_iter().enumerate() {
                let at = LogPosition {
                    chain_id: 1,
                    block: 0,
                    log_index: (3 * index + offset) as u64,
                };
                node.step(0, Input::Chain(ChainEvent { at, time: 0, fact }));
            }
        }
    }

    /// A request at timestamp `time`, so selection reads the registry at `time - 1`.
    fn requested_at(block: u64, e3: E3Id, time: UnixSecs) -> Input {
        chain(
            block,
            ChainFact::E3Requested {
                e3,
                params: params(e3_committee::CiphernodesCommitteeSize::Minimum),
                interfold: INTERFOLD,
                attestation: ATTESTATION,
                request: CommitteeRequest { time, ..REQUEST },
            },
        )
    }

    fn seed_ready(block: u64, e3: E3Id, seed: u64, committee_deadline: UnixSecs) -> Input {
        chain(
            block,
            ChainFact::SeedReady {
                e3,
                seed: U256::from(seed),
                committee_deadline,
            },
        )
    }

    fn submissions(effects: &[Effect]) -> Vec<Transaction> {
        effects
            .iter()
            .filter_map(|effect| match effect {
                Effect::Submit(submission) => Some(submission.transaction.clone()),
                _ => None,
            })
            .collect()
    }

    /// This node's rank and best ticket among `operators` for `seed`, as every node ranks them.
    fn rank(operators: &[u64], seed: u64, owner_cap: bool) -> Option<(usize, u64)> {
        let eligible: Vec<Eligible> = operators
            .iter()
            .map(|operator| Eligible {
                operator: address(*operator),
                tickets: 10,
                owner: Some(address(*operator)),
            })
            .collect();
        let owners = candidate_owners(3, 1);
        let ranked = candidates(e3(1), U256::from(seed), &eligible, owner_cap, owners);
        ranked
            .iter()
            .enumerate()
            .find(|(_, candidate)| candidate.operator == address(ME))
            .map(|(rank, candidate)| (rank, candidate.ticket))
    }

    #[test]
    fn a_selected_node_submits_its_best_ticket_before_the_committee_deadline() {
        let mut node = node();
        registered(&mut node, &[1, 2, ME], 10);
        node.step(1, requested(1, e3(1)));
        let effects = node.step(5, seed_ready(5, e3(1), 42, 100));
        let (_, ticket) = rank(&[1, 2, ME], 42, true).unwrap();
        assert_eq!(
            submissions(&effects),
            vec![Transaction::SubmitTicket { ticket }]
        );
    }

    #[test]
    fn a_node_inactive_at_the_request_submits_nothing() {
        let mut node = node();
        registered(&mut node, &[1, 2, ME], 10);
        node.step(1, chain(1, ChainFact::EligibilityReset));
        node.step(3, requested_at(3, e3(1), 3));
        assert!(submissions(&node.step(5, seed_ready(5, e3(1), 42, 100))).is_empty());
    }

    #[test]
    fn a_change_in_the_request_s_own_block_does_not_count() {
        let mut node = node();
        registered(&mut node, &[1, 2], 10);
        let activation = LogPosition {
            chain_id: 1,
            block: 3,
            log_index: 0,
        };
        let facts = [
            ChainFact::OperatorActive {
                operator: address(ME),
                active: true,
            },
            ChainFact::TicketBalance {
                operator: address(ME),
                balance: U256::from(10),
            },
            ChainFact::BondOwner {
                operator: address(ME),
                owner: address(ME),
            },
        ];
        for (log_index, fact) in (1..).zip(facts) {
            let at = LogPosition {
                log_index,
                ..activation
            };
            node.step(3, Input::Chain(ChainEvent { at, time: 3, fact }));
        }
        let request = LogPosition {
            log_index: 9,
            ..activation
        };
        let fact = match requested_at(3, e3(1), 3) {
            Input::Chain(event) => event.fact,
            _ => unreachable!(),
        };
        node.step(
            3,
            Input::Chain(ChainEvent {
                at: request,
                time: 3,
                fact,
            }),
        );
        assert!(submissions(&node.step(5, seed_ready(5, e3(1), 42, 100))).is_empty());
    }

    #[test]
    fn a_seed_after_the_committee_deadline_submits_nothing() {
        let mut node = node();
        registered(&mut node, &[1, 2, ME], 10);
        node.step(1, requested(1, e3(1)));
        assert!(submissions(&node.step(100, seed_ready(5, e3(1), 42, 100))).is_empty());
    }

    #[test]
    fn a_node_takes_at_most_as_many_e3s_at_once_as_it_has_tickets() {
        let mut node = node();
        registered(&mut node, &[1, 2, ME], 1);
        node.step(1, requested(1, e3(1)));
        node.step(1, requested(2, e3(2)));
        assert_eq!(
            submissions(&node.step(5, seed_ready(5, e3(1), 42, 100))).len(),
            1
        );
        assert!(submissions(&node.step(5, seed_ready(6, e3(2), 42, 100))).is_empty());
    }

    #[test]
    fn the_finalizer_calls_after_the_deadline_staggered_by_rank() {
        let seed = (0..1_000)
            .find(|seed| rank(&[1, 2, ME], *seed, true).is_some_and(|(rank, _)| rank > 0))
            .expect("a seed that ranks this node after another");
        let mut node = node();
        registered(&mut node, &[1, 2, ME], 10);
        node.step(1, requested(1, e3(1)));
        node.step(5, seed_ready(5, e3(1), seed, 100));
        let (rank, _) = rank(&[1, 2, ME], seed, true).unwrap();
        let due = 100 + 1 + 30 * rank as u64;
        assert_eq!(node.next_deadline(), Some(due));
        assert!(submissions(&node.step(due - 1, Input::Tick)).is_empty());
        let effects = node.step(due, Input::Tick);
        assert_eq!(submissions(&effects), vec![Transaction::FinalizeCommittee]);
        assert!(submissions(&node.step(due + 600, Input::Tick)).is_empty());
    }

    #[test]
    fn a_finalized_committee_stops_the_finalizer() {
        let mut node = node();
        registered(&mut node, &[1, 2, ME], 10);
        node.step(1, requested(1, e3(1)));
        node.step(5, seed_ready(5, e3(1), 42, 100));
        node.step(100, finalized(6, e3(1), members([1, 2])));
        assert!(submissions(&node.step(10_000, Input::Tick)).is_empty());
    }

    #[test]
    fn a_required_identity_policy_ranks_every_eligible_operator() {
        let operators: Vec<u64> = (1..=8).chain([ME]).collect();
        let seed = (0..1_000)
            .find(|seed| rank(&operators, *seed, true).is_none())
            .expect("a seed that leaves this node off the owner shortlist");
        let submits = |required: bool| {
            let mut node = node();
            registered(&mut node, &operators, 10);
            node.step(1, chain(1, ChainFact::IdentityPolicy { required }));
            node.step(3, requested_at(3, e3(1), 3));
            submissions(&node.step(5, seed_ready(5, e3(1), seed, 100))).len()
        };
        assert_eq!(submits(false), 0);
        assert_eq!(submits(true), 1);
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
    fn decryption_shares_wait_in_the_hold_until_the_key_is_published() {
        let mut node = node();
        node.step(0, requested(10, e3(1)));
        node.step(0, finalized(11, e3(1), members([1, 2])));
        node.step(0, decryption_shares(e3(1), 1, 1));
        let roster = vec![address(1), address(ME)];
        node.step(0, key_published(12, e3(1), members([1, 2]), roster));
        let decryption = node.e3(&e3(1)).and_then(|state| state.decryption.as_ref());
        assert!(decryption.is_some_and(|d| d.shares_of(&address(1)).is_some()));
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
