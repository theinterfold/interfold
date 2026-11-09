// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Runs v2 nodes in one process with virtual time, crashes, and network delays. Each node also
//! feeds a shadow copy of its machine that never crashes and never touches a store; the node must
//! always produce the same effects as its shadow and end in the same state.

mod jobs;
mod real_jobs;

pub use jobs::{Jobs, MockJobs};
pub use real_jobs::RealJobs;

use alloy_primitives::{Address, B256, U256};
use e3_engine::{EffectKey, Engine, MemoryStore, Pending};
use e3_protocol::{
    dkg::KeyAnchor,
    node::{
        ChainEvent, ChainFact, CryptoParams, DataRef, Effect, Eligibility, FailureReason, Fetched,
        Input, JobDone, LogPosition, Node, PeerMessage, Stage, Submission, Transaction,
    },
    selection::ticket_score,
    testing::{address, sign, COMPUTE_DEADLINE, TIMING},
    BlobRef, E3Id, Machine, UnixSecs,
};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha8Rng;
use std::collections::{BTreeMap, BTreeSet};

pub struct SimNode {
    operator: u64,
    store: MemoryStore,
    engine: Option<Engine<Node, MemoryStore>>,
    shadow: Node,
    snapshot_every: u64,
}

impl SimNode {
    /// The node of operator `operator`, as `e3_protocol::testing` numbers operators.
    pub fn new(operator: u64, snapshot_every: u64) -> Self {
        let store = MemoryStore::default();
        let (engine, _) = Engine::open(store.clone(), Node::new(address(operator)), snapshot_every)
            .expect("a fresh memory store opens");
        Self {
            operator,
            store,
            engine: Some(engine),
            shadow: Node::new(address(operator)),
            snapshot_every,
        }
    }

    pub fn apply(&mut self, now: UnixSecs, input: Input) -> Vec<Pending<Effect>> {
        let engine = self.engine.take().expect("the node is running");
        let (engine, pending) = engine
            .apply(now, input.clone())
            .expect("a memory store commits");
        let effects: Vec<_> = pending.iter().map(|p| p.effect.clone()).collect();
        assert_eq!(effects, self.shadow.step(now, input));
        self.engine = Some(engine);
        pending
    }

    pub fn acknowledge(&mut self, key: EffectKey) {
        self.engine
            .as_mut()
            .expect("the node is running")
            .acknowledge(key)
            .expect("a memory store acknowledges");
    }

    /// Drop the running engine without warning and open a new one on the same store. Returns the
    /// effects still pending.
    pub fn crash_and_restart(&mut self) -> Vec<Pending<Effect>> {
        self.engine = None;
        let genesis = Node::new(address(self.operator));
        let (engine, pending) = Engine::open(self.store.clone(), genesis, self.snapshot_every)
            .expect("the store reopens");
        self.engine = Some(engine);
        pending
    }

    pub fn node(&self) -> &Node {
        self.engine.as_ref().expect("the node is running").machine()
    }

    pub fn shadow(&self) -> &Node {
        &self.shadow
    }

    pub fn address(&self) -> Address {
        address(self.operator)
    }
}

/// The faults of a run.
#[derive(Clone, Copy, Debug)]
pub struct Faults {
    /// The chance that a node crashes before it applies an input, and again before it acts on the
    /// effects of one.
    pub crash: f64,
    /// Peer messages and job results take from one to this many seconds.
    pub max_delay: UnixSecs,
    /// The chance that a peer message arrives twice.
    pub duplicate: f64,
    /// The chance that a peer message never reaches a peer.
    pub drop: f64,
}

/// Nodes with an operator signer each, a job runner, one chain, and a network that delays,
/// reorders, duplicates, and drops peer messages.
pub struct Sim<J = MockJobs> {
    nodes: Vec<SimNode>,
    chain_lags: Vec<UnixSecs>,
    ticks: Vec<Option<UnixSecs>>,
    queue: BTreeMap<(UnixSecs, u64), Delivery>,
    next_delivery: u64,
    /// How many facts each block holds so far; a fact's block is its time, so later facts never
    /// sort before earlier ones.
    blocks: BTreeMap<UnixSecs, u64>,
    /// What the simulated contracts keep for each E3.
    requests: BTreeMap<E3Id, Request>,
    /// Facts by the time they are confirmed; the simulated contracts take each at its time.
    confirming: BTreeMap<UnixSecs, Vec<ChainFact>>,
    now: UnixSecs,
    rng: ChaCha8Rng,
    faults: Faults,
    gossip: Vec<PeerMessage>,
    submissions: Vec<Submission>,
    jobs: J,
    /// The earliest time the chain publishes an E3's ciphertext once its key is out.
    ciphertext_at: UnixSecs,
    /// The bytes the availability layer holds, by hash.
    available: BTreeMap<B256, BlobRef>,
}

struct Delivery {
    to: usize,
    input: Input,
    /// The node's own effect that this input answers. Such an input is lost when its node
    /// crashes, and the node's outbox runs the effect again.
    answers: Option<EffectKey>,
}

impl Sim {
    pub fn new(seed: u64, operators: &[u64], faults: Faults) -> Self {
        Self::with_jobs(seed, operators, faults, MockJobs::new(seed))
    }
}

impl<J: Jobs> Sim<J> {
    pub fn with_jobs(seed: u64, operators: &[u64], faults: Faults, jobs: J) -> Self {
        let mut rng = ChaCha8Rng::seed_from_u64(seed);
        let nodes = operators
            .iter()
            .map(|&operator| SimNode::new(operator, rng.random_range(1..=4)))
            .collect();
        Self {
            nodes,
            chain_lags: vec![0; operators.len()],
            ticks: vec![None; operators.len()],
            queue: BTreeMap::new(),
            next_delivery: 0,
            blocks: BTreeMap::new(),
            requests: BTreeMap::new(),
            confirming: BTreeMap::new(),
            now: 0,
            rng,
            faults,
            gossip: Vec::new(),
            submissions: Vec::new(),
            jobs,
            ciphertext_at: 0,
            available: BTreeMap::new(),
        }
    }

    pub fn set_ciphertext_at(&mut self, at: UnixSecs) {
        self.ciphertext_at = at;
    }

    pub fn jobs(&self) -> &J {
        &self.jobs
    }

    pub fn set_chain_lag(&mut self, node: usize, lag: UnixSecs) {
        self.chain_lags[node] = lag;
    }

    /// A fact confirmed at `at`, in its own block. Each node reads it after its chain lag.
    pub fn chain(&mut self, at: UnixSecs, fact: ChainFact) {
        let at = at.max(self.now);
        self.confirming.entry(at).or_default().push(fact.clone());
        let log_index = self.blocks.entry(at).or_default();
        let event = ChainEvent {
            at: LogPosition {
                chain_id: 1,
                block: at,
                log_index: *log_index,
            },
            time: at,
            fact,
        };
        *log_index += 1;
        for node in 0..self.nodes.len() {
            let input = Input::Chain(event.clone());
            self.schedule(at + self.chain_lags[node], node, input, None);
        }
    }

    /// Deliver everything due by `end`, in time order.
    pub fn run_until(&mut self, end: UnixSecs) {
        while let Some(entry) = self.queue.first_entry() {
            let (at, _) = *entry.key();
            if at > end {
                break;
            }
            let delivery = entry.remove();
            self.now = at;
            self.deliver(delivery);
        }
    }

    pub fn nodes(&self) -> &[SimNode] {
        &self.nodes
    }

    /// Every peer message the nodes sent, in sending order.
    pub fn gossip(&self) -> &[PeerMessage] {
        &self.gossip
    }

    /// Every transaction the nodes asked the chain writer for, in order.
    pub fn submissions(&self) -> &[Submission] {
        &self.submissions
    }

    /// The committee the chain finalized for `e3`, ascending.
    pub fn committee(&self, e3: &E3Id) -> Option<&[Address]> {
        self.requests.get(e3)?.committee.as_deref()
    }

    /// The members that slashes expelled from `e3`'s committee.
    pub fn expelled(&self, e3: &E3Id) -> Option<&BTreeSet<Address>> {
        Some(&self.requests.get(e3)?.expelled)
    }

    pub fn key_published(&self, e3: &E3Id) -> bool {
        self.requests
            .get(e3)
            .is_some_and(|request| request.key_published)
    }

    fn confirm(&mut self) {
        while let Some(entry) = self.confirming.first_entry() {
            if *entry.key() > self.now {
                break;
            }
            for fact in entry.remove() {
                if let ChainFact::E3Requested {
                    e3,
                    params,
                    committee_deadline,
                    ..
                } = &fact
                {
                    let request = Request::new(*params, *committee_deadline);
                    self.requests.insert(*e3, request);
                }
                if let Some(request) = fact_e3(&fact).and_then(|e3| self.requests.get_mut(&e3)) {
                    request.apply(&fact);
                }
            }
        }
    }

    fn deliver(&mut self, delivery: Delivery) {
        self.confirm();
        let node = delivery.to;
        if self.rng.random_bool(self.faults.crash) {
            self.crash(node);
            if delivery.answers.is_some() {
                return;
            }
        }
        let pending = self.nodes[node].apply(self.now, delivery.input);
        if self.rng.random_bool(self.faults.crash) {
            self.crash(node);
        } else {
            if let Some(effect) = delivery.answers {
                self.nodes[node].acknowledge(effect);
            }
            self.act(node, pending);
        }
        self.schedule_tick(node);
    }

    fn crash(&mut self, node: usize) {
        self.queue
            .retain(|_, delivery| delivery.to != node || delivery.answers.is_none());
        let pending = self.nodes[node].crash_and_restart();
        self.act(node, pending);
    }

    fn act(&mut self, node: usize, pending: Vec<Pending<Effect>>) {
        for Pending { key, effect } in pending {
            match effect {
                Effect::Run(job) => {
                    let done = Input::Job(JobDone {
                        e3: job.e3,
                        result: self.jobs.run(node, &job),
                    });
                    let at = self.now + self.delay();
                    self.schedule(at, node, done, Some(key));
                }
                Effect::Sign(signing) => {
                    let signed = sign(self.nodes[node].operator, &signing);
                    self.schedule(self.now, node, signed, Some(key));
                }
                Effect::Gossip(message) => {
                    self.nodes[node].acknowledge(key);
                    for peer in (0..self.nodes.len()).filter(|&peer| peer != node) {
                        if self.rng.random_bool(self.faults.drop) {
                            continue;
                        }
                        let copies = 1 + u32::from(self.rng.random_bool(self.faults.duplicate));
                        for _ in 0..copies {
                            let at = self.now + self.delay();
                            self.schedule(at, peer, Input::Announced(message.clone()), None);
                        }
                    }
                    self.gossip.push(message);
                }
                Effect::Submit(submission) => {
                    self.nodes[node].acknowledge(key);
                    self.submit(address(self.nodes[node].operator), submission);
                }
                Effect::FetchBlobs(fetch) => {
                    let at = self.now + self.delay();
                    self.schedule(at, node, Input::Peer(fetch.message), Some(key));
                }
                Effect::ReadEligibility(read) => {
                    let eligible = Some(read.operators.into_iter().collect());
                    let answer = Input::Eligibility(Eligibility {
                        e3: read.e3,
                        eligible,
                    });
                    let at = self.now + self.delay();
                    self.schedule(at, node, answer, Some(key));
                }
                Effect::Note(_) => self.nodes[node].acknowledge(key),
                Effect::Fetch(fetch) => {
                    let blob = self.available[&fetch.data.hash];
                    let fetched = Input::Fetched(Fetched { e3: fetch.e3, blob });
                    let at = self.now + self.delay();
                    self.schedule(at, node, fetched, Some(key));
                }
            }
        }
    }

    /// The simulated contracts: tickets count until the committee deadline; finalizing after it
    /// takes the N best scores, or fails the E3 with fewer; the first key and the first plaintext
    /// of an E3 count, as on chain once they are set.
    fn submit(&mut self, sender: Address, submission: Submission) {
        let e3 = submission.e3;
        let now = self.now;
        let Some(request) = self.requests.get_mut(&e3) else {
            return;
        };
        let fact = match &submission.transaction {
            Transaction::SubmitTicket { ticket } => {
                if now <= request.deadline {
                    let score = ticket_score(sender, *ticket, e3, request.seed);
                    request.tickets.insert(sender, score);
                }
                None
            }
            Transaction::FinalizeCommittee => request.finalize(now).map(|members| match members {
                Some(members) => ChainFact::CommitteeFinalized {
                    e3,
                    members,
                    dkg: TIMING,
                },
                None => ChainFact::Failed {
                    e3,
                    reason: FailureReason::InsufficientCommitteeMembers,
                },
            }),
            Transaction::PublishCommittee(publication) => {
                let committee = request.committee.clone().unwrap_or_default();
                (!std::mem::replace(&mut request.key_published, true)).then(|| {
                    let slots = publication.attestations.iter().filter_map(|attestation| {
                        let member = committee.get(attestation.party_id as usize)?;
                        let anchor = KeyAnchor {
                            sk_agg_commit: attestation.sk_agg_commit,
                            esm_agg_commit: attestation.esm_agg_commit,
                        };
                        Some((*member, anchor))
                    });
                    let anchors: BTreeMap<Address, KeyAnchor> = slots.collect();
                    ChainFact::KeyPublished {
                        e3,
                        roster: anchors.keys().copied().collect(),
                        committee,
                        commitment: publication.commitment,
                        compute_deadline: COMPUTE_DEADLINE,
                        anchors,
                    }
                })
            }
            Transaction::PublishPlaintext(_) => (!std::mem::replace(&mut request.completed, true))
                .then_some(ChainFact::StageChanged {
                    e3,
                    stage: Stage::Complete,
                }),
            Transaction::MarkFailed => {
                let (deadline, reason) = request.timeout;
                let fails = !request.completed && !request.failed && now > deadline;
                request.failed |= fails;
                fails.then_some(ChainFact::Failed { e3, reason })
            }
            Transaction::SettleFailure => (request.failed
                && !std::mem::replace(&mut request.settled, true))
            .then_some(ChainFact::FailureSettled { e3 }),
            // The slashing manager takes T votes; this policy expels the member.
            Transaction::ProposeSlash { accused, votes, .. } => {
                let quorum = request.params.committee_size.values().threshold;
                (votes.len() >= quorum && request.expelled.insert(*accused)).then_some(
                    ChainFact::MemberExpelled {
                        e3,
                        member: *accused,
                    },
                )
            }
        };
        let ciphertext = match (&fact, &submission.transaction) {
            (Some(_), Transaction::PublishCommittee(publication)) => {
                let params = request.params;
                Some(self.jobs.ciphertext(e3, &params, publication.public_key))
            }
            _ => None,
        };
        let settled = matches!(fact, Some(ChainFact::FailureSettled { .. }));
        if let Some(fact) = fact {
            let at = self.now + self.delay();
            self.chain(at, fact);
        }
        if settled {
            // Governance closes the E3 in its slashing manager after settlement.
            let at = self.now + self.delay();
            self.chain(at, ChainFact::DependenciesReleased { e3 });
        }
        if let Some(ciphertext) = ciphertext {
            self.available.insert(ciphertext.hash, ciphertext);
            let at = self.ciphertext_at.max(self.now + 100);
            let ready = ChainFact::CiphertextReady {
                e3,
                ciphertext: DataRef {
                    hash: ciphertext.hash,
                    block: 0,
                    leaf: 0,
                },
                deadline: at + 100_000,
            };
            self.chain(at, ready);
        }
        self.submissions.push(submission);
    }

    fn schedule_tick(&mut self, node: usize) {
        let Some(at) = self.nodes[node].node().next_deadline() else {
            return;
        };
        if self.ticks[node] != Some(at) {
            self.ticks[node] = Some(at);
            self.schedule(at, node, Input::Tick, None);
        }
    }

    fn schedule(&mut self, at: UnixSecs, to: usize, input: Input, answers: Option<EffectKey>) {
        self.next_delivery += 1;
        let delivery = Delivery { to, input, answers };
        self.queue
            .insert((at.max(self.now), self.next_delivery), delivery);
    }

    fn delay(&mut self) -> UnixSecs {
        self.rng.random_range(1..=self.faults.max_delay)
    }
}

/// One E3 as the simulated contracts keep it.
struct Request {
    params: CryptoParams,
    n: usize,
    seed: U256,
    deadline: UnixSecs,
    tickets: BTreeMap<Address, U256>,
    finalized: bool,
    committee: Option<Vec<Address>>,
    key_published: bool,
    completed: bool,
    /// When the stage the E3 is in fails, and why.
    timeout: (UnixSecs, FailureReason),
    failed: bool,
    settled: bool,
    /// The members a slash expelled.
    expelled: BTreeSet<Address>,
}

impl Request {
    fn new(params: CryptoParams, committee_deadline: UnixSecs) -> Self {
        Self {
            params,
            n: params.committee_size.values().n,
            seed: U256::ZERO,
            deadline: committee_deadline,
            tickets: BTreeMap::new(),
            finalized: false,
            committee: None,
            key_published: false,
            completed: false,
            timeout: (committee_deadline, FailureReason::CommitteeFormationTimeout),
            failed: false,
            settled: false,
            expelled: BTreeSet::new(),
        }
    }

    fn apply(&mut self, fact: &ChainFact) {
        match fact {
            ChainFact::SeedReady { seed, .. } => {
                self.seed = seed.seed;
                self.deadline = seed.deadline;
                self.timeout = (seed.deadline, FailureReason::CommitteeFormationTimeout);
            }
            ChainFact::CommitteeFinalized { members, dkg, .. } => {
                let mut members = members.clone();
                members.sort();
                self.committee = Some(members);
                self.timeout = (dkg.deadline, FailureReason::DkgTimeout);
            }
            ChainFact::KeyPublished {
                compute_deadline, ..
            } => self.timeout = (*compute_deadline, FailureReason::ComputeTimeout),
            ChainFact::CiphertextReady { deadline, .. } => {
                self.timeout = (*deadline, FailureReason::DecryptionTimeout)
            }
            ChainFact::Failed { .. } => self.failed = true,
            _ => {}
        }
    }

    /// The committee, or None when too few tickets came, the first time a call after the
    /// deadline finalizes it.
    fn finalize(&mut self, now: UnixSecs) -> Option<Option<Vec<Address>>> {
        if now <= self.deadline || std::mem::replace(&mut self.finalized, true) {
            return None;
        }
        let mut ranked: Vec<(U256, Address)> = self
            .tickets
            .iter()
            .map(|(operator, score)| (*score, *operator))
            .collect();
        ranked.sort();
        if ranked.len() < self.n {
            return Some(None);
        }
        let mut members: Vec<Address> = ranked[..self.n]
            .iter()
            .map(|(_, operator)| *operator)
            .collect();
        members.sort();
        Some(Some(members))
    }
}

/// The E3 a fact is about; chain-wide facts name none.
fn fact_e3(fact: &ChainFact) -> Option<E3Id> {
    let e3 = match fact {
        ChainFact::E3Requested { e3, .. }
        | ChainFact::SeedReady { e3, .. }
        | ChainFact::CommitteeFinalized { e3, .. }
        | ChainFact::KeyPublished { e3, .. }
        | ChainFact::CiphertextReady { e3, .. }
        | ChainFact::StageChanged { e3, .. }
        | ChainFact::FailureSettled { e3 }
        | ChainFact::DependenciesReleased { e3 }
        | ChainFact::Failed { e3, .. }
        | ChainFact::MemberExpelled { e3, .. } => e3,
        ChainFact::VoteValidity { .. }
        | ChainFact::OperatorActive { .. }
        | ChainFact::TicketBalance { .. }
        | ChainFact::BondOwner { .. }
        | ChainFact::EligibilityReset
        | ChainFact::OperatorEnabled { .. }
        | ChainFact::RandomnessProvider { .. }
        | ChainFact::SlashingManager { .. } => return None,
    };
    Some(*e3)
}

#[cfg(test)]
mod tests;
