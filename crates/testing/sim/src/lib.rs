// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Runs v2 nodes in one process with virtual time, crashes, and network delays. Each node also
//! feeds a shadow copy of its machine that never crashes and never touches a store; the node must
//! always produce the same effects as its shadow and end in the same state.

use alloy_primitives::{keccak256, Address, B256, U256};
use e3_engine::{EffectKey, Engine, MemoryStore, Pending};
use e3_protocol::{
    decryption::{
        DecryptionWork, DecryptionWorkResult, OwnShares as DecryptionShares, PlaintextPublication,
    },
    dkg::{
        AggregatedKey, DkgWork, DkgWorkResult, NodeFold, OwnDecryptionKey, OwnKey, OwnShares,
        RecipientShares,
    },
    node::{
        ChainEvent, ChainFact, Effect, FailureReason, Input, Job, JobDone, LogPosition, Node,
        PeerMessage, Stage, Submission, Transaction, Work, WorkResult,
    },
    proof::ZkProof,
    selection::ticket_score,
    testing::{address, sign, TIMING},
    BlobRef, E3Id, Machine, UnixSecs,
};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha8Rng;
use std::collections::BTreeMap;

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

/// Nodes with an operator signer each, a mock job runner, one chain, and a network that delays,
/// reorders, duplicates, and drops peer messages.
pub struct Sim {
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
    now: UnixSecs,
    rng: ChaCha8Rng,
    faults: Faults,
    gossip: Vec<PeerMessage>,
    submissions: Vec<Submission>,
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
            now: 0,
            rng,
            faults,
            gossip: Vec::new(),
            submissions: Vec::new(),
        }
    }

    pub fn set_chain_lag(&mut self, node: usize, lag: UnixSecs) {
        self.chain_lags[node] = lag;
    }

    /// A fact confirmed at `at`, in its own block. Each node reads it after its chain lag.
    pub fn chain(&mut self, at: UnixSecs, fact: ChainFact) {
        let at = at.max(self.now);
        match &fact {
            ChainFact::E3Requested { e3, params, .. } => {
                self.requests
                    .insert(*e3, Request::new(params.committee_size.values().n));
            }
            ChainFact::SeedReady {
                e3,
                seed,
                committee_deadline,
            } => {
                if let Some(request) = self.requests.get_mut(e3) {
                    request.seed = *seed;
                    request.deadline = *committee_deadline;
                }
            }
            ChainFact::CommitteeFinalized { e3, members, .. } => {
                if let Some(request) = self.requests.get_mut(e3) {
                    let mut members = members.clone();
                    members.sort();
                    request.committee = Some(members);
                }
            }
            _ => {}
        }
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

    fn deliver(&mut self, delivery: Delivery) {
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
                        result: self.run(&job),
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
                            self.schedule(at, peer, Input::Peer(message.clone()), None);
                        }
                    }
                    self.gossip.push(message);
                }
                Effect::Submit(submission) => {
                    self.nodes[node].acknowledge(key);
                    self.submit(address(self.nodes[node].operator), submission);
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
                    ChainFact::KeyPublished {
                        e3,
                        roster: publication
                            .attestations
                            .iter()
                            .filter_map(|attestation| committee.get(attestation.party_id as usize))
                            .copied()
                            .collect(),
                        committee,
                        commitment: publication.commitment,
                    }
                })
            }
            Transaction::PublishPlaintext(_) => (!std::mem::replace(&mut request.completed, true))
                .then_some(ChainFact::StageChanged {
                    e3,
                    stage: Stage::Complete,
                }),
        };
        if let Some(fact) = fact {
            let at = self.now + self.delay();
            self.chain(at, fact);
        }
        self.submissions.push(submission);
    }

    /// Mock work: no cryptography, but the same shape of results, drawn fresh on every run as real
    /// key and share generation are. A check passes when the checked bytes are the ones the mock
    /// derived for them.
    fn run(&mut self, job: &Job) -> WorkResult {
        let result = match &job.work {
            Work::Dkg(DkgWork::MakeEncryptionKey) => {
                let proof = self.proof();
                let public = blob(keccak256(proof.data.hash));
                DkgWorkResult::EncryptionKeyMade(OwnKey {
                    public,
                    secret: blob(keccak256(public.hash)),
                    proof,
                })
            }
            Work::Dkg(DkgWork::CheckEncryptionKey { sender, key, proof }) => {
                DkgWorkResult::EncryptionKeyChecked {
                    sender: *sender,
                    valid: key.hash == keccak256(proof.data.hash),
                }
            }
            Work::Dkg(DkgWork::MakeShares { keys, .. }) => {
                let pk_share = blob(self.hash());
                let recipients = keys
                    .keys()
                    .map(|member| {
                        let shares = RecipientShares {
                            shares: blob(keccak256(
                                [pk_share.hash.as_slice(), member.as_slice()].concat(),
                            )),
                            c3a: (0..3).map(|_| self.proof()).collect(),
                            c3b: (0..3).map(|_| self.proof()).collect(),
                        };
                        (*member, shares)
                    })
                    .collect();
                let c1 = ZkProof {
                    public_inputs: vec![pk_share.hash],
                    ..self.proof()
                };
                DkgWorkResult::SharesMade(OwnShares {
                    pk_share,
                    own_share: blob(self.hash()),
                    c1,
                    c2a: self.proof(),
                    c2b: self.proof(),
                    recipients,
                })
            }
            Work::Dkg(DkgWork::CheckShares {
                dealer, message, ..
            }) => {
                let expected = keccak256(
                    [
                        message.pk_share.hash.as_slice(),
                        message.recipient.as_slice(),
                    ]
                    .concat(),
                );
                DkgWorkResult::SharesChecked {
                    dealer: *dealer,
                    valid: message.shares.hash == expected,
                }
            }
            Work::Dkg(DkgWork::MakeDecryptionKey { c2, .. }) => {
                let binds = |proof: ZkProof| ZkProof {
                    public_inputs: vec![c2_commitment(c2)],
                    ..proof
                };
                DkgWorkResult::DecryptionKeyMade(OwnDecryptionKey {
                    key: blob(self.hash()),
                    c4a: binds(self.proof()),
                    c4b: vec![binds(self.proof())],
                })
            }
            Work::Dkg(DkgWork::CheckDecryptionKey {
                member,
                c2,
                message,
                ..
            }) => DkgWorkResult::DecryptionKeyChecked {
                member: *member,
                valid: message.c4a.proof.public_inputs == [c2_commitment(c2)],
            },
            Work::Dkg(DkgWork::FoldProofs { .. }) => DkgWorkResult::ProofsFolded(NodeFold {
                proof: self.proof(),
                sk_agg_commit: self.hash(),
                esm_agg_commit: self.hash(),
            }),
            Work::Dkg(DkgWork::CheckKeyshare {
                member, keyshare, ..
            }) => DkgWorkResult::KeyshareChecked {
                member: *member,
                valid: keyshare.c1.proof.public_inputs == [keyshare.pk_share.hash],
            },
            Work::Decryption(work) => return self.decrypt(work),
            Work::Dkg(DkgWork::AggregateKey { keyshares, .. }) => {
                let shares: Vec<u8> = keyshares
                    .iter()
                    .flat_map(|keyshare| keyshare.pk_share.hash.0)
                    .collect();
                let public_key = blob(keccak256(shares));
                DkgWorkResult::KeyAggregated(AggregatedKey {
                    public_key,
                    commitment: keccak256(public_key.hash),
                    proof: self.proof(),
                })
            }
        };
        WorkResult::Dkg(result)
    }

    /// Mock decryption: a share binds the domain in its C6 inputs, and the plaintext follows from
    /// the ciphertext alone, so every aggregator gets the same one.
    fn decrypt(&mut self, work: &DecryptionWork) -> WorkResult {
        let result = match work {
            DecryptionWork::MakeShares {
                key,
                ciphertext,
                domain,
            } => DecryptionWorkResult::SharesMade(DecryptionShares {
                shares: vec![blob(keccak256([key.hash, ciphertext.hash].concat()))],
                c6: vec![ZkProof {
                    public_inputs: vec![*domain],
                    ..self.proof()
                }],
            }),
            DecryptionWork::CheckShares {
                member,
                domain,
                message,
                ..
            } => DecryptionWorkResult::SharesChecked {
                member: *member,
                valid: message
                    .c6
                    .iter()
                    .all(|proof| proof.proof.public_inputs == [*domain]),
            },
            DecryptionWork::AggregatePlaintext { ciphertext, .. } => {
                DecryptionWorkResult::PlaintextMade(PlaintextPublication {
                    plaintext: blob(keccak256(ciphertext.hash)),
                    proof: self.proof(),
                })
            }
        };
        WorkResult::Decryption(result)
    }

    fn hash(&mut self) -> B256 {
        B256::from(self.rng.random::<[u8; 32]>())
    }

    fn proof(&mut self) -> ZkProof {
        ZkProof {
            data: blob(self.hash()),
            public_inputs: vec![self.hash()],
        }
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

fn blob(hash: B256) -> BlobRef {
    BlobRef { hash, len: 1_000 }
}

/// What a mock C4 proof commits to: the roster dealers' C2 statements, in roster order.
fn c2_commitment(c2: &BTreeMap<Address, (ZkProof, ZkProof)>) -> B256 {
    let statements: Vec<u8> = c2
        .values()
        .flat_map(|(c2a, c2b)| c2a.public_inputs.iter().chain(&c2b.public_inputs))
        .flat_map(|word| word.0)
        .collect();
    keccak256(statements)
}

#[cfg(test)]
mod tests;

/// One E3 as the simulated contracts keep it.
struct Request {
    n: usize,
    seed: U256,
    deadline: UnixSecs,
    tickets: BTreeMap<Address, U256>,
    finalized: bool,
    committee: Option<Vec<Address>>,
    key_published: bool,
    completed: bool,
}

impl Request {
    fn new(n: usize) -> Self {
        Self {
            n,
            seed: U256::ZERO,
            deadline: UnixSecs::MAX,
            tickets: BTreeMap::new(),
            finalized: false,
            committee: None,
            key_published: false,
            completed: false,
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
