// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Runs v2 nodes in one process with virtual time, crashes, and network delays. Each node also
//! feeds a shadow copy of its machine that never crashes and never touches a store; the node must
//! always produce the same effects as its shadow and end in the same state.

use alloy_primitives::{keccak256, Bytes, B256};
use e3_engine::{EffectKey, Engine, MemoryStore, Pending};
use e3_protocol::{
    dkg::{DkgWork, DkgWorkResult, OwnKey, OwnShares, RecipientShares},
    node::{
        ChainEvent, ChainFact, Effect, Input, Job, JobDone, LogPosition, Node, PeerMessage, Work,
        WorkResult,
    },
    proof::ZkProof,
    testing::{address, sign},
    BlobRef, Machine, UnixSecs,
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
}

/// Nodes with an operator signer each, a mock job runner, one chain, and a network that delays,
/// reorders, and duplicates peer messages but never loses them.
pub struct Sim {
    nodes: Vec<SimNode>,
    chain_lags: Vec<UnixSecs>,
    ticks: Vec<Option<UnixSecs>>,
    queue: BTreeMap<(UnixSecs, u64), Delivery>,
    next_delivery: u64,
    block: u64,
    now: UnixSecs,
    rng: ChaCha8Rng,
    faults: Faults,
    gossip: Vec<PeerMessage>,
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
            block: 0,
            now: 0,
            rng,
            faults,
            gossip: Vec::new(),
        }
    }

    pub fn set_chain_lag(&mut self, node: usize, lag: UnixSecs) {
        self.chain_lags[node] = lag;
    }

    /// A fact confirmed at `at`, in its own block. Each node reads it after its chain lag.
    pub fn chain(&mut self, at: UnixSecs, fact: ChainFact) {
        self.block += 1;
        let event = ChainEvent {
            at: LogPosition {
                chain_id: 1,
                block: self.block,
                log_index: 0,
            },
            fact,
        };
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
                        let copies = 1 + u32::from(self.rng.random_bool(self.faults.duplicate));
                        for _ in 0..copies {
                            let at = self.now + self.delay();
                            self.schedule(at, peer, Input::Peer(message.clone()), None);
                        }
                    }
                    self.gossip.push(message);
                }
            }
        }
    }

    /// Mock work: no cryptography, but the same shape of results, drawn fresh on every run as real
    /// key and share generation are. A check passes when the checked bytes are the ones the mock
    /// derived for them.
    fn run(&mut self, job: &Job) -> WorkResult {
        let result = match &job.work {
            Work::Dkg(DkgWork::MakeEncryptionKey) => {
                let proof = self.proof();
                let public = blob(keccak256(&proof.data));
                DkgWorkResult::EncryptionKeyMade(OwnKey {
                    public,
                    secret: blob(keccak256(public.hash)),
                    proof,
                })
            }
            Work::Dkg(DkgWork::CheckEncryptionKey { sender, key, proof }) => {
                DkgWorkResult::EncryptionKeyChecked {
                    sender: *sender,
                    valid: key.hash == keccak256(&proof.data),
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
                DkgWorkResult::SharesMade(OwnShares {
                    pk_share,
                    own_share: blob(self.hash()),
                    c1: self.proof(),
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
        };
        WorkResult::Dkg(result)
    }

    fn hash(&mut self) -> B256 {
        B256::from(self.rng.random::<[u8; 32]>())
    }

    fn proof(&mut self) -> ZkProof {
        ZkProof {
            data: Bytes::from(self.rng.random::<[u8; 32]>().to_vec()),
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

#[cfg(test)]
mod tests;
