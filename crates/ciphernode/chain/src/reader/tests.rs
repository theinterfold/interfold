// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use super::*;
use crate::testing::{contracts, e3_requested, log, CONFIG, RANDOMNESS};
use alloy_primitives::{Address, Bytes, B256};
use alloy_sol_types::SolValue;
use e3_evm_contracts::{ICiphernodeRegistry, IInterfold, IRandomnessProvider, ISlashingManager};
use e3_protocol::{
    dkg::{AttestationContext, KeyAnchor},
    node::{CommitteeSeed, CryptoParams, DataRef},
    E3Id,
};
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;

const CONFIRMATIONS: u64 = 3;
const POLL: Duration = Duration::from_millis(250);
const TIMING: DkgTiming = DkgTiming {
    deadline: 900,
    window: 300,
};
const COMPUTE_DEADLINE: UnixSecs = 1_500;
const DECRYPTION_DEADLINE: UnixSecs = 2_000;
const RANDOMNESS_DEADLINE: UnixSecs = 60;
const TICKET_PRICE: U256 = U256::from_limbs([5, 0, 0, 0]);
const KEY_COMMITMENT: B256 = B256::repeat_byte(0x99);
const SK_AGG_COMMIT: B256 = B256::repeat_byte(0x66);
const ESM_AGG_COMMIT: B256 = B256::repeat_byte(0x77);
const SEED: CommitteeSeed = CommitteeSeed {
    seed: U256::from_limbs([42, 0, 0, 0]),
    deadline: 500,
};

#[derive(Default)]
struct Chain {
    head: u64,
    logs: Vec<RawLog>,
    /// The registry's accepted seed and committee deadline.
    seed: Option<CommitteeSeed>,
    /// Requests for more blocks than this fail, as a provider's cap does.
    cap: Option<u64>,
    reads_fail: bool,
    /// Reads of contract state get no answer.
    reads_held: bool,
    /// The block each read was made at.
    read_at: Vec<u64>,
    heads_asked: usize,
    announcing: Announcing,
    /// The node's announcements, with the contracts each covers.
    subscriptions: Vec<(Vec<Address>, mpsc::UnboundedSender<u64>)>,
}

/// How a node answers a request for announcements.
#[derive(Clone, Copy, Default)]
enum Announcing {
    /// It cannot announce, as over HTTP.
    #[default]
    No,
    Yes,
    Refuses,
    /// It never answers.
    Stuck,
}

#[derive(Clone, Default)]
struct FakeNode(Arc<Mutex<Chain>>);

impl FakeNode {
    /// A node that announces logs, as over a WebSocket.
    fn announcing() -> Self {
        let node = Self::default();
        node.with(|chain| chain.announcing = Announcing::Yes);
        node
    }

    fn with(&self, change: impl FnOnce(&mut Chain)) {
        change(&mut self.0.lock().unwrap());
    }

    /// Mines `log`: the head moves to its block, and the announcements of its contract name it.
    fn mine(&self, log: RawLog) {
        self.with(|chain| {
            chain.head = chain.head.max(log.at.block);
            for (addresses, announce) in &chain.subscriptions {
                if addresses.contains(&log.address) {
                    let _ = announce.send(log.at.block);
                }
            }
            chain.logs.push(log);
        });
    }

    fn heads_asked(&self) -> usize {
        self.0.lock().unwrap().heads_asked
    }

    async fn read<T>(&self, block: u64, value: impl FnOnce(&Chain) -> T) -> Result<T, RpcError> {
        let held = self.0.lock().unwrap().reads_held;
        if held {
            std::future::pending::<()>().await;
        }
        let mut chain = self.0.lock().unwrap();
        if chain.reads_fail {
            return Err(RpcError("the read failed".into()));
        }
        chain.read_at.push(block);
        Ok(value(&chain))
    }
}

impl Rpc for FakeNode {
    async fn head(&self) -> Result<u64, RpcError> {
        let mut chain = self.0.lock().unwrap();
        chain.heads_asked += 1;
        Ok(chain.head)
    }

    async fn announce(
        &self,
        addresses: &[Address],
    ) -> Result<Option<BoxStream<'static, u64>>, RpcError> {
        let announcing = self.0.lock().unwrap().announcing;
        match announcing {
            Announcing::No => return Ok(None),
            Announcing::Refuses => return Err(RpcError("too many subscriptions".into())),
            Announcing::Stuck => std::future::pending().await,
            Announcing::Yes => {}
        }
        let (announce, announced) = mpsc::unbounded_channel();
        self.with(|chain| chain.subscriptions.push((addresses.to_vec(), announce)));
        let blocks = futures::stream::unfold(announced, |mut announced| async move {
            let block = announced.recv().await?;
            Some((block, announced))
        });
        Ok(Some(blocks.boxed()))
    }

    async fn logs(
        &self,
        addresses: &[Address],
        from: u64,
        to: u64,
    ) -> Result<Vec<RawLog>, RpcError> {
        // A chain node answers over the network, so the reader waits here like it does there.
        tokio::task::yield_now().await;
        let chain = self.0.lock().unwrap();
        if chain.cap.is_some_and(|cap| to - from + 1 > cap) {
            return Err(RpcError("block range too large".into()));
        }
        let logs = chain
            .logs
            .iter()
            .filter(|log| addresses.contains(&log.address) && (from..=to).contains(&log.at.block));
        Ok(logs.cloned().collect())
    }

    async fn sortition(&self, _: U256, block: u64) -> Result<Sortition, RpcError> {
        self.read(block, |chain| Sortition {
            ticket_price: TICKET_PRICE,
            committee_deadline: chain.seed.map_or(RANDOMNESS_DEADLINE, |seed| seed.deadline),
            seed: chain.seed.map(|seed| seed.seed),
        })
        .await
    }

    async fn deadlines(&self, _: U256, block: u64) -> Result<Deadlines, RpcError> {
        self.read(block, |_| Deadlines {
            dkg: TIMING.deadline,
            compute: COMPUTE_DEADLINE,
            decryption: DECRYPTION_DEADLINE,
        })
        .await
    }

    async fn dkg_window(&self, _: U256, block: u64) -> Result<UnixSecs, RpcError> {
        self.read(block, |_| TIMING.window).await
    }

    async fn eligible(
        &self,
        operators: &[Address],
        _: UnixSecs,
    ) -> Result<BTreeSet<Address>, RpcError> {
        Ok(operators.iter().copied().collect())
    }
}

fn e3() -> E3Id {
    E3Id {
        chain_id: 1,
        number: U256::from(7),
    }
}

fn stage_changed(block: u64) -> RawLog {
    let event = IInterfold::E3StageChanged {
        e3Id: U256::from(7),
        previousStage: 1,
        newStage: 2,
    };
    log(contracts().interfold, &event, block, 1, 0)
}

/// The logs of one block whose facts need contract state: a seed, a finalized committee, a key,
/// and a ciphertext.
fn reads(block: u64) -> Vec<RawLog> {
    let c = contracts();
    let fulfilled = IRandomnessProvider::RandomnessFulfilled {
        requestId: U256::from(1),
        e3Id: U256::from(7),
        randomWord: U256::from(3),
        fulfilledAt: U256::from(50),
    };
    let sortition = ICiphernodeRegistry::SortitionCommitteeFinalized {
        e3Id: U256::from(7),
        committee: vec![Address::repeat_byte(1)],
        scores: vec![U256::from(1)],
    };
    let finalized = IInterfold::CommitteeFinalized {
        e3Id: U256::from(7),
    };
    // A roster of one: its slot at 2, its key commitments at 5 + H and 5 + 2H, the key last.
    let mut inputs = vec![B256::ZERO; 9];
    inputs[6] = SK_AGG_COMMIT;
    inputs[7] = ESM_AGG_COMMIT;
    *inputs.last_mut().unwrap() = KEY_COMMITMENT;
    let key = ICiphernodeRegistry::CommitteeProofPublished {
        e3Id: U256::from(7),
        nodes: vec![Address::repeat_byte(1)],
        pkCommitment: KEY_COMMITMENT,
        proof: (Bytes::new(), inputs).abi_encode_params().into(),
    };
    let ciphertext = IInterfold::CiphertextOutputReferencePublished {
        e3Id: U256::from(7),
        contentHash: B256::repeat_byte(0xc7),
        ciphertextCommitment: B256::ZERO,
        availabilityBlock: 70,
        availabilityLeafIndex: 3,
    };
    vec![
        log(RANDOMNESS, &fulfilled, block, 2, 1),
        log(c.interfold, &finalized, block, 3, 2),
        log(c.registry, &sortition, block, 3, 3),
        log(c.registry, &key, block, 4, 4),
        log(c.interfold, &ciphertext, block, 5, 5),
    ]
}

fn reader(node: &FakeNode, max_range: u64) -> Reader<FakeNode> {
    Reader::new(node.clone(), contracts(), CONFIRMATIONS, max_range, 0, POLL)
}

/// A poll that finds a contract it did not know reads its blocks again; a reader that never
/// learns the contract would read them forever.
async fn discovering_poll(reader: &mut Reader<FakeNode>) -> Vec<ChainEvent> {
    let poll = tokio::time::timeout(std::time::Duration::from_secs(10), reader.poll());
    poll.await.expect("the poll ends").unwrap()
}

fn blocks(events: &[ChainEvent]) -> Vec<u64> {
    events.iter().map(|event| event.at.block).collect()
}

#[tokio::test]
async fn a_poll_reads_the_blocks_the_head_has_confirmed() {
    let node = FakeNode::default();
    node.with(|chain| {
        chain.head = 10;
        chain.logs = vec![stage_changed(5), stage_changed(9)];
    });
    let mut reader = reader(&node, 1_000);
    assert_eq!(blocks(&reader.poll().await.unwrap()), [5]);
    assert!(reader.poll().await.unwrap().is_empty());
    node.with(|chain| chain.head = 12);
    assert_eq!(blocks(&reader.poll().await.unwrap()), [9]);
}

/// A reader catching up reads state at the confirmed head, which a node that prunes old state
/// still has, not at the old blocks it is reading.
#[tokio::test]
async fn facts_that_need_contract_state_carry_its_values_at_the_confirmed_head() {
    let node = FakeNode::default();
    node.with(|chain| {
        chain.head = 1_003;
        chain.logs = reads(5);
        chain.seed = Some(SEED);
    });
    let events = reader(&node, 100).poll().await.unwrap();
    let facts: Vec<ChainFact> = events.into_iter().map(|event| event.fact).collect();
    let ciphertext = DataRef {
        hash: B256::repeat_byte(0xc7),
        block: 70,
        leaf: 3,
    };
    let expected = vec![
        ChainFact::SeedReady {
            e3: e3(),
            seed: SEED,
        },
        ChainFact::CommitteeFinalized {
            e3: e3(),
            members: vec![Address::repeat_byte(1)],
            dkg: TIMING,
        },
        ChainFact::KeyPublished {
            e3: e3(),
            committee: vec![Address::repeat_byte(1)],
            roster: vec![Address::repeat_byte(1)],
            commitment: KEY_COMMITMENT,
            compute_deadline: COMPUTE_DEADLINE,
            anchors: [(
                Address::repeat_byte(1),
                KeyAnchor {
                    sk_agg_commit: SK_AGG_COMMIT,
                    esm_agg_commit: ESM_AGG_COMMIT,
                },
            )]
            .into(),
        },
        ChainFact::CiphertextReady {
            e3: e3(),
            ciphertext,
            deadline: DECRYPTION_DEADLINE,
        },
    ];
    assert_eq!(facts, expected);
    assert!(node
        .0
        .lock()
        .unwrap()
        .read_at
        .iter()
        .all(|block| *block == 1_000));
}

#[tokio::test]
async fn randomness_the_registry_has_not_accepted_readies_no_seed() {
    let node = FakeNode::default();
    node.with(|chain| {
        chain.head = 10;
        chain.logs = reads(5)[..1].to_vec();
    });
    assert!(reader(&node, 1_000).poll().await.unwrap().is_empty());
}

#[tokio::test]
async fn a_failed_poll_returns_nothing_and_the_next_one_reads_the_same_blocks() {
    let node = FakeNode::default();
    node.with(|chain| {
        chain.head = 10;
        chain.logs = [vec![stage_changed(4)], reads(5)].concat();
        chain.seed = Some(SEED);
        chain.reads_fail = true;
    });
    let mut reader = reader(&node, 1_000);
    assert!(matches!(reader.poll().await, Err(ReadError::Rpc(_))));
    node.with(|chain| chain.reads_fail = false);
    assert_eq!(blocks(&reader.poll().await.unwrap()), [4, 5, 5, 5, 5]);
}

/// A chain node can hold a request without ever answering; the poll fails in time, and the next
/// one reads the same blocks.
#[tokio::test(start_paused = true)]
async fn a_read_the_chain_node_never_answers_fails_the_poll_in_time() {
    let node = FakeNode::default();
    node.with(|chain| {
        chain.head = 10;
        chain.logs = reads(5);
        chain.seed = Some(SEED);
        chain.reads_held = true;
    });
    let mut reader = reader(&node, 1_000);
    let poll = tokio::time::timeout(LONGEST_ANSWER * 2, reader.poll());
    let failed = poll.await.expect("the poll ends");
    assert!(matches!(failed, Err(ReadError::Rpc(_))));
    node.with(|chain| chain.reads_held = false);
    assert_eq!(blocks(&reader.poll().await.unwrap()), [5, 5, 5, 5]);
}

#[tokio::test]
async fn a_range_the_provider_rejects_is_requested_again_in_halves() {
    let node = FakeNode::default();
    node.with(|chain| {
        chain.head = 2_003;
        chain.logs = vec![stage_changed(100), stage_changed(600), stage_changed(1_900)];
        chain.cap = Some(300);
    });
    let mut reader = reader(&node, 1_000);
    let mut read = Vec::new();
    for _ in 0..40 {
        if let Ok(events) = reader.poll().await {
            read.extend(blocks(&events));
        }
    }
    assert_eq!(read, [100, 600, 1_900]);
}

/// Governance replaced the provider, so the node did not know the one this request names. A mock
/// provider fulfills inside the request, before the registry logs it. The node keeps the
/// provider, so a restart reads its fulfillments too.
#[tokio::test]
async fn a_request_s_new_randomness_provider_is_read_in_the_same_poll() {
    let c = contracts();
    let provider = Address::repeat_byte(0x77);
    let requested = ICiphernodeRegistry::CommitteeRandomnessRequested {
        e3Id: U256::from(7),
        requestId: U256::from(1),
        provider,
        randomnessDeadline: U256::from(60),
    };
    let fulfilled = IRandomnessProvider::RandomnessFulfilled {
        requestId: U256::from(1),
        e3Id: U256::from(7),
        randomWord: U256::from(3),
        fulfilledAt: U256::from(50),
    };
    let node = FakeNode::default();
    node.with(|chain| {
        chain.head = 10;
        chain.logs = vec![
            log(provider, &fulfilled, 5, 2, 0),
            log(c.registry, &requested, 5, 2, 1),
        ];
        chain.seed = Some(SEED);
    });
    let events = discovering_poll(&mut reader(&node, 1_000)).await;
    let facts: Vec<ChainFact> = events.into_iter().map(|event| event.fact).collect();
    let seed = ChainFact::SeedReady {
        e3: e3(),
        seed: SEED,
    };
    assert_eq!(
        facts,
        vec![seed, ChainFact::RandomnessProvider { provider }]
    );
}

/// Governance replaced the slashing manager; the new one closes an E3 in a later block of the same
/// poll.
#[tokio::test]
async fn a_slashing_manager_the_interfold_sets_is_read_in_the_same_poll() {
    let c = contracts();
    let manager = Address::repeat_byte(0x55);
    let set = IInterfold::SlashingManagerSet {
        slashingManager: manager,
    };
    let released = ISlashingManager::E3DependenciesReleased {
        e3Id: U256::from(7),
    };
    let node = FakeNode::default();
    node.with(|chain| {
        chain.head = 10;
        chain.logs = vec![
            log(c.interfold, &set, 5, 2, 0),
            log(manager, &released, 6, 3, 0),
        ];
    });
    let events = discovering_poll(&mut reader(&node, 1_000)).await;
    let facts: Vec<ChainFact> = events.into_iter().map(|event| event.fact).collect();
    let expected = vec![
        ChainFact::SlashingManager { manager },
        ChainFact::DependenciesReleased { e3: e3() },
    ];
    assert_eq!(facts, expected);
}

/// A provider can fulfill inside the request's own transaction, before `E3Requested`: the node
/// cannot take that seed yet, so the request carries it.
#[tokio::test]
async fn a_request_carries_the_seed_its_own_transaction_fulfilled() {
    let c = contracts();
    let attestation = ICiphernodeRegistry::DkgFoldAttestationContextEstablished {
        e3Id: U256::from(7),
        registry: c.registry,
        dkgFoldAttestationVerifier: Address::repeat_byte(0x5f),
    };
    let fulfilled = &reads(5)[0];
    let node = FakeNode::default();
    node.with(|chain| {
        chain.head = 10;
        chain.logs = vec![
            log(c.registry, &attestation, 5, 9, 0),
            RawLog {
                transaction: B256::repeat_byte(9),
                ..fulfilled.clone()
            },
            log(c.interfold, &e3_requested(CONFIG), 5, 9, 2),
        ];
        chain.seed = Some(SEED);
    });
    let events = reader(&node, 1_000).poll().await.unwrap();
    let facts: Vec<ChainFact> = events.into_iter().map(|event| event.fact).collect();
    let request = ChainFact::E3Requested {
        e3: e3(),
        params: CryptoParams {
            param_set: 1,
            committee_size: e3_committee::CiphernodesCommitteeSize::Minimum,
            seed: B256::from(U256::from(42)),
        },
        interfold: c.interfold,
        attestation: AttestationContext {
            registry: c.registry,
            verifier: Address::repeat_byte(0x5f),
        },
        request: CommitteeRequest {
            time: 50,
            ticket_price: TICKET_PRICE,
            owner_cap: false,
            dkg_window: TIMING.window,
        },
        committee_deadline: SEED.deadline,
        seed: Some(SEED.seed),
    };
    let seed = ChainFact::SeedReady {
        e3: e3(),
        seed: SEED,
    };
    assert_eq!(facts, vec![seed, request]);
}

/// Over a WebSocket the chain node announces the contracts' logs, so the reader asks it nothing
/// while the chain is quiet, reads a quiet chain once a minute, and reads an announced log at once.
#[tokio::test(start_paused = true)]
async fn the_reader_waits_for_announced_logs_and_reads_a_quiet_chain_each_minute() {
    let node = FakeNode::announcing();
    node.with(|chain| chain.head = 10);
    let mut reader = Reader::new(node.clone(), contracts(), 0, 1_000, 0, POLL);
    assert!(reader.poll().await.unwrap().is_empty());

    let start = Instant::now();
    reader.wait().await;
    assert_eq!(start.elapsed(), LONGEST_WAIT);
    assert_eq!(node.heads_asked(), 2, "the poll's and the subscription's");

    node.mine(stage_changed(11));
    let start = Instant::now();
    reader.wait().await;
    assert_eq!(start.elapsed(), Duration::ZERO);
    assert_eq!(blocks(&reader.poll().await.unwrap()), [11]);
}

/// Logs mined before the announcements started were not announced, and an announced block needs
/// its confirmations: the reader polls at the poll interval until it has read them.
#[tokio::test(start_paused = true)]
async fn blocks_not_announced_or_not_confirmed_are_polled_for() {
    let node = FakeNode::announcing();
    node.with(|chain| {
        chain.head = 10;
        chain.logs = vec![stage_changed(9)];
    });
    let mut reader = reader(&node, 1_000);
    assert!(reader.poll().await.unwrap().is_empty());
    let start = Instant::now();
    reader.wait().await;
    assert_eq!(start.elapsed(), POLL);
    node.with(|chain| chain.head = 13);
    assert_eq!(blocks(&reader.poll().await.unwrap()), [9]);

    node.mine(stage_changed(14));
    reader.wait().await;
    assert!(reader.poll().await.unwrap().is_empty());
    let start = Instant::now();
    reader.wait().await;
    assert_eq!(start.elapsed(), POLL);
    node.with(|chain| chain.head = 17);
    assert_eq!(blocks(&reader.poll().await.unwrap()), [14]);
}

/// A randomness provider the reader learns of fulfills requests in its own logs, which drive
/// ticket times, so the node announces its logs too.
#[tokio::test(start_paused = true)]
async fn the_logs_of_a_contract_the_reader_learns_of_are_announced() {
    let provider = Address::repeat_byte(0x77);
    let requested = ICiphernodeRegistry::CommitteeRandomnessRequested {
        e3Id: U256::from(7),
        requestId: U256::from(1),
        provider,
        randomnessDeadline: U256::from(60),
    };
    let fulfilled = IRandomnessProvider::RandomnessFulfilled {
        requestId: U256::from(1),
        e3Id: U256::from(7),
        randomWord: U256::from(3),
        fulfilledAt: U256::from(50),
    };
    let node = FakeNode::announcing();
    node.with(|chain| chain.head = 10);
    let mut reader = Reader::new(node.clone(), contracts(), 0, 1_000, 0, POLL);
    assert!(reader.poll().await.unwrap().is_empty());
    let mine = async {
        tokio::time::sleep(Duration::from_secs(1)).await;
        node.mine(log(contracts().registry, &requested, 11, 2, 0));
    };
    tokio::join!(reader.wait(), mine);
    let facts = reader.poll().await.unwrap();
    assert_eq!(facts[0].fact, ChainFact::RandomnessProvider { provider });

    let mine = async {
        tokio::time::sleep(Duration::from_secs(1)).await;
        node.mine(log(provider, &fulfilled, 12, 3, 0));
    };
    let start = Instant::now();
    let woke = async {
        reader.wait().await;
        start.elapsed()
    };
    let (woke, ()) = tokio::join!(woke, mine);
    assert_eq!(woke, Duration::from_secs(1));
    node.with(|chain| chain.seed = Some(SEED));
    let facts = reader.poll().await.unwrap();
    let seed = ChainFact::SeedReady {
        e3: e3(),
        seed: SEED,
    };
    assert_eq!(
        facts
            .into_iter()
            .map(|event| event.fact)
            .collect::<Vec<_>>(),
        [seed]
    );
}

/// A refused request for announcements is made again a minute later, and the reader polls
/// meanwhile. A request left unanswered for a minute is not made again, since a late answer to each
/// would leave a subscription that nothing ends: the reader polls for the rest of the run.
#[tokio::test(start_paused = true)]
async fn the_reader_polls_around_failed_requests_for_announcements() {
    let node = FakeNode::announcing();
    node.with(|chain| {
        chain.head = 10;
        chain.announcing = Announcing::Refuses;
    });
    let mut reader = Reader::new(node.clone(), contracts(), 0, 1_000, 0, POLL);
    assert!(reader.poll().await.unwrap().is_empty());
    let start = Instant::now();
    reader.wait().await;
    assert_eq!(start.elapsed(), POLL);
    node.with(|chain| chain.announcing = Announcing::Yes);
    tokio::time::sleep(LONGEST_WAIT).await;
    let start = Instant::now();
    reader.wait().await;
    assert_eq!(
        start.elapsed(),
        LONGEST_WAIT,
        "announced, the quiet chain is read once a minute"
    );

    let node = FakeNode::announcing();
    node.with(|chain| {
        chain.head = 10;
        chain.announcing = Announcing::Stuck;
    });
    let mut reader = Reader::new(node.clone(), contracts(), 0, 1_000, 0, POLL);
    assert!(reader.poll().await.unwrap().is_empty());
    let start = Instant::now();
    let wait = tokio::time::timeout(2 * LONGEST_WAIT, reader.wait());
    wait.await.expect("the wait ends");
    assert_eq!(start.elapsed(), LONGEST_WAIT);
    node.with(|chain| chain.announcing = Announcing::Yes);
    tokio::time::sleep(LONGEST_WAIT).await;
    let start = Instant::now();
    reader.wait().await;
    assert_eq!(start.elapsed(), POLL);
}
