// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use super::*;
use crate::testing::{contracts, log, RANDOMNESS};
use alloy_primitives::{Address, B256};
use e3_evm_contracts::{ICiphernodeRegistry, IInterfold, IRandomnessProvider};
use e3_protocol::{node::DataRef, E3Id};
use std::sync::{Arc, Mutex};

const CONFIRMATIONS: u64 = 3;
const TIMING: DkgTiming = DkgTiming {
    deadline: 900,
    window: 300,
};
const DECRYPTION_DEADLINE: UnixSecs = 2_000;

#[derive(Default)]
struct Chain {
    head: u64,
    logs: Vec<RawLog>,
    /// The registry's accepted seed and committee deadline.
    seed: Option<(U256, UnixSecs)>,
    /// Requests for more blocks than this fail, as a provider's cap does.
    cap: Option<u64>,
    reads_fail: bool,
    /// The block each read was made at.
    read_at: Vec<u64>,
}

#[derive(Clone, Default)]
struct FakeNode(Arc<Mutex<Chain>>);

impl FakeNode {
    fn with(&self, change: impl FnOnce(&mut Chain)) {
        change(&mut self.0.lock().unwrap());
    }

    fn read<T>(&self, block: u64, value: impl FnOnce(&Chain) -> T) -> Result<T, RpcError> {
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
        Ok(self.0.lock().unwrap().head)
    }

    async fn logs(&self, from: u64, to: u64) -> Result<Vec<RawLog>, RpcError> {
        let chain = self.0.lock().unwrap();
        if chain.cap.is_some_and(|cap| to - from + 1 > cap) {
            return Err(RpcError("block range too large".into()));
        }
        let logs = chain
            .logs
            .iter()
            .filter(|log| (from..=to).contains(&log.at.block));
        Ok(logs.cloned().collect())
    }

    async fn seed(&self, _: U256, block: u64) -> Result<Option<(U256, UnixSecs)>, RpcError> {
        self.read(block, |chain| chain.seed)
    }

    async fn dkg_timing(&self, _: U256, block: u64) -> Result<DkgTiming, RpcError> {
        self.read(block, |_| TIMING)
    }

    async fn decryption_deadline(&self, _: U256, block: u64) -> Result<UnixSecs, RpcError> {
        self.read(block, |_| DECRYPTION_DEADLINE)
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

/// The logs of one block whose facts need contract state: a seed, a finalized committee, and a
/// ciphertext.
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
    let ciphertext = IInterfold::CiphertextOutputReferencePublished {
        e3Id: U256::from(7),
        contentHash: B256::repeat_byte(0xc7),
        ciphertextCommitment: B256::ZERO,
        availabilityBlock: 70,
        availabilityLeafIndex: 3,
    };
    vec![
        log(RANDOMNESS, &fulfilled, block, 2, 1),
        log(c.registry, &sortition, block, 3, 2),
        log(c.interfold, &finalized, block, 3, 3),
        log(c.interfold, &ciphertext, block, 4, 4),
    ]
}

fn reader(node: &FakeNode, max_range: u64) -> Reader<FakeNode> {
    Reader::new(node.clone(), contracts(), CONFIRMATIONS, max_range, 0)
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
        chain.seed = Some((U256::from(42), 500));
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
            seed: U256::from(42),
            committee_deadline: 500,
        },
        ChainFact::CommitteeFinalized {
            e3: e3(),
            members: vec![Address::repeat_byte(1)],
            dkg: TIMING,
        },
        ChainFact::CiphertextReady {
            e3: e3(),
            ciphertext,
            deadline: DECRYPTION_DEADLINE,
        },
    ];
    assert_eq!(facts, expected);
    assert_eq!(node.0.lock().unwrap().read_at, [1_000, 1_000, 1_000]);
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
        chain.seed = Some((U256::from(42), 500));
        chain.reads_fail = true;
    });
    let mut reader = reader(&node, 1_000);
    assert!(matches!(reader.poll().await, Err(ReadError::Rpc(_))));
    node.with(|chain| chain.reads_fail = false);
    assert_eq!(blocks(&reader.poll().await.unwrap()), [4, 5, 5, 5]);
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
