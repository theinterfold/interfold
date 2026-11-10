// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! The runtime over stand-ins for the chain, the network and the availability layer.

use super::*;
use alloy_primitives::U256;
use e3_blobs::MemoryBlobs;
use e3_chain::{
    Call, Deadlines, Estimate, KeyChunk, LogsError, OnChain, RawLog, RpcError, Sortition,
};
use e3_crypto::Cipher;
use e3_data_availability::DataReference;
use e3_engine::{Step, Store};
use e3_jobs::{JobLimits, Proofs};
use e3_p2p::{InboxWriter, NetworkError};
use e3_protocol::{
    node::{Admission, Effect, Note, Noted, PeerMessage},
    proof::ProofType,
    wire::Envelope,
    E3Id,
};
use futures::stream::BoxStream;
use std::{
    collections::BTreeMap,
    future::pending,
    path::Path,
    sync::atomic::{AtomicUsize, Ordering},
};

const STARTUP: Duration = Duration::from_secs(120);

#[derive(Clone, Default)]
struct Chain {
    panics: bool,
    head: u64,
    logs_fail: bool,
    /// How long each log request takes.
    slow_logs: Duration,
    /// Heads asked so far; after `heads_ok` of them, the chain node fails every request.
    heads: Arc<AtomicUsize>,
    heads_ok: Option<usize>,
    /// How many operators the registry lists.
    listed: u64,
    /// The first this many requests for the count fail.
    listed_failures: usize,
    /// How many blocks the head moves at each request for it.
    advancing: u64,
    listed_asked: Arc<AtomicUsize>,
}

impl Rpc for Chain {
    async fn head(&self) -> Result<u64, RpcError> {
        assert!(!self.panics, "the reader panics");
        let asked = self.heads.fetch_add(1, Ordering::SeqCst);
        if self.heads_ok.is_some_and(|ok| asked >= ok) {
            return Err(RpcError("the chain node is down".into()));
        }
        Ok(self.head + asked as u64 * self.advancing)
    }

    async fn announce(&self, _: &[Address]) -> Result<Option<BoxStream<'static, u64>>, RpcError> {
        Ok(None)
    }

    async fn logs(&self, _: &[Address], _: u64, _: u64) -> Result<Vec<RawLog>, LogsError> {
        tokio::time::sleep(self.slow_logs).await;
        if self.logs_fail {
            return Err(RpcError("logs are not served".into()).into());
        }
        Ok(Vec::new())
    }

    async fn sortition(&self, _: U256, _: u64) -> Result<Sortition, RpcError> {
        unreachable!("no log asks for it")
    }

    async fn deadlines(&self, _: U256, _: u64) -> Result<Deadlines, RpcError> {
        unreachable!("no log asks for it")
    }

    async fn dkg_window(&self, _: U256, _: u64) -> Result<UnixSecs, RpcError> {
        unreachable!("no log asks for it")
    }

    async fn listed(&self, _: u64) -> Result<u64, RpcError> {
        if self.listed_asked.fetch_add(1, Ordering::SeqCst) < self.listed_failures {
            return Err(RpcError("the count is not served".into()));
        }
        Ok(self.listed)
    }

    async fn eligible(&self, _: &[Address], _: UnixSecs) -> Result<BTreeSet<Address>, RpcError> {
        unreachable!("no log asks for it")
    }
}

struct NoAccount;

impl Account for NoAccount {
    async fn estimate(&self, _: &Call) -> Result<Estimate, RpcError> {
        pending().await
    }

    async fn send(&self, _: &Call, _: u64) -> Result<bool, RpcError> {
        pending().await
    }

    async fn key_chunk(&self, _: &KeyChunk) -> Result<OnChain, RpcError> {
        pending().await
    }
}

struct Quiet;

impl Network for Quiet {
    async fn publish(&self, _: Envelope) -> Result<(), NetworkError> {
        Ok(())
    }

    async fn fetch(&self, _: PeerMessage) -> Result<(), NetworkError> {
        Ok(())
    }

    fn admit(&self, _: Admission) {}

    fn connected(&self) -> usize {
        0
    }

    async fn close(&self) {}
}

struct NoData;

#[async_trait::async_trait]
impl DataAvailabilityReader for NoData {
    async fn retrieve(&self, _: DataReference) -> anyhow::Result<Vec<u8>> {
        pending().await
    }
}

async fn parts(
    dir: &Path,
    chain: Chain,
) -> (
    Settings,
    Parts<Chain, NoAccount, Quiet, MemoryBlobs>,
    InboxWriter,
) {
    let contracts = Contracts {
        chain_id: 1,
        interfold: Address::repeat_byte(1),
        registry: Address::repeat_byte(2),
        bonding: Address::repeat_byte(3),
        slashing: BTreeSet::new(),
        randomness: BTreeSet::new(),
        crypto_configs: BTreeMap::new(),
    };
    let settings = Settings {
        contracts,
        start_block: 0,
        confirmations: 0,
        max_log_range: 10,
        poll_interval: Duration::from_millis(10),
        startup_timeout: STARTUP,
        snapshot_every: 100,
        status_port: None,
        job_slots: 1,
        proof_slots: 1,
    };
    let (peers, inbox) = e3_p2p::inbox();
    let blobs = MemoryBlobs::default();
    let limits = JobLimits {
        threads: 1,
        scope: Default::default(),
    };
    let cipher = Cipher::from_password("node").await.unwrap();
    let parts = Parts {
        operator: PrivateKeySigner::random(),
        journal: Journal::open(dir.join("journal.redb")).unwrap(),
        blobs: blobs.clone(),
        jobs: JobRunner::new(blobs, cipher, Proofs::Placeholder, limits).unwrap(),
        rpc: chain,
        account: NoAccount,
        network: Quiet,
        inbox,
        availability: Arc::new(NoData),
        heartbeat: Heartbeat::start(&dir.join("ingestion"), 1, 0).unwrap(),
        notes: NoteFeed::open(&dir.join("notes")).unwrap(),
        notes_dir: dir.join("notes"),
    };
    (settings, parts, peers)
}

/// One step that left one effect, for an E3 the machine does not hold, in the outbox.
fn left_in_the_outbox() -> Step {
    let effect = Effect::Note(Note {
        e3: E3Id {
            chain_id: 1,
            number: U256::from(1),
        },
        event: Noted::ProofFailed {
            member: Address::ZERO,
            proof_type: ProofType::C0PkBfv,
        },
    });
    Step {
        seq: 1,
        entry: bincode::serialize(&(0u64, Input::Tick)).unwrap(),
        effects: vec![(
            EffectKey { seq: 1, index: 0 },
            bincode::serialize(&effect).unwrap(),
        )],
        snapshot: None,
        answers: None,
    }
}

/// What the last stop left waits for the chain: until the reader has caught up, nothing says
/// whether it is still owed.
#[tokio::test]
async fn recovered_work_waits_for_the_first_catch_up() {
    let behind = Chain {
        head: 5,
        logs_fail: true,
        ..Chain::default()
    };
    for (chain, left) in [(behind, 1), (Chain::default(), 0)] {
        let dir = tempfile::tempdir().unwrap();
        let (settings, mut parts, _peers) = parts(dir.path(), chain).await;
        parts.journal.commit(left_in_the_outbox()).unwrap();
        run(
            settings,
            parts,
            tokio::time::sleep(Duration::from_millis(300)),
        )
        .await
        .unwrap();
        let stored = Journal::read_existing(dir.path().join("journal.redb")).unwrap();
        assert_eq!(stored.outbox.len(), left);
    }
}

/// A node that lost its reader must end, so its supervisor can restart it.
#[tokio::test]
async fn a_reader_that_panics_ends_the_node() {
    let dir = tempfile::tempdir().unwrap();
    let chain = Chain {
        panics: true,
        ..Default::default()
    };
    let (settings, parts, _peers) = parts(dir.path(), chain).await;
    let ended = run(settings, parts, pending()).await.unwrap_err();
    assert!(matches!(ended, NodeError::TaskPanicked(..)), "{ended}");
}

#[tokio::test]
async fn a_network_that_stops_ends_the_node() {
    let dir = tempfile::tempdir().unwrap();
    let (settings, parts, peers) = parts(dir.path(), Chain::default()).await;
    drop(peers);
    let ended = run(settings, parts, pending()).await.unwrap_err();
    assert!(
        matches!(ended, NodeError::TaskEnded("the network")),
        "{ended}"
    );
}

#[tokio::test]
async fn a_stop_ends_the_node_without_an_error() {
    let dir = tempfile::tempdir().unwrap();
    let (settings, parts, _peers) = parts(dir.path(), Chain::default()).await;
    let stop = tokio::time::sleep(Duration::from_millis(50));
    run(settings, parts, stop).await.unwrap();
}

/// A node whose logs start after some operators registered would rank committees from part of
/// them, and submit no ticket if its own operator is among the missing.
#[tokio::test]
async fn a_node_that_read_fewer_operators_than_the_registry_lists_ends() {
    let dir = tempfile::tempdir().unwrap();
    let chain = Chain {
        head: 5,
        listed: 3,
        ..Default::default()
    };
    let (settings, parts, _peers) = parts(dir.path(), chain).await;
    let ended = run(settings, parts, pending()).await.unwrap_err();
    assert!(
        matches!(
            ended,
            NodeError::MissedRegistrations {
                listed: 3,
                read: 0,
                ..
            }
        ),
        "{ended}"
    );
}

/// Polls that succeed at the head do not finish the catch-up: the work a restart recovered waits
/// for it, so a count that never comes must not leave a node up that looks healthy.
#[tokio::test(start_paused = true)]
async fn a_registry_count_that_never_comes_ends_the_node_at_the_startup_deadline() {
    let dir = tempfile::tempdir().unwrap();
    let chain = Chain {
        head: 5,
        listed_failures: usize::MAX,
        ..Default::default()
    };
    let (settings, parts, _peers) = parts(dir.path(), chain).await;
    let ended = run(settings, parts, pending()).await.unwrap_err();
    assert!(matches!(ended, NodeError::ChainSilent { .. }), "{ended}");
}

/// New blocks keep the reader busy, and do not give a count that fails more time.
#[tokio::test(start_paused = true)]
async fn an_advancing_head_does_not_put_off_the_count_s_deadline() {
    let dir = tempfile::tempdir().unwrap();
    let chain = Chain {
        advancing: 3,
        listed_failures: usize::MAX,
        slow_logs: Duration::from_secs(1),
        ..Default::default()
    };
    let (mut settings, parts, _peers) = parts(dir.path(), chain).await;
    settings.max_log_range = 1;
    let ended = tokio::time::timeout(STARTUP * 2, run(settings, parts, pending()))
        .await
        .expect("the deadline ends the start")
        .unwrap_err();
    assert!(matches!(ended, NodeError::ChainSilent { .. }), "{ended}");
}

/// The start is not complete while the count is due, so an outage then still ends the node.
#[tokio::test(start_paused = true)]
async fn an_outage_while_the_count_is_due_ends_the_node() {
    let dir = tempfile::tempdir().unwrap();
    let chain = Chain {
        heads_ok: Some(1),
        listed_failures: 1,
        ..Default::default()
    };
    let (settings, parts, _peers) = parts(dir.path(), chain).await;
    let ended = run(settings, parts, pending()).await.unwrap_err();
    assert!(matches!(ended, NodeError::ChainSilent { .. }), "{ended}");
}

/// The time the history took is not the count's: its deadline starts when it is first due.
#[tokio::test(start_paused = true)]
async fn a_slow_last_read_leaves_the_count_its_whole_deadline() {
    let dir = tempfile::tempdir().unwrap();
    let chain = Chain {
        head: 5,
        listed_failures: 1,
        slow_logs: Duration::from_secs(20),
        ..Default::default()
    };
    let asked = chain.listed_asked.clone();
    let (mut settings, parts, _peers) = parts(dir.path(), chain).await;
    settings.startup_timeout = Duration::from_secs(10);
    run(settings, parts, tokio::time::sleep(STARTUP))
        .await
        .unwrap();
    assert_eq!(asked.load(Ordering::SeqCst), 2);
}

#[tokio::test(start_paused = true)]
async fn a_registry_count_that_fails_for_a_while_is_read_again() {
    let dir = tempfile::tempdir().unwrap();
    let chain = Chain {
        head: 5,
        listed_failures: 2,
        ..Default::default()
    };
    let asked = chain.listed_asked.clone();
    let (settings, parts, _peers) = parts(dir.path(), chain).await;
    run(settings, parts, tokio::time::sleep(STARTUP))
        .await
        .unwrap();
    assert_eq!(asked.load(Ordering::SeqCst), 3);
}

/// A chain node that never serves the node's logs ends the process for its supervisor, instead
/// of leaving a node up that reads nothing.
#[tokio::test(start_paused = true)]
async fn a_chain_node_that_refuses_the_logs_ends_the_node_at_the_startup_deadline() {
    let dir = tempfile::tempdir().unwrap();
    let chain = Chain {
        head: 5,
        logs_fail: true,
        ..Default::default()
    };
    let (settings, parts, _peers) = parts(dir.path(), chain).await;
    let ended = run(settings, parts, pending()).await.unwrap_err();
    assert!(matches!(ended, NodeError::ChainSilent { .. }), "{ended}");
}

/// Reading a long history takes longer than the startup limit, and keeps making progress.
#[tokio::test(start_paused = true)]
async fn a_long_catch_up_that_keeps_reading_is_fine() {
    let dir = tempfile::tempdir().unwrap();
    let chain = Chain {
        head: 1_000,
        slow_logs: Duration::from_secs(20),
        ..Default::default()
    };
    let (settings, parts, _peers) = parts(dir.path(), chain).await;
    run(settings, parts, tokio::time::sleep(STARTUP * 20))
        .await
        .unwrap();
}

/// Once the node has caught up, an outage is the node's to wait out.
#[tokio::test(start_paused = true)]
async fn an_outage_after_the_first_catch_up_does_not_end_the_node() {
    let dir = tempfile::tempdir().unwrap();
    let chain = Chain {
        heads_ok: Some(1),
        ..Default::default()
    };
    let (settings, parts, _peers) = parts(dir.path(), chain).await;
    run(settings, parts, tokio::time::sleep(STARTUP * 20))
        .await
        .unwrap();
}
