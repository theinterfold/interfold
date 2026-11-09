// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! The runtime over stand-ins for the chain, the network and the availability layer.

use super::*;
use alloy_primitives::U256;
use e3_blobs::MemoryBlobs;
use e3_chain::{Call, Deadlines, Estimate, RawLog, RpcError, Sortition};
use e3_crypto::Cipher;
use e3_data_availability::DataReference;
use e3_jobs::{JobLimits, Proofs};
use e3_p2p::NetworkError;
use e3_protocol::wire::Envelope;
use futures::stream::BoxStream;
use std::{collections::BTreeMap, future::pending, path::Path};

#[derive(Clone)]
struct Chain {
    panics: bool,
}

impl Rpc for Chain {
    async fn head(&self) -> Result<u64, RpcError> {
        assert!(!self.panics, "the reader panics");
        Ok(0)
    }

    async fn announce(&self, _: &[Address]) -> Result<Option<BoxStream<'static, u64>>, RpcError> {
        Ok(None)
    }

    async fn logs(&self, _: &[Address], _: u64, _: u64) -> Result<Vec<RawLog>, RpcError> {
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
}

struct Quiet;

impl Network for Quiet {
    async fn publish(&self, _: Envelope) -> Result<(), NetworkError> {
        Ok(())
    }

    async fn fetch(&self, _: PeerMessage) -> Result<(), NetworkError> {
        Ok(())
    }

    fn admit(&self, _: BTreeSet<Address>) {}
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
    panics: bool,
) -> (
    Settings,
    Parts<Chain, NoAccount, Quiet, MemoryBlobs>,
    mpsc::Sender<PeerMessage>,
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
        snapshot_every: 100,
        job_slots: 1,
    };
    let (peers, inbound) = mpsc::channel(1);
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
        rpc: Chain { panics },
        account: NoAccount,
        network: Quiet,
        inbound,
        availability: Arc::new(NoData),
        heartbeat: Heartbeat::start(&dir.join("ingestion"), 1, 0).unwrap(),
    };
    (settings, parts, peers)
}

/// A node that lost its reader must end, so its supervisor can restart it.
#[tokio::test]
async fn a_reader_that_panics_ends_the_node() {
    let dir = tempfile::tempdir().unwrap();
    let (settings, parts, _peers) = parts(dir.path(), true).await;
    let ended = run(settings, parts, pending()).await.unwrap_err();
    assert!(matches!(ended, NodeError::TaskPanicked(..)), "{ended}");
}

#[tokio::test]
async fn a_network_that_stops_ends_the_node() {
    let dir = tempfile::tempdir().unwrap();
    let (settings, parts, peers) = parts(dir.path(), false).await;
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
    let (settings, parts, _peers) = parts(dir.path(), false).await;
    let stop = tokio::time::sleep(Duration::from_millis(50));
    run(settings, parts, stop).await.unwrap();
}
