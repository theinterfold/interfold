// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Runs several v2 nodes in one process over an in-memory network against one chain: the local
//! end-to-end setup until the nodes have a peer-to-peer network.

use alloy::{network::EthereumWallet, providers::ProviderBuilder, transports::http::reqwest::Url};
use alloy_primitives::Address;
use alloy_signer_local::PrivateKeySigner;
use anyhow::Context;
use e3_blobs::FileBlobs;
use e3_chain::{ChainNode, Contracts, Release, Wallet};
use e3_crypto::Cipher;
use e3_data_availability::{DataAvailabilityReader, HttpObjectReader};
use e3_evm_contracts::ICiphernodeRegistry;
use e3_jobs::JobRunner;
use e3_journal::Journal;
use e3_node::{run, Parts, Settings};
use e3_p2p::{MemoryNetwork, SharedBlobs};
use serde::Deserialize;
use std::{collections::BTreeSet, path::PathBuf, sync::Arc, time::Duration};
use tokio::task::JoinSet;
use tracing::error;
use tracing_subscriber::EnvFilter;

#[derive(Deserialize)]
struct Config {
    rpc_url: String,
    chain_id: u64,
    interfold: Address,
    registry: Address,
    bonding: Address,
    start_block: u64,
    confirmations: u64,
    poll_interval_ms: u64,
    availability_url: String,
    data_dir: PathBuf,
    /// One node per operator private key.
    operators: Vec<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();
    let path = std::env::args()
        .nth(1)
        .context("usage: e3-node-cluster <config.json>")?;
    let config: Config = serde_json::from_slice(&std::fs::read(&path)?)?;
    let url: Url = config.rpc_url.parse()?;
    let chain = ProviderBuilder::new().connect_http(url.clone());
    let randomness = ICiphernodeRegistry::new(config.registry, &chain)
        .randomnessProvider()
        .call()
        .await?;
    let settings = Settings {
        contracts: Contracts {
            chain_id: config.chain_id,
            interfold: config.interfold,
            registry: config.registry,
            bonding: config.bonding,
            randomness: BTreeSet::from([randomness]),
            crypto_configs: e3_jobs::crypto_configs(),
        },
        start_block: config.start_block,
        confirmations: config.confirmations,
        max_log_range: 2_000,
        poll_interval: Duration::from_millis(config.poll_interval_ms),
        snapshot_every: 100,
    };
    let built = e3_ciphernode_config::current_node_release();
    let release = Release {
        id: built.release_id(),
        protocol_version: built.protocol_version,
        node_generation: built.node_generation,
    };
    let availability: Arc<dyn DataAvailabilityReader> =
        Arc::new(HttpObjectReader::new(config.availability_url)?);
    let network = MemoryNetwork::default();
    let mut nodes = JoinSet::new();
    for (index, key) in config.operators.iter().enumerate() {
        let operator: PrivateKeySigner = key.parse()?;
        let dir = config.data_dir.join(format!("node-{index}"));
        std::fs::create_dir_all(&dir)?;
        let blobs = FileBlobs::open(dir.join("blobs"))?;
        let shared: SharedBlobs = Arc::new(blobs.clone());
        let (peer, inbound) = network.join(operator.address(), shared);
        let wallet = ProviderBuilder::new()
            .wallet(EthereumWallet::from(operator.clone()))
            .connect_http(url.clone());
        let wallet = Wallet::new(wallet, config.chain_id);
        wallet
            .acknowledge_release(&settings.contracts, release)
            .await
            .with_context(|| format!("node {index} cannot join"))?;
        let parts = Parts {
            operator: operator.clone(),
            journal: Journal::open(dir.join("journal.redb"))?,
            blobs: blobs.clone(),
            jobs: JobRunner::new(
                blobs,
                Cipher::from_password(&format!("node {index}")).await?,
            ),
            rpc: ChainNode::new(
                ProviderBuilder::new().connect_http(url.clone()),
                settings.contracts.clone(),
            ),
            account: wallet,
            network: peer,
            inbound,
            availability: availability.clone(),
        };
        let settings = settings.clone();
        nodes.spawn(async move { (operator.address(), run(settings, parts).await) });
    }
    while let Some(stopped) = nodes.join_next().await {
        let (operator, failure) = stopped?;
        error!(%operator, %failure, "node stopped");
    }
    Ok(())
}
