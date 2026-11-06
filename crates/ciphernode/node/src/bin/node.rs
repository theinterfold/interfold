// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Runs one v2 node from a JSON configuration file.

use alloy::{network::EthereumWallet, providers::ProviderBuilder, transports::http::reqwest::Url};
use alloy_primitives::{Address, B256};
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
use e3_p2p::{P2p, P2pConfig};
use serde::Deserialize;
use std::{collections::BTreeSet, path::PathBuf, sync::Arc, time::Duration};
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
    /// The operator's private key.
    operator: String,
    /// Seals the node's secrets at rest.
    cipher_password: String,
    network: NetworkConfig,
}

#[derive(Deserialize)]
struct NetworkConfig {
    name: String,
    /// The ed25519 secret of the node's network identity.
    identity: B256,
    listen: Vec<String>,
    peers: Vec<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();
    let path = std::env::args()
        .nth(1)
        .context("usage: e3-node <config.json>")?;
    let config: Config = serde_json::from_slice(&std::fs::read(&path)?)?;
    let url: Url = config.rpc_url.parse()?;
    let operator: PrivateKeySigner = config.operator.parse()?;
    let chain = ProviderBuilder::new().connect_http(url.clone());
    let randomness = ICiphernodeRegistry::new(config.registry, &chain)
        .randomnessProvider()
        .call()
        .await?;
    let contracts = Contracts {
        chain_id: config.chain_id,
        interfold: config.interfold,
        registry: config.registry,
        bonding: config.bonding,
        randomness: BTreeSet::from([randomness]),
        crypto_configs: e3_jobs::crypto_configs(),
    };
    let built = e3_ciphernode_config::current_node_release();
    let release = Release {
        id: built.release_id(),
        protocol_version: built.protocol_version,
        node_generation: built.node_generation,
    };
    let wallet = ProviderBuilder::new()
        .wallet(EthereumWallet::from(operator.clone()))
        .connect_http(url);
    let wallet = Wallet::new(wallet, config.chain_id);
    wallet.acknowledge_release(&contracts, release).await?;

    std::fs::create_dir_all(&config.data_dir)?;
    let blobs = FileBlobs::open(config.data_dir.join("blobs"))?;
    let p2p = P2pConfig {
        identity: config.network.identity.0,
        network: config.network.name,
        protocol_version: release.protocol_version,
        listen: parse(&config.network.listen)?,
        peers: parse(&config.network.peers)?,
    };
    let (network, inbound) = P2p::start(p2p, operator.address(), Arc::new(blobs.clone())).await?;
    let listening: Vec<String> = network
        .listening()
        .iter()
        .map(ToString::to_string)
        .collect();
    std::fs::write(config.data_dir.join("listening"), listening.join("\n"))?;

    let availability: Arc<dyn DataAvailabilityReader> =
        Arc::new(HttpObjectReader::new(config.availability_url)?);
    let settings = Settings {
        contracts: contracts.clone(),
        start_block: config.start_block,
        confirmations: config.confirmations,
        max_log_range: 2_000,
        poll_interval: Duration::from_millis(config.poll_interval_ms),
        snapshot_every: 100,
    };
    let parts = Parts {
        operator,
        journal: Journal::open(config.data_dir.join("journal.redb"))?,
        blobs: blobs.clone(),
        jobs: JobRunner::new(blobs, Cipher::from_password(&config.cipher_password).await?),
        rpc: ChainNode::new(chain, contracts),
        account: wallet,
        network,
        inbound,
        availability,
    };
    Err(run(settings, parts).await.into())
}

fn parse<T: std::str::FromStr>(values: &[String]) -> anyhow::Result<Vec<T>>
where
    T::Err: std::error::Error + Send + Sync + 'static,
{
    Ok(values
        .iter()
        .map(|value| value.parse())
        .collect::<Result<_, _>>()?)
}
