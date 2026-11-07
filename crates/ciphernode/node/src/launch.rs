// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Builds a node from its configuration and runs it. The `e3-node` binary and `interfold start`
//! both start the node here, each from its own configuration format.

use crate::{run, Parts, Settings};
use alloy::{network::EthereumWallet, providers::Provider, providers::ProviderBuilder};
use alloy_primitives::Address;
use alloy_signer_local::PrivateKeySigner;
use e3_blobs::FileBlobs;
use e3_chain::{ChainNode, Contracts, Release, Wallet};
use e3_crypto::Cipher;
use e3_data_availability::{DataAvailabilityReader, HttpObjectReader};
use e3_evm_contracts::{ICiphernodeRegistry, IInterfold};
use e3_jobs::{Circuits, JobRunner, Proofs};
use e3_journal::Journal;
use e3_p2p::{P2p, P2pConfig};
use e3_zk_prover::{BBPath, ZkBackend, ZkProver};
use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

pub struct Config {
    /// An `http(s)://` or `ws(s)://` URL of the chain's RPC node.
    pub rpc_url: String,
    /// The chain the contracts are on; read from the RPC node when unset.
    pub chain_id: Option<u64>,
    pub interfold: Address,
    pub registry: Address,
    pub bonding: Address,
    pub start_block: u64,
    pub confirmations: u64,
    pub poll_interval: Duration,
    pub availability_url: String,
    pub data_dir: PathBuf,
    pub operator: PrivateKeySigner,
    /// Seals the node's secrets at rest.
    pub cipher: Cipher,
    /// Without a prover the node makes placeholder proofs, which only the mock verifiers of a test
    /// deployment accept.
    pub prover: Option<Prover>,
    pub network: Network,
}

pub struct Prover {
    pub bb: PathBuf,
    /// The compiled circuits, by preset and committee size.
    pub circuits: PathBuf,
    /// How many proofs run at once: under the secure parameters each one can hold gigabytes.
    pub concurrent: usize,
}

pub struct Network {
    /// Keeps the node apart from other networks: it is part of every protocol name.
    pub id: String,
    /// The ed25519 secret of the node's network identity.
    pub identity: [u8; 32],
    pub listen: Vec<String>,
    /// Peers to dial; one without its `/p2p/` identity is dialed by address.
    pub peers: Vec<String>,
}

/// Runs the node until it fails.
pub async fn launch(config: Config) -> anyhow::Result<()> {
    let chain = ProviderBuilder::new().connect(&config.rpc_url).await?;
    let chain_id = match config.chain_id {
        Some(chain_id) => chain_id,
        None => chain.get_chain_id().await?,
    };
    let randomness = ICiphernodeRegistry::new(config.registry, &chain)
        .randomnessProvider()
        .call()
        .await?;
    let slashing = IInterfold::new(config.interfold, &chain)
        .slashingManager()
        .call()
        .await?;
    let contracts = Contracts {
        chain_id,
        interfold: config.interfold,
        registry: config.registry,
        bonding: config.bonding,
        slashing: BTreeSet::from([slashing]),
        randomness: BTreeSet::from([randomness]),
        crypto_configs: e3_jobs::crypto_configs(),
    };
    let built = e3_ciphernode_config::current_node_release();
    let release = Release {
        id: built.release_id(),
        protocol_version: built.protocol_version,
        node_generation: built.node_generation,
    };
    open_data_dir(&config.data_dir)?;
    let proofs = proofs(&config)?;
    let operator = config.operator;
    let wallet = ProviderBuilder::new()
        .wallet(EthereumWallet::from(operator.clone()))
        .connect(&config.rpc_url)
        .await?;
    let unmined = config.data_dir.join("unmined.json");
    let wallet = Wallet::new(wallet, chain_id, config.confirmations, unmined)?;
    wallet.acknowledge_release(&contracts, release).await?;

    let blobs = FileBlobs::open(config.data_dir.join("blobs"))?;
    let p2p = P2pConfig {
        identity: config.network.identity,
        network: config.network.id,
        protocol_version: release.protocol_version,
        listen: parse(&config.network.listen)?,
        peers: parse(&config.network.peers)?,
    };
    let (network, inbound) = P2p::start(p2p, operator.address(), blobs.clone()).await?;
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
        poll_interval: config.poll_interval,
        snapshot_every: 100,
    };
    let parts = Parts {
        operator,
        journal: Journal::open(config.data_dir.join("journal.redb"))?,
        blobs: blobs.clone(),
        jobs: JobRunner::new(blobs, config.cipher, proofs),
        rpc: ChainNode::new(chain, contracts),
        account: wallet,
        network,
        inbound,
        availability,
    };
    Err(run(settings, parts).await.into())
}

/// Runs a node that only helps the others find each other: it answers their lookups and takes no
/// part in their messages, the chain, or proofs.
pub async fn bootstrap(network: Network) -> anyhow::Result<()> {
    let release = e3_ciphernode_config::current_node_release();
    let _p2p = P2p::bootstrap(P2pConfig {
        identity: network.identity,
        network: network.id,
        protocol_version: release.protocol_version,
        listen: parse(&network.listen)?,
        peers: parse(&network.peers)?,
    })
    .await?;
    std::future::pending().await
}

fn proofs(config: &Config) -> anyhow::Result<Proofs> {
    let Some(prover) = &config.prover else {
        return Ok(Proofs::Placeholder);
    };
    // Proofs that a stop cut short run again from the start, so their files go.
    let proving = config.data_dir.join("proving");
    if let Err(error) = std::fs::remove_dir_all(&proving) {
        if error.kind() != std::io::ErrorKind::NotFound {
            return Err(error.into());
        }
    }
    let bb = BBPath::Custom(prover.bb.clone());
    let backend = ZkBackend::new(bb, prover.circuits.clone(), proving);
    let circuits = Circuits::new(ZkProver::new(&backend), prover.concurrent)?;
    Ok(Proofs::Circuits(Box::new(circuits)))
}

/// The layout of the node's files in a data directory: the machine's encoding, and the version of
/// the blob store's folders and the wallet's file, which changes with either. A node refuses a
/// directory in another layout rather than misread its journal or delete its blobs.
fn data_layout() -> String {
    const STORE_VERSION: u32 = 1;
    let encoding = e3_protocol::ENCODING_VERSION;
    format!("interfold-node-v2 encoding {encoding} store {STORE_VERSION}")
}

/// The files of the node in a data directory; others, such as its configuration, may share it.
const NODE_FILES: [&str; 3] = ["journal.redb", "blobs", "unmined.json"];

fn open_data_dir(dir: &Path) -> anyhow::Result<()> {
    std::fs::create_dir_all(dir)?;
    let (marker, layout) = (dir.join("LAYOUT"), data_layout());
    match std::fs::read_to_string(&marker) {
        Ok(found) => anyhow::ensure!(
            found.trim() == layout,
            "{} holds node data in layout '{}', not '{layout}': use an empty directory",
            dir.display(),
            found.trim()
        ),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let unmarked = NODE_FILES.iter().any(|file| dir.join(file).exists());
            anyhow::ensure!(
                !unmarked,
                "{} holds node data of an unknown layout: use an empty directory",
                dir.display()
            );
            std::fs::write(&marker, layout)?;
        }
        Err(error) => return Err(error.into()),
    }
    Ok(())
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
