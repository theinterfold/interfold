// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Builds a node from its configuration and runs it. The `e3-node` binary and `interfold start`
//! both start the node here, each from its own configuration format.

use crate::{
    dir::{Inventory, NodeDir},
    heartbeat::Heartbeat,
    notes::NoteFeed,
    preflight::{self, retry_until, Verified},
    runtime::{now, run, Parts, Settings},
};
use alloy::{network::EthereumWallet, providers::ProviderBuilder, transports::Authorization};
use alloy_primitives::{keccak256, Address};
use alloy_signer_local::PrivateKeySigner;
use e3_blobs::FileBlobs;
use e3_chain::{ChainNode, Endpoint, Standing, Wallet};
use e3_crypto::Cipher;
use e3_data_availability::{AvailReader, DataAvailabilityReader, HttpObjectReader};
use e3_entrypoint::fence::ProcessFence;
use e3_jobs::{JobLimits, JobRunner};
use e3_journal::Journal;
use e3_p2p::{Network as _, P2p, P2pConfig};
use e3_zk_prover::BBPath;
use std::{future::Future, path::PathBuf, sync::Arc, time::Duration};
use tokio::time::Instant;
use tracing::info;

/// The longest one attempt to acknowledge the release may take, with its wait for the receipt.
const ACKNOWLEDGE_LIMIT: Duration = Duration::from_secs(6 * 60);

pub struct Config {
    /// An `http(s)://` or `ws(s)://` URL of the chain's RPC node.
    pub rpc_url: String,
    /// The credentials the RPC node asks for, if any.
    pub rpc_auth: Option<Authorization>,
    /// The chain the contracts are on; read from the RPC node when unset.
    pub chain_id: Option<u64>,
    pub interfold: Address,
    pub registry: Address,
    pub bonding: Address,
    pub start_block: u64,
    pub confirmations: u64,
    /// The most blocks one log request covers; the reader learns a provider's lower limit.
    pub max_log_range: u64,
    /// The wait between polls of the RPC node: for new blocks over HTTP, for a block's
    /// confirmations, and for a transaction's receipt.
    pub poll_interval: Duration,
    /// How long the start may wait for the chain and the prover, and how long the reader may go
    /// without a successful read before the node has first caught up.
    pub startup_timeout: Duration,
    pub availability: Availability,
    pub data_dir: PathBuf,
    /// The list of folders this node's key has run in, which `data_dir` joins.
    pub inventory: Inventory,
    /// Held while the node runs, so no other node or maintenance command can use its directory.
    pub fence: ProcessFence,
    pub operator: PrivateKeySigner,
    /// Seals the node's secrets at rest.
    pub cipher: Cipher,
    pub proving: Proving,
    /// CPU threads kept for the node's own loops.
    pub reserved_threads: usize,
    pub network: Network,
    /// Serves a read-only status page on this port of this machine.
    pub status_port: Option<u16>,
}

/// Where the node reads ciphertexts.
pub enum Availability {
    /// An Avail node's HTTP RPC.
    Avail(String),
    /// A service that serves objects by their hash, as test deployments run.
    Http(String),
}

/// How the node makes its proofs.
pub enum Proving {
    /// With the `bb` and circuits this release pins, which each start installs or repairs.
    Circuits(Prover),
    /// With the `bb` and circuits a test built for itself, as they are.
    #[cfg(any(test, feature = "testing"))]
    AsInstalled(Prover),
    /// Placeholder proofs, which only the mock verifiers of a test deployment accept.
    #[cfg(any(test, feature = "testing"))]
    Placeholder,
}

impl Proving {
    /// What makes the proofs, unless placeholders stand in.
    pub(crate) fn prover(&self) -> Option<&Prover> {
        match self {
            Proving::Circuits(prover) => Some(prover),
            #[cfg(any(test, feature = "testing"))]
            Proving::AsInstalled(prover) => Some(prover),
            #[cfg(any(test, feature = "testing"))]
            Proving::Placeholder => None,
        }
    }
}

pub struct Prover {
    pub bb: BBPath,
    /// The compiled circuits, by preset and committee size.
    pub circuits: PathBuf,
    /// How many proofs run at once: under the secure parameters each one can hold gigabytes.
    pub concurrent: usize,
    /// The longest one `bb` run may take.
    pub bb_timeout: Duration,
}

pub struct Network {
    /// Keeps the node apart from other networks: it is part of every protocol name.
    pub id: String,
    /// Keeps it apart from other deployments on that network: see [`deployment`].
    pub deployment: String,
    /// The ed25519 secret of the node's network identity.
    pub identity: [u8; 32],
    pub listen: Vec<String>,
    /// Peers to dial; one without its `/p2p/` identity is dialed by address.
    pub peers: Vec<String>,
}

impl Config {
    pub(crate) fn endpoint(&self) -> Endpoint {
        Endpoint::new(
            self.rpc_url.clone(),
            self.rpc_auth.clone(),
            self.poll_interval,
        )
    }
}

/// Runs the node until `stop` completes or the node fails. A stop during startup ends it too.
pub async fn launch(config: Config, stop: impl Future<Output = ()>) -> anyhow::Result<()> {
    tokio::pin!(stop);
    let verified = tokio::select! {
        verified = preflight::verify(config) => verified?,
        () = &mut stop => return Ok(()),
    };
    start(verified, stop).await
}

/// Builds the node from what startup verified and runs it. The fence in the configuration stays
/// held until this ends.
async fn start(
    verified: Verified,
    mut stop: std::pin::Pin<&mut impl Future<Output = ()>>,
) -> anyhow::Result<()> {
    let Verified {
        config,
        rpc,
        contracts,
        release,
        standing,
        proofs,
        threads,
        proof_slots,
    } = verified;
    let chain_id = contracts.chain_id;
    let journal = Journal::open(config.data_dir.join("journal.redb"))?;
    let heartbeat = Heartbeat::start(&config.data_dir.join("ingestion"), chain_id, now())?;
    let notes_dir = NodeDir::new(&config.data_dir).notes();
    let notes = NoteFeed::open(&notes_dir)?;
    let operator = config.operator.clone();
    let wallet = ProviderBuilder::new()
        .wallet(EthereumWallet::from(operator.clone()))
        .connect_client(config.endpoint().http()?);
    let unmined = config.data_dir.join("unmined.json");
    let wallet = Wallet::new(wallet, chain_id, config.confirmations, unmined)?;
    if let Standing::Unacknowledged(call) = &standing {
        let deadline = Instant::now() + config.startup_timeout;
        let what = "acknowledging the release";
        let landed = retry_until(deadline, ACKNOWLEDGE_LIMIT, what, || wallet.send_once(call));
        let landed = tokio::select! {
            landed = landed => landed?,
            () = &mut stop => return Ok(()),
        };
        anyhow::ensure!(
            landed,
            "the chain refused this node's release acknowledgement"
        );
    }
    info!(
        release = %release.id,
        protocol = release.protocol_version,
        generation = release.node_generation,
        "the chain accepts this node's release"
    );

    let blobs = FileBlobs::open(config.data_dir.join("blobs"))?;
    let p2p = P2pConfig {
        identity: config.network.identity,
        network: config.network.id,
        deployment: config.network.deployment,
        protocol_version: release.protocol_version,
        listen: parse(&config.network.listen)?,
        peers: parse(&config.network.peers)?,
    };
    let (network, inbox) = tokio::select! {
        started = P2p::start(p2p, operator.address(), blobs.clone()) => started?,
        () = &mut stop => return Ok(()),
    };
    let listening: Vec<String> = network
        .listening()
        .iter()
        .map(ToString::to_string)
        .collect();
    std::fs::write(config.data_dir.join("listening"), listening.join("\n"))?;

    let availability: Arc<dyn DataAvailabilityReader> = match config.availability {
        Availability::Avail(url) => Arc::new(AvailReader::new(url)?),
        Availability::Http(url) => Arc::new(HttpObjectReader::new(url)?),
    };
    let settings = Settings {
        contracts: contracts.clone(),
        start_block: config.start_block,
        confirmations: config.confirmations,
        max_log_range: config.max_log_range,
        poll_interval: config.poll_interval,
        startup_timeout: config.startup_timeout,
        snapshot_every: 100,
        status_port: config.status_port,
        job_slots: threads,
        proof_slots,
    };
    let scope = keccak256([release.id.as_slice(), operator.address().as_slice()].concat());
    let parts = Parts {
        operator,
        journal,
        blobs: blobs.clone(),
        jobs: JobRunner::new(blobs, config.cipher, proofs, JobLimits { threads, scope })?,
        rpc: ChainNode::new(rpc, contracts),
        account: wallet,
        network,
        inbox,
        availability,
        heartbeat,
        notes,
        notes_dir,
    };
    Ok(run(settings, parts, stop.as_mut()).await?)
}

/// What keeps the nodes of one deployment apart from another's on the same network: the Interfold
/// contract they serve. The chain ID is optional in a node's configuration, so two nodes of one
/// deployment could disagree on it, and each would split from the other. A bootstrap node knows
/// this from its configuration, with no access to the chain.
pub fn deployment(interfold: Address) -> String {
    alloy_primitives::hex::encode(&keccak256(interfold.as_slice())[..8])
}

/// Runs a node that only helps the others find each other, until `stop` completes: it answers
/// their lookups and takes no part in their messages, the chain, or proofs.
pub async fn bootstrap(network: Network, stop: impl Future<Output = ()>) -> anyhow::Result<()> {
    let release = e3_ciphernode_config::current_node_release();
    let (p2p, stopped) = P2p::bootstrap(P2pConfig {
        identity: network.identity,
        network: network.id,
        deployment: network.deployment,
        protocol_version: release.protocol_version,
        listen: parse(&network.listen)?,
        peers: parse(&network.peers)?,
    })
    .await?;
    tokio::select! {
        () = stopped.closed() => anyhow::bail!("the network stopped"),
        () = stop => {
            p2p.close().await;
            Ok(())
        }
    }
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
