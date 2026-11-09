// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Builds a node from its configuration and runs it. The `e3-node` binary and `interfold start`
//! both start the node here, each from its own configuration format.

use crate::{
    heartbeat::Heartbeat,
    memory,
    runtime::{now, run, Parts, Settings},
};
use alloy::{
    network::EthereumWallet,
    providers::{Provider, ProviderBuilder},
    rpc::client::{ClientBuilder, RpcClient},
    transports::{
        http::reqwest::{
            header::{HeaderMap, HeaderValue, AUTHORIZATION},
            Client, Url,
        },
        ws::WsConnect,
        Authorization,
    },
};
use alloy_primitives::{keccak256, Address};
use alloy_signer_local::PrivateKeySigner;
use e3_blobs::FileBlobs;
use e3_chain::{ChainNode, Contracts, Release, Wallet};
use e3_crypto::Cipher;
use e3_data_availability::{AvailReader, DataAvailabilityReader, HttpObjectReader};
use e3_evm_contracts::{ICiphernodeRegistry, IInterfold};
use e3_jobs::{Circuits, JobLimits, JobRunner, Proofs};
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
    /// The credentials the RPC node asks for, if any.
    pub rpc_auth: Option<Authorization>,
    /// The chain the contracts are on; read from the RPC node when unset.
    pub chain_id: Option<u64>,
    pub interfold: Address,
    pub registry: Address,
    pub bonding: Address,
    pub start_block: u64,
    pub confirmations: u64,
    /// The most blocks one log request covers; the reader halves it while requests fail.
    pub max_log_range: u64,
    /// The wait between polls of the RPC node: for new blocks over HTTP, for a block's
    /// confirmations, and for a transaction's receipt.
    pub poll_interval: Duration,
    pub availability: Availability,
    pub data_dir: PathBuf,
    pub operator: PrivateKeySigner,
    /// Seals the node's secrets at rest.
    pub cipher: Cipher,
    /// Without a prover the node makes placeholder proofs, which only the mock verifiers of a test
    /// deployment accept.
    pub prover: Option<Prover>,
    /// CPU threads kept for the node's own loops.
    pub reserved_threads: usize,
    pub network: Network,
}

/// Where the node reads ciphertexts.
pub enum Availability {
    /// An Avail node's HTTP RPC.
    Avail(String),
    /// A service that serves objects by their hash, as test deployments run.
    Http(String),
}

pub struct Prover {
    pub bb: PathBuf,
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
    /// The ed25519 secret of the node's network identity.
    pub identity: [u8; 32],
    pub listen: Vec<String>,
    /// Peers to dial; one without its `/p2p/` identity is dialed by address.
    pub peers: Vec<String>,
}

/// Runs the node until it fails.
pub async fn launch(config: Config) -> anyhow::Result<()> {
    // Before the node asks the chain or the network anything, so a second node on the directory
    // stops at once.
    let _held = lock_data_dir(&config.data_dir)?;
    let (auth, poll) = (config.rpc_auth.as_ref(), config.poll_interval);
    let chain =
        ProviderBuilder::new().connect_client(rpc_client(&config.rpc_url, auth, poll).await?);
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
    let journal = Journal::open(config.data_dir.join("journal.redb"))?;
    let heartbeat = Heartbeat::start(&config.data_dir.join("ingestion"), chain_id, now())?;
    let (proofs, threads) = proofs(&config)?;
    let operator = config.operator;
    // Over a WebSocket, alloy's receipt waits would keep a new-block subscription open for good;
    // over HTTP they poll only while a transaction is unmined.
    let wallet = ProviderBuilder::new()
        .wallet(EthereumWallet::from(operator.clone()))
        .connect_client(rpc_client(&http_url(&config.rpc_url)?, auth, poll).await?);
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
        snapshot_every: 100,
    };
    let scope = keccak256([release.id.as_slice(), operator.address().as_slice()].concat());
    let parts = Parts {
        operator,
        journal,
        blobs: blobs.clone(),
        jobs: JobRunner::new(blobs, config.cipher, proofs, JobLimits { threads, scope })?,
        rpc: ChainNode::new(chain, contracts),
        account: wallet,
        network,
        inbound,
        availability,
        heartbeat,
    };
    Err(run(settings, parts).await.into())
}

/// The longest an HTTP request to the RPC node may take.
const HTTP_ANSWER: Duration = Duration::from_secs(60);

/// A connection to the RPC node at `url` that presents `auth` and polls every `poll`.
async fn rpc_client(
    url: &str,
    auth: Option<&Authorization>,
    poll: Duration,
) -> anyhow::Result<RpcClient> {
    if url.starts_with("ws://") || url.starts_with("wss://") {
        let mut connect = WsConnect::new(url);
        if let Some(auth) = auth {
            connect = connect.with_auth(auth.clone());
        }
        return Ok(ClientBuilder::default()
            .ws(connect)
            .await?
            .with_poll_interval(poll));
    }
    let mut headers = HeaderMap::new();
    if let Some(auth) = auth {
        let mut value = HeaderValue::from_str(&auth.to_string())?;
        value.set_sensitive(true);
        headers.insert(AUTHORIZATION, value);
    }
    // An RPC node can hold a request without ever answering; a send or a read then fails, and its
    // caller tries again.
    let client = Client::builder()
        .default_headers(headers)
        .timeout(HTTP_ANSWER)
        .build()?;
    Ok(ClientBuilder::default()
        .http_with_client(client, url.parse()?)
        .with_poll_interval(poll))
}

/// The HTTP URL of the RPC node at `url`, which serves HTTP where it serves a WebSocket.
fn http_url(url: &str) -> anyhow::Result<String> {
    let mut url: Url = url.parse()?;
    let scheme = match url.scheme() {
        "ws" => "http",
        "wss" => "https",
        _ => return Ok(url.into()),
    };
    if url.set_scheme(scheme).is_err() {
        anyhow::bail!("the RPC URL {url} has no HTTP form");
    }
    Ok(url.into())
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

/// The node's proofs, and the threads its other work may use.
fn proofs(config: &Config) -> anyhow::Result<(Proofs, usize)> {
    let Some(prover) = &config.prover else {
        let threads = memory::threads_for_placeholders(config.reserved_threads);
        return Ok((Proofs::Placeholder, threads));
    };
    // Proofs that a stop cut short run again from the start, so their files go.
    let proving = config.data_dir.join("proving");
    if let Err(error) = std::fs::remove_dir_all(&proving) {
        if error.kind() != std::io::ErrorKind::NotFound {
            return Err(error.into());
        }
    }
    let bb = BBPath::Custom(prover.bb.clone());
    let backend =
        ZkBackend::new(bb, prover.circuits.clone(), proving).with_bb_timeout(prover.bb_timeout);
    let capacity = memory::capacity(prover.concurrent, config.reserved_threads)?;
    let circuits = Circuits::new(
        ZkProver::new(&backend),
        capacity.proofs,
        capacity.bb_threads,
    )?;
    Ok((Proofs::Circuits(Box::new(circuits)), capacity.threads))
}

/// The layout of the node's files in a data directory: the machine's encoding, and the version of
/// the blob store's folders and the wallet's file, which changes with either. A node refuses a
/// directory in another layout rather than misread its journal or delete its blobs.
pub fn data_layout() -> String {
    const STORE_VERSION: u32 = 1;
    let encoding = e3_protocol::ENCODING_VERSION;
    format!("interfold-node-v2 encoding {encoding} store {STORE_VERSION}")
}

/// The files of the node in a data directory; others, such as its configuration, may share it.
const NODE_FILES: [&str; 3] = ["journal.redb", "blobs", "unmined.json"];

/// Holds `dir` for this process until the returned file closes: one node runs on a data directory,
/// whichever command starts it.
fn lock_data_dir(dir: &Path) -> anyhow::Result<std::fs::File> {
    std::fs::create_dir_all(dir)?;
    let file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(dir.join("node.lock"))?;
    match file.try_lock() {
        Ok(()) => Ok(file),
        Err(std::fs::TryLockError::WouldBlock) => {
            anyhow::bail!("another node runs on {}", dir.display())
        }
        Err(std::fs::TryLockError::Error(error)) => Err(error.into()),
    }
}

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

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };

    /// An RPC node that asks for credentials gets them with each request.
    #[tokio::test]
    async fn the_rpc_node_gets_the_configured_credentials() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let node = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            let mut buffer = [0; 1024];
            let body = loop {
                let read = socket.read(&mut buffer).await.unwrap();
                request.extend_from_slice(&buffer[..read]);
                let text = String::from_utf8_lossy(&request).into_owned();
                if let Some((_, body)) = text.split_once("\r\n\r\n") {
                    if let Ok(body) = serde_json::from_str::<serde_json::Value>(body) {
                        break body;
                    }
                }
            };
            let answer =
                serde_json::json!({ "jsonrpc": "2.0", "id": body["id"], "result": "0x7a69" })
                    .to_string();
            let response = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n{answer}",
                answer.len()
            );
            socket.write_all(response.as_bytes()).await.unwrap();
            String::from_utf8_lossy(&request).to_lowercase()
        });
        let poll = Duration::from_millis(250);
        let client = rpc_client(&url, Some(&Authorization::bearer("secret")), poll)
            .await
            .unwrap();
        let chain_id = ProviderBuilder::new()
            .connect_client(client)
            .get_chain_id()
            .await
            .unwrap();
        assert_eq!(chain_id, 31337);
        assert!(node.await.unwrap().contains("authorization: bearer secret"));
    }

    /// The wallet sends over HTTP to the RPC node the reader reads over a WebSocket, still over
    /// TLS and on the same path, which often carries the provider's key.
    #[test]
    fn a_node_cannot_run_on_a_data_directory_another_holds() {
        let dir = tempfile::tempdir().unwrap();
        let held = lock_data_dir(dir.path()).unwrap();
        let refused = lock_data_dir(dir.path()).unwrap_err();
        assert!(refused.to_string().contains("another node runs on"));
        drop(held);
        lock_data_dir(dir.path()).unwrap();
    }

    #[test]
    fn a_websocket_url_s_http_form_keeps_tls_and_the_path() {
        assert_eq!(
            http_url("ws://127.0.0.1:8545").unwrap(),
            "http://127.0.0.1:8545/"
        );
        assert_eq!(
            http_url("wss://eth.example/v2/key?x=1").unwrap(),
            "https://eth.example/v2/key?x=1"
        );
        assert_eq!(
            http_url("https://eth.example/v2/key").unwrap(),
            "https://eth.example/v2/key"
        );
    }
}
