// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Runs one v2 node from a JSON configuration file.

use alloy_primitives::{Address, B256};
use alloy_signer_local::PrivateKeySigner;
use anyhow::Context;
use e3_crypto::Cipher;
use e3_node::launch::{launch, Availability, Config, Network, Prover};
use serde::Deserialize;
use std::{path::PathBuf, time::Duration};
use tracing_subscriber::EnvFilter;

#[derive(Deserialize)]
struct JsonConfig {
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
    /// Where `bin/bb` and the compiled `circuits` are, for real proofs.
    #[serde(default)]
    noir_dir: Option<PathBuf>,
    /// How many proofs run at once, two unless set.
    #[serde(default)]
    concurrent_proofs: Option<usize>,
    network: JsonNetwork,
}

#[derive(Deserialize)]
struct JsonNetwork {
    id: String,
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
    let config: JsonConfig = serde_json::from_slice(&std::fs::read(&path)?)?;
    let operator: PrivateKeySigner = config.operator.parse()?;
    launch(Config {
        rpc_url: config.rpc_url,
        rpc_auth: None,
        chain_id: Some(config.chain_id),
        interfold: config.interfold,
        registry: config.registry,
        bonding: config.bonding,
        start_block: config.start_block,
        confirmations: config.confirmations,
        max_log_range: 2_000,
        poll_interval: Duration::from_millis(config.poll_interval_ms),
        availability: Availability::Http(config.availability_url),
        data_dir: config.data_dir,
        operator,
        cipher: Cipher::from_password(&config.cipher_password).await?,
        prover: config.noir_dir.map(|noir| Prover {
            bb: noir.join("bin").join("bb"),
            circuits: noir.join("circuits"),
            concurrent: config.concurrent_proofs.unwrap_or(2),
            bb_timeout: Duration::from_secs(12 * 60 * 60),
        }),
        reserved_threads: 1,
        network: Network {
            id: config.network.id,
            identity: config.network.identity.0,
            listen: config.network.listen,
            peers: config.network.peers,
        },
    })
    .await
}
