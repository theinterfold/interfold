// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! The v2 node's configuration from the CLI's: one chain with its contracts and availability
//! service, the operator key that `interfold wallet set` stored, and the node's port and peers.

use crate::keystore;
use alloy::{signers::local::PrivateKeySigner, transports::Authorization};
use anyhow::{bail, Context, Result};
use e3_ciphernode_config::NodeConfig;
use e3_crypto::Cipher;
use e3_entrypoint::fence::ProcessFence;
use e3_evm_config::{DataAvailabilityMode, RpcAuth};
use e3_node::launch::{Availability, Config, Network, Prover, Proving};
use e3_zk_prover::BBPath;
use std::time::Duration;

pub async fn config(config: &NodeConfig, fence: ProcessFence) -> Result<Config> {
    let chains: Vec<_> = config
        .chains()
        .iter()
        .filter(|chain| chain.enabled.unwrap_or(true))
        .collect();
    let [chain] = chains.as_slice() else {
        bail!(
            "the node runs on one chain, and {} are enabled",
            chains.len()
        );
    };
    let availability = match &chain.data_availability {
        Some(availability) => match availability.mode {
            DataAvailabilityMode::Avail => Availability::Avail(availability.rpc_url.clone()),
            DataAvailabilityMode::MockHttp => Availability::Http(availability.rpc_url.clone()),
        },
        None => bail!("the chain has no data availability service"),
    };
    let contracts = &chain.contracts;
    let read = [
        &contracts.interfold,
        &contracts.ciphernode_registry,
        &contracts.bonding_registry,
    ];
    // Reading a public chain from genesis would take days of log requests.
    if !chain.rpc_url()?.is_local()
        && read
            .iter()
            .any(|contract| contract.deploy_block().unwrap_or(0) == 0)
    {
        bail!("name each contract's deploy_block: a non-local chain is not read from genesis");
    }
    let start_block = read
        .iter()
        .filter_map(|contract| contract.deploy_block())
        .min()
        .unwrap_or_default();
    let cipher = Cipher::from_file(config.key_file()).await?;
    let (operator, identity) = keys(config, &cipher).await?;
    Ok(Config {
        rpc_url: chain.rpc_url.clone(),
        rpc_auth: match &chain.rpc_auth {
            RpcAuth::None => None,
            RpcAuth::Basic { username, password } => Some(Authorization::basic(username, password)),
            RpcAuth::Bearer(token) => Some(Authorization::bearer(token)),
        },
        chain_id: chain.chain_id,
        interfold: contracts.interfold.address()?,
        registry: contracts.ciphernode_registry.address()?,
        bonding: contracts.bonding_registry.address()?,
        start_block,
        confirmations: chain.ingestion_confirmations()?,
        max_log_range: chain.rpc_log_range_blocks()?,
        poll_interval: chain.rpc_poll_interval()?,
        startup_timeout: Duration::from_secs(config.startup_timeout_secs()),
        availability,
        data_dir: crate::node_state::dir(config).path().to_path_buf(),
        fence,
        proving: proving(config),
        reserved_threads: config.multithread_reserve_threads(),
        network: network(config, identity),
        operator,
        cipher,
    })
}

/// How the node proves. A production build refuses, before this, a configuration that skips proofs.
fn proving(config: &NodeConfig) -> Proving {
    #[cfg(feature = "test-only-skip-proof-aggregation")]
    if config.skip_proof_aggregation() {
        return Proving::Placeholder;
    }
    Proving::Circuits(Prover {
        bb: BBPath::new(config.bb_binary(), config.using_custom_bb()),
        circuits: config.circuits_dir(),
        concurrent: config.multithread_concurrent_jobs().unwrap_or(2),
        bb_timeout: config.bb_timeout(),
    })
}

/// A bootstrap node's configuration: the network part of a node's.
pub async fn bootstrap(config: &NodeConfig) -> Result<Network> {
    let cipher = Cipher::from_file(config.key_file()).await?;
    let (_, identity) = keys(config, &cipher).await?;
    Ok(network(config, identity))
}

fn network(config: &NodeConfig, identity: [u8; 32]) -> Network {
    Network {
        // The network ID, not its name, keeps custom networks apart.
        id: config.network().id().to_string(),
        identity,
        listen: vec![format!("/ip4/0.0.0.0/udp/{}/quic-v1", config.quic_port())],
        peers: config.peers(),
    }
}

/// The operator key and the network key that `interfold wallet set` sealed in the node's store.
async fn keys(config: &NodeConfig, cipher: &Cipher) -> Result<(PrivateKeySigner, [u8; 32])> {
    let keys = keystore::read(&config.db_file(), cipher)?
        .context("no wallet is set: run `interfold wallet set` first")?;
    Ok((keys.operator, keys.network))
}
