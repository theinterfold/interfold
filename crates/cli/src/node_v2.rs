// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! The v2 node's configuration from the CLI's: one chain with its contracts and availability
//! service, the operator key that `interfold wallet set` stored, and the node's port and peers.

use alloy::{signers::local::PrivateKeySigner, transports::Authorization};
use anyhow::{bail, Context, Result};
use e3_ciphernode_config::NodeConfig;
use e3_crypto::Cipher;
use e3_entrypoint::helpers::datastore::get_repositories;
use e3_evm::EthPrivateKeyRepositoryFactory;
use e3_evm_config::{DataAvailabilityMode, RpcAuth};
use e3_net::NetRepositoryFactory;
use e3_node::launch::{Availability, Config, Network, Prover};
use zeroize::Zeroizing;

pub async fn config(config: &NodeConfig) -> Result<Config> {
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
    let start_block = read
        .iter()
        .filter_map(|contract| contract.deploy_block())
        .min()
        .unwrap_or_default();
    let cipher = Cipher::from_file(config.key_file()).await?;
    let (operator, identity) = keys(config, &cipher).await?;
    // Test deployments with mock verifiers take placeholder proofs, and so do test binaries told
    // to skip proof aggregation.
    let prover = (!config.skip_proof_aggregation()).then(|| Prover {
        bb: config.bb_binary(),
        circuits: config.circuits_dir(),
        concurrent: config.multithread_concurrent_jobs().unwrap_or(2),
    });
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
        poll_interval: chain.rpc_poll_interval()?,
        availability,
        data_dir: config.node_data_dir().join("v2"),
        prover,
        network: network(config, identity),
        operator,
        cipher,
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
/// The network key keeps the node's peer ID; its first 32 bytes are its ed25519 secret.
async fn keys(config: &NodeConfig, cipher: &Cipher) -> Result<(PrivateKeySigner, [u8; 32])> {
    let repositories = get_repositories(config)?;
    let unset = "no wallet is set: run `interfold wallet set` first";
    let sealed = repositories
        .eth_private_key()
        .read()
        .await?
        .context(unset)?;
    let operator = PrivateKeySigner::from_slice(&Zeroizing::new(cipher.decrypt_data(&sealed)?))?;
    let sealed = repositories.libp2p_keypair().read().await?.context(unset)?;
    let keypair = Zeroizing::new(cipher.decrypt_data(&sealed)?);
    let secret = keypair
        .get(..32)
        .context("the stored network key is not an ed25519 keypair")?;
    Ok((operator, secret.try_into()?))
}
