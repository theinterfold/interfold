// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! What a node shows before anything starts. A configuration becomes [`Verified`] only here, and a
//! node is built only from a `Verified` one. A chain node that does not answer yet is waited for
//! until the startup deadline; a chain that says the configuration is wrong ends the start at once.

use crate::{
    dir::{Identity, NodeDir},
    effects::Backoff,
    launch::{Config, Proving},
    memory,
};
use alloy::providers::{Provider, RootProvider};
use alloy_primitives::Address;
use e3_chain::{standing, Contracts, Release, Standing};
use e3_evm_contracts::{ICiphernodeRegistry, IInterfold};
use e3_jobs::{Circuits, Proofs};
use e3_zk_prover::{ZkBackend, ZkProver};
use std::{collections::BTreeSet, fmt::Display, future::Future, time::Duration};
use tokio::time::Instant;
use tracing::{info, warn};

/// The chains the release's randomness exists on: Ethereum mainnet and Sepolia have the VRF, and
/// local development chains take a mock.
const SUPPORTED_CHAINS: [u64; 4] = [1, 1_337, 31_337, 11_155_111];

/// The longest one attempt to read from the chain node may take.
const READ_LIMIT: Duration = Duration::from_secs(60);

/// A configuration the chain, the prover and this host have backed up.
pub struct Verified {
    pub(crate) config: Config,
    pub(crate) rpc: RootProvider,
    pub(crate) contracts: Contracts,
    pub(crate) release: Release,
    pub(crate) standing: Standing,
    pub(crate) proofs: Proofs,
    /// Threads the node's jobs may use.
    pub(crate) threads: usize,
}

#[derive(Debug, thiserror::Error)]
pub enum Refused {
    #[error("{0} must be greater than zero")]
    NotPositive(&'static str),
    #[error("the RPC node serves chain {actual}, and this node is set up for chain {configured}")]
    WrongChain { configured: u64, actual: u64 },
    #[error("this release does not run on chain {0}")]
    UnsupportedChain(u64),
    #[error("the {name} is set to {configured}, and Interfold uses {actual}")]
    Miswired {
        name: &'static str,
        configured: Address,
        actual: Address,
    },
    #[error("the ciphernode registry has no randomness provider")]
    NoRandomness,
    #[error("{what} did not succeed in {after:?}; the last failure was: {last}")]
    TimedOut {
        what: &'static str,
        after: Duration,
        last: String,
    },
}

/// Checks `config` against the chain, the prover and this host, or says why the node cannot start.
pub async fn verify(config: Config) -> anyhow::Result<Verified> {
    positive(&config)?;
    let deadline = Instant::now() + config.startup_timeout;
    let endpoint = config.endpoint();
    let connect = || endpoint.connect();
    let client = retry_until(deadline, READ_LIMIT, "connecting to the RPC node", connect).await?;
    let rpc = RootProvider::new(client);
    let chain = retry_until(deadline, READ_LIMIT, "reading the contracts", || {
        read_chain(&rpc, &config)
    })
    .await?;
    chain.check(&config)?;
    let contracts = Contracts {
        chain_id: chain.id,
        interfold: config.interfold,
        registry: config.registry,
        bonding: config.bonding,
        slashing: BTreeSet::from([chain.slashing]),
        randomness: BTreeSet::from([chain.randomness]),
        crypto_configs: e3_jobs::crypto_configs(),
    };
    let built = e3_ciphernode_config::current_node_release();
    let release = Release {
        id: built.release_id(),
        protocol_version: built.protocol_version,
        node_generation: built.node_generation,
    };
    let operator = config.operator.address();
    let standing = retry_until(
        deadline,
        READ_LIMIT,
        "reading the release requirement",
        || standing(&rpc, &contracts, release, operator),
    )
    .await?;
    if let Standing::Unsupported(refusal) = standing {
        return Err(refusal.into());
    }
    NodeDir::new(&config.data_dir).open(&Identity {
        chain_id: chain.id,
        interfold: config.interfold,
        operator,
    })?;
    let (proofs, threads) = proofs(&config, deadline).await?;
    info!(
        chain = chain.id,
        "the chain and this host fit the configuration"
    );
    Ok(Verified {
        config,
        rpc,
        contracts,
        release,
        standing,
        proofs,
        threads,
    })
}

fn positive(config: &Config) -> Result<(), Refused> {
    let durations = [
        ("the poll interval", config.poll_interval),
        ("the startup timeout", config.startup_timeout),
    ];
    if let Some((name, _)) = durations.iter().find(|(_, value)| value.is_zero()) {
        return Err(Refused::NotPositive(name));
    }
    if config.max_log_range == 0 {
        return Err(Refused::NotPositive("the log range"));
    }
    let prover = match &config.proving {
        Proving::Circuits(prover) => prover,
        #[cfg(any(test, feature = "testing"))]
        Proving::AsInstalled(prover) => prover,
        #[cfg(any(test, feature = "testing"))]
        Proving::Placeholder => return Ok(()),
    };
    if prover.bb_timeout.is_zero() {
        return Err(Refused::NotPositive("the bb timeout"));
    }
    if prover.concurrent == 0 {
        return Err(Refused::NotPositive("the number of concurrent proofs"));
    }
    Ok(())
}

/// What the chain says about the contracts the node is set up for.
struct ChainFacts {
    id: u64,
    bonding: Address,
    registry: Address,
    randomness: Address,
    slashing: Address,
}

async fn read_chain(rpc: &RootProvider, config: &Config) -> anyhow::Result<ChainFacts> {
    let interfold = IInterfold::new(config.interfold, rpc);
    Ok(ChainFacts {
        id: rpc.get_chain_id().await?,
        bonding: interfold.bondingRegistry().call().await?,
        registry: interfold.ciphernodeRegistry().call().await?,
        slashing: interfold.slashingManager().call().await?,
        randomness: ICiphernodeRegistry::new(config.registry, rpc)
            .randomnessProvider()
            .call()
            .await?,
    })
}

impl ChainFacts {
    fn check(&self, config: &Config) -> Result<(), Refused> {
        if let Some(configured) = config.chain_id.filter(|configured| *configured != self.id) {
            return Err(Refused::WrongChain {
                configured,
                actual: self.id,
            });
        }
        if !SUPPORTED_CHAINS.contains(&self.id) {
            return Err(Refused::UnsupportedChain(self.id));
        }
        let wiring = [
            ("bonding registry", config.bonding, self.bonding),
            ("ciphernode registry", config.registry, self.registry),
        ];
        for (name, configured, actual) in wiring {
            if configured != actual {
                return Err(Refused::Miswired {
                    name,
                    configured,
                    actual,
                });
            }
        }
        if self.randomness == Address::ZERO {
            return Err(Refused::NoRandomness);
        }
        Ok(())
    }
}

/// The node's proofs and the threads its jobs may use. The host must fit a prover before anything
/// is installed for it.
async fn proofs(config: &Config, deadline: Instant) -> anyhow::Result<(Proofs, usize)> {
    let (prover, install) = match &config.proving {
        Proving::Circuits(prover) => (prover, true),
        #[cfg(any(test, feature = "testing"))]
        Proving::AsInstalled(prover) => (prover, false),
        #[cfg(any(test, feature = "testing"))]
        Proving::Placeholder => {
            let threads = memory::threads_for_placeholders(config.reserved_threads);
            return Ok((Proofs::Placeholder, threads));
        }
    };
    let capacity = memory::capacity(prover.concurrent, config.reserved_threads)?;
    // Proofs that a stop cut short run again from the start, so their files go.
    let proving = config.data_dir.join("proving");
    if let Err(error) = std::fs::remove_dir_all(&proving) {
        if error.kind() != std::io::ErrorKind::NotFound {
            return Err(error.into());
        }
    }
    let backend = ZkBackend::new(prover.bb.clone(), prover.circuits.clone(), proving)
        .with_bb_timeout(prover.bb_timeout);
    if install {
        retry_until(
            deadline,
            config.startup_timeout,
            "installing the prover",
            || backend.ensure_installed(),
        )
        .await?;
    }
    let circuits = Circuits::new(
        ZkProver::new(&backend),
        capacity.proofs,
        capacity.bb_threads,
    )?;
    Ok((Proofs::Circuits(Box::new(circuits)), capacity.threads))
}

/// Repeats `attempt`, each try limited to `limit`, until it succeeds or `deadline` passes.
pub(crate) async fn retry_until<T, E: Display, F: Future<Output = Result<T, E>>>(
    deadline: Instant,
    limit: Duration,
    what: &'static str,
    mut attempt: impl FnMut() -> F,
) -> Result<T, Refused> {
    let (started, mut backoff) = (Instant::now(), Backoff::STARTUP);
    loop {
        let cutoff = (Instant::now() + limit).min(deadline);
        let last = match tokio::time::timeout_at(cutoff, attempt()).await {
            Ok(Ok(value)) => return Ok(value),
            Ok(Err(failure)) => failure.to_string(),
            Err(_) => "no answer in time".to_string(),
        };
        let wait = backoff.next();
        if Instant::now() + wait >= deadline {
            return Err(Refused::TimedOut {
                what,
                after: started.elapsed(),
                last,
            });
        }
        warn!(failure = %last, "{what}: trying again");
        tokio::time::sleep(wait).await;
    }
}

#[cfg(test)]
mod tests;
