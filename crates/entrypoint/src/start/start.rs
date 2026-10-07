// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use anyhow::{bail, Context, Result};
use e3_ciphernode_builder::{CiphernodeBuilder, CiphernodeHandle};
use e3_config::AppConfig;
use e3_crypto::Cipher;
use e3_zk_prover::ZkBackend;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use std::future::Future;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;
#[cfg(feature = "test-only-skip-proof-aggregation")]
use tracing::warn;
use tracing::{info, instrument};

async fn await_startup<F, T>(future: F, timeout: Duration) -> Result<T>
where
    F: Future<Output = Result<T>>,
{
    tokio::time::timeout(timeout, future)
        .await
        .with_context(|| format!("ciphernode startup did not complete within {timeout:?}"))?
}

fn validate_proof_aggregation_mode(skip_proof_aggregation: bool) -> Result<()> {
    if skip_proof_aggregation && !cfg!(feature = "test-only-skip-proof-aggregation") {
        bail!(
            "`skip_proof_aggregation` is test/CI-only and this binary was built without the \
             `test-only-skip-proof-aggregation` Cargo feature"
        );
    }
    Ok(())
}

/// Directory of the per-chain ingestion heartbeat files that `dappnode/healthcheck.sh` reads.
pub fn ingestion_heartbeat_dir(config: &AppConfig) -> PathBuf {
    config.node_data_dir().join("ingestion")
}

/// Record that this start runs one chain reader per enabled chain, from now. After a startup
/// grace, `dappnode/healthcheck.sh` requires a heartbeat from each, so a reader that never reaches
/// its first successful read fails the check instead of passing as a node that is still starting.
pub fn write_ingestion_expectation(config: &AppConfig) -> Result<()> {
    let enabled_chains = config
        .chains()
        .iter()
        .filter(|chain| chain.enabled.unwrap_or(true))
        .count();
    let dir = ingestion_heartbeat_dir(config);
    e3_evm::write_ingestion_expectation(&dir, enabled_chains).with_context(|| {
        format!(
            "failed to write the ingestion expectation for the health check in {}",
            dir.display()
        )
    })
}

/// Start the node. With `bootstrap`, the node only runs networking and chain reads, so peers can
/// use it to discover each other. It does not join committees, generate proofs, sign votes, or
/// send transactions, so it needs neither the prover's memory nor ETH. Its data directory is
/// stamped as a bootstrap node's, and a full node refuses to start on it (and the reverse).
#[instrument(name = "app", skip_all)]
pub async fn execute(config: &AppConfig, bootstrap: bool) -> Result<CiphernodeHandle> {
    validate_proof_aggregation_mode(config.skip_proof_aggregation())?;
    write_ingestion_expectation(config)?;

    let rng = Arc::new(Mutex::new(
        ChaCha20Rng::try_from_os_rng().context("failed to seed ChaCha20 RNG from OS")?,
    ));
    let cipher = Arc::new(Cipher::from_file(&config.key_file()).await?);

    let startup_timeout = Duration::from_secs(config.startup_timeout_secs());
    info!(
        startup_timeout_secs = startup_timeout.as_secs(),
        "Ciphernode startup deadline configured"
    );

    if bootstrap {
        info!(
            "Bootstrap mode: networking and chain reads only; no committee work, proofs, or \
             transactions"
        );
        let builder = CiphernodeBuilder::new(rng, cipher)
            .with_name(&config.name())
            .with_bootstrap_role()
            .with_logging()
            .with_persistence(&config.log_file(), &config.db_file())
            .with_chains(config.chains())
            .with_contract_interfold_reader()
            .with_max_buffered_evm_events(config.max_buffered_evm_events())
            .with_ingestion_heartbeat(ingestion_heartbeat_dir(config))
            .with_network_buffer_limits(
                config.max_buffered_net_events(),
                config.max_buffered_net_bytes(),
            )
            .with_network(config.network().clone(), config.peers(), config.quic_port())
            .with_shared_store()
            .with_shared_eventstore();
        return await_startup(builder.build(), startup_timeout).await;
    }

    let backend = ZkBackend::new(config.bb_binary(), config.circuits_dir(), config.work_dir())
        .with_bb_timeout(config.bb_timeout());

    let reserve = config.multithread_reserve_threads();
    let concurrent_jobs = config.multithread_concurrent_jobs();
    info!(
        "Ciphernode multithread: reserve_threads={reserve}, concurrent_jobs={}",
        concurrent_jobs
            .map(|n| n.to_string())
            .unwrap_or_else(|| "2 (default)".to_string())
    );

    let builder = CiphernodeBuilder::new(rng.clone(), cipher.clone())
        .with_name(&config.name())
        .with_logging()
        .with_persistence(&config.log_file(), &config.db_file())
        .with_sortition_score()
        .with_chains(config.chains())
        .with_contract_interfold_full()
        .with_contract_bonding_registry()
        .with_multithread_config(reserve, concurrent_jobs)
        .with_max_buffered_evm_events(config.max_buffered_evm_events())
        .with_network_buffer_limits(
            config.max_buffered_net_events(),
            config.max_buffered_net_bytes(),
        )
        .with_contract_ciphernode_registry()
        .with_contract_slashing_manager()
        .with_ingestion_heartbeat(ingestion_heartbeat_dir(config))
        .with_trbfv()
        .with_zkproof(backend)
        .with_pubkey_aggregation()
        .with_threshold_plaintext_aggregation()
        .with_network(config.network().clone(), config.peers(), config.quic_port())
        .with_shared_store()
        .with_shared_eventstore();

    #[cfg(feature = "test-only-skip-proof-aggregation")]
    let builder = if config.skip_proof_aggregation() {
        warn!(
            "Skipping recursive proof aggregation for this feature-gated test/CI node; \
             on-chain final proof verification remains mandatory"
        );
        builder.with_proof_aggregation_disabled_for_testing()
    } else {
        builder
    };

    let build = builder.build();
    let node = await_startup(build, startup_timeout).await?;

    Ok(node)
}

#[cfg(test)]
mod tests {
    use super::{await_startup, validate_proof_aggregation_mode};
    use anyhow::{bail, Result};
    use std::time::Duration;

    #[tokio::test]
    async fn startup_deadline_returns_completed_result() -> Result<()> {
        let value =
            await_startup(async { Ok::<_, anyhow::Error>(7) }, Duration::from_secs(1)).await?;
        assert_eq!(value, 7);
        Ok(())
    }

    #[tokio::test]
    async fn startup_deadline_fails_instead_of_waiting_forever() -> Result<()> {
        let error = await_startup(
            std::future::pending::<Result<()>>(),
            Duration::from_millis(5),
        )
        .await
        .expect_err("pending startup must hit its deadline");
        if !error
            .to_string()
            .contains("startup did not complete within 5ms")
        {
            bail!("unexpected timeout error: {error:#}");
        }
        Ok(())
    }

    #[cfg(not(feature = "test-only-skip-proof-aggregation"))]
    #[test]
    fn production_build_rejects_proof_aggregation_skip() {
        let error = validate_proof_aggregation_mode(true)
            .expect_err("production build must reject proof aggregation skipping");
        assert!(error
            .to_string()
            .contains("test-only-skip-proof-aggregation"));
        assert!(validate_proof_aggregation_mode(false).is_ok());
    }

    #[cfg(feature = "test-only-skip-proof-aggregation")]
    #[test]
    fn test_feature_allows_proof_aggregation_skip() {
        assert!(validate_proof_aggregation_mode(true).is_ok());
        assert!(validate_proof_aggregation_mode(false).is_ok());
    }
}

#[cfg(test)]
mod ingestion_expectation_tests {
    use super::*;

    fn chain(name: &str, enabled: bool) -> String {
        format!(
            "  - name: \"{name}\"\n    enabled: {enabled}\n    rpc_url: \"ws://localhost:8545\"\n    \
             contracts:\n      interfold: \"0x9fE46736679d2D9a65F0992F2272dE9f3c7fa6e0\"\n      \
             ciphernode_registry:\n        address: \"0xCf7Ed3AccA5a467e9e704C703E8D87F634fB0Fc9\"\n        \
             deploy_block: 1\n      bonding_registry: \"0xDc64a140Aa3E981100a9becA4E685f962f0cF6C9\"\n"
        )
    }

    fn scoped_config(dir: &std::path::Path, chains: &[String]) -> Result<AppConfig> {
        let yaml = format!(
            "chains:\n{}nodes:\n  cn1:\n    network: local\n",
            chains.concat()
        );
        let config: e3_config::UnscopedAppConfig = serde_yaml::from_str(&yaml)?;
        config.into_scoped_with_defaults(
            "cn1",
            &dir.join("data"),
            &dir.join("config"),
            &dir.to_path_buf(),
        )
    }

    fn expectation(config: &AppConfig) -> Result<String> {
        Ok(std::fs::read_to_string(
            ingestion_heartbeat_dir(config).join(e3_evm::INGESTION_EXPECTATION_FILE),
        )?)
    }

    /// `start` records one chain reader for each enabled chain, before it builds anything.
    #[test]
    fn the_expectation_counts_the_enabled_chains() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let config = scoped_config(
            dir.path(),
            &[chain("hardhat", true), chain("devnet", false)],
        )?;

        write_ingestion_expectation(&config)?;

        let written = expectation(&config)?;
        assert!(written.starts_with("chains=1\nstarted_at="), "{written}");
        Ok(())
    }

    /// A start records the expectation before anything that can wait on a chain: a start that
    /// stops at its key file has written it, and a start that cannot write it fails.
    #[actix::test]
    async fn a_start_records_the_expectation_before_it_reads_a_chain() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let config = scoped_config(dir.path(), &[chain("hardhat", true), chain("devnet", true)])?;
        // There is no key file, so the start stops before it builds a provider.
        let Err(error) = execute(&config, false).await else {
            panic!("a start without a key file must fail");
        };
        assert!(
            !format!("{error:#}").contains("ingestion expectation"),
            "{error:#}"
        );
        let written = expectation(&config)?;
        assert!(written.starts_with("chains=2\nstarted_at="), "{written}");

        // A file where the heartbeat directory belongs: the expectation cannot be written.
        let blocked = tempfile::tempdir()?;
        let config = scoped_config(blocked.path(), &[chain("hardhat", true)])?;
        let heartbeats = ingestion_heartbeat_dir(&config);
        std::fs::create_dir_all(heartbeats.parent().expect("the directory has a parent"))?;
        std::fs::write(&heartbeats, b"not a directory")?;
        let Err(error) = execute(&config, false).await else {
            panic!("a start that cannot write its expectation must fail");
        };
        assert!(
            format!("{error:#}").contains("failed to write the ingestion expectation"),
            "{error:#}"
        );
        Ok(())
    }
}
