// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use anyhow::{Context, Result};
use e3_ciphernode_builder::{CiphernodeBuilder, CiphernodeHandle};
use e3_config::AppConfig;
use e3_crypto::Cipher;
use e3_zk_prover::ZkBackend;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use std::sync::{Arc, Mutex};
use tracing::{info, instrument};

#[instrument(name = "app", skip_all)]
pub async fn execute(config: &AppConfig) -> Result<CiphernodeHandle> {
    let rng = Arc::new(Mutex::new(
        ChaCha20Rng::try_from_os_rng().context("failed to seed ChaCha20 RNG from OS")?,
    ));
    let cipher = Arc::new(Cipher::from_file(&config.key_file()).await?);
    let backend = ZkBackend::new(config.bb_binary(), config.circuits_dir(), config.work_dir());

    let reserve = config.multithread_reserve_threads();
    let concurrent_jobs = config.multithread_concurrent_jobs();
    info!(
        "Ciphernode multithread: reserve_threads={reserve}, concurrent_jobs={}",
        concurrent_jobs
            .map(|n| n.to_string())
            .unwrap_or_else(|| "auto (CPUs - reserve)".to_string())
    );

    let node = CiphernodeBuilder::new(rng.clone(), cipher.clone())
        .with_persistence(&config.log_file(), &config.db_file())
        .with_sortition_score()
        .with_chains(config.chains())
        .with_contract_interfold_full()
        .with_contract_bonding_registry()
        .with_multithread_config(reserve, concurrent_jobs)
        .with_contract_ciphernode_registry()
        .with_contract_slashing_manager()
        .with_trbfv()
        .with_zkproof(backend)
        .with_pubkey_aggregation()
        .with_threshold_plaintext_aggregation()
        .with_net(config.peers(), config.quic_port())
        .with_shared_store()
        .with_shared_eventstore()
        .build()
        .await?;

    Ok(node)
}
