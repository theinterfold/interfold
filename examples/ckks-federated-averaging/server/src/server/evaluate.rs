// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Evaluate-and-publish job (CRISP's `program_server_request::run_compute`): once the input
//! window closes AND at least `min_clients` updates were accepted, run the federated-averaging
//! policy over the indexed `(gradient, count)` ciphertext pairs (read back from calldata)
//! under the committee's level-0 relin key and publish the evaluated ciphertext on-chain,
//! which triggers the threshold decryption. The server never sees an update or a count: it
//! only ever handles ciphertexts.

use crate::config::CONFIG;
use crate::server::contract::ciphertext_commitment;
use crate::server::models::RoundStatus;
use crate::server::repo::FedAvgE3Repository;
use alloy::primitives::{Bytes, U256};
use e3_sdk::evm_helpers::contracts::{InterfoldContract, InterfoldWrite};
use e3_sdk::indexer::{DataStore, SharedStore};
use eyre::{eyre, Result};
use log::info;
use std::path::PathBuf;
use std::time::Instant;

/// Where the joint keys for `e3_id` live: `<relin_key_dir>/<chain_id>:<e3_id>`.
pub fn relin_key_dir(base: &str, chain_id: u64, e3_id: &str) -> PathBuf {
    PathBuf::from(base).join(format!("{chain_id}:{e3_id}"))
}

pub async fn evaluate_and_publish(store: SharedStore<impl DataStore>, e3_id: &str) -> Result<()> {
    let mut repo = FedAvgE3Repository::new(store, e3_id);
    let round = repo.get().await?;

    if round.ciphertexts.len() != round.updates.len() {
        return Err(eyre!(
            "{} update(s) indexed but only {} ciphertext pair(s) recovered from calldata",
            round.updates.len(),
            round.ciphertexts.len()
        ));
    }
    // The public minimum client count: with fewer clients the public aggregate leaks too
    // much about each contribution (the usual FedAvg leakage) — refuse to evaluate.
    if round.ciphertexts.len() < round.params.min_clients {
        return Err(eyre!(
            "only {} update(s) accepted; the round requires at least {} clients before evaluating",
            round.ciphertexts.len(),
            round.params.min_clients
        ));
    }
    let inputs: Vec<(Vec<u8>, Vec<u8>)> = round
        .ciphertexts
        .iter()
        .map(|(_, g, c)| (g.clone(), c.clone()))
        .collect();
    let rlk_dir = relin_key_dir(&CONFIG.relin_key_dir, CONFIG.chain_id, e3_id);
    for f in ckks_fedavg_program::ceremony_key_files() {
        if !rlk_dir.join(&f).exists() {
            return Err(eyre!(
                "ceremony key {} missing — is the level-0 relin ceremony complete and CKKS_RELIN_KEY_DIR shared with the nodes?",
                rlk_dir.join(&f).display()
            ));
        }
    }

    info!(
        "[e3_id={e3_id}] evaluating: {} updates (d {}, min clients {}): one ct×ct per client under rlk_level_0, one rescale, opens at level {}",
        inputs.len(),
        round.params.d,
        round.params.min_clients,
        ckks_fedavg_program::opening_level()
    );
    let t0 = Instant::now();
    let output =
        tokio::task::spawn_blocking(move || ckks_fedavg_program::evaluate(&inputs, &rlk_dir))
            .await
            .map_err(|e| eyre!("evaluation task panicked: {e}"))?
            .map_err(|e| eyre!("{e:#}"))?;
    let eval_ms = t0.elapsed().as_millis() as u64;
    repo.record_timing("evaluate_ms", eval_ms).await?;
    info!(
        "[e3_id={e3_id}] evaluated in {eval_ms} ms → {} byte ciphertext output",
        output.len()
    );

    let commitment = ciphertext_commitment(&output);
    let contract = InterfoldContract::new(
        &CONFIG.http_rpc_url,
        &CONFIG.private_key,
        &CONFIG.interfold_address,
    )
    .await?;
    let id = U256::from_str_radix(e3_id, 10)?;
    let t1 = Instant::now();
    // Dev stack: the CKKS ciphertext verifier is the mock (keccak commitment); the proof is opaque.
    let receipt = contract
        .publish_ciphertext_output(
            id,
            Bytes::from(output),
            commitment,
            Bytes::from(vec![0x12, 0x34, 0x56, 0x78]),
        )
        .await?;
    repo.record_timing("publish_ciphertext_ms", t1.elapsed().as_millis() as u64)
        .await?;
    info!(
        "[e3_id={e3_id}] ciphertext output published: tx {} — committee threshold-decrypting",
        receipt.transaction_hash
    );
    repo.update(|r| r.error = None).await?;
    repo.set_status(RoundStatus::Published).await?;
    Ok(())
}
