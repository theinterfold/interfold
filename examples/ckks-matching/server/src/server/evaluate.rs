// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Evaluate-and-publish job (CRISP's `program_server_request::run_compute`): once the input
//! window closes (or both parties submitted), run the matching policy over the two indexed
//! ciphertext pairs (read back from calldata) under the committee's level-0 relin key and
//! publish the evaluated ciphertext on-chain, which triggers the threshold decryption.
//! Refuses to evaluate unless BOTH slots (A = 0, B = 1) have submitted.

use crate::config::CONFIG;
use crate::server::contract::ciphertext_commitment;
use crate::server::models::RoundStatus;
use crate::server::repo::MatchingE3Repository;
use alloy::primitives::{Bytes, U256};
use ckks_matching_program::RoundInputs;
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
    let mut repo = MatchingE3Repository::new(store, e3_id);
    let round = repo.get().await?;

    if round.ciphertexts.len() != round.submissions.len() {
        return Err(eyre!(
            "{} submission(s) indexed but only {} ciphertext pair(s) recovered from calldata",
            round.submissions.len(),
            round.ciphertexts.len()
        ));
    }
    let inputs = RoundInputs::from_submissions(&round.ciphertexts).map_err(|e| eyre!("{e:#}"))?;
    let rlk_dir = relin_key_dir(&CONFIG.relin_key_dir, CONFIG.chain_id, e3_id);
    for f in ckks_matching_program::ceremony_key_files() {
        if !rlk_dir.join(&f).exists() {
            return Err(eyre!(
                "ceremony key {} missing — is the level-0 relin ceremony complete and CKKS_RELIN_KEY_DIR shared with the nodes?",
                rlk_dir.join(&f).display()
            ));
        }
    }

    info!(
        "[e3_id={e3_id}] evaluating: forward(a) · reversed(b) — ONE ct×ct under rlk_level_0, one rescale, + mask(m_a) + mask(m_b), opens at level {}",
        ckks_matching_program::opening_level()
    );
    let t0 = Instant::now();
    let output =
        tokio::task::spawn_blocking(move || ckks_matching_program::evaluate(&inputs, &rlk_dir))
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
