// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Evaluate-and-publish job (CRISP's `program_server_request::run_compute`): once the input
//! window closes, run the credit-scoring v2 SIGMOID policy over the indexed application
//! ciphertext pairs (read back from calldata, placed at their on-chain slots) under the
//! committee's two per-level relin keys and publish the evaluated ciphertext on-chain, which
//! triggers the threshold decryption.

use crate::config::CONFIG;
use crate::server::contract::ciphertext_commitment;
use crate::server::models::RoundStatus;
use crate::server::repo::CreditE3Repository;
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
    let mut repo = CreditE3Repository::new(store, e3_id);
    let round = repo.get().await?;

    if round.ciphertexts.len() != round.applications.len() {
        return Err(eyre!(
            "{} application(s) indexed but only {} ciphertext pair(s) recovered from calldata",
            round.applications.len(),
            round.ciphertexts.len()
        ));
    }
    if round.ciphertexts.is_empty() {
        return Err(eyre!("no applications to score"));
    }
    // Slot layout: registered applicant `i` holds slot `i`; a registered applicant that never
    // applied leaves an empty slot (the policy opens it as 0.5).
    let slots = round.snapshot.len();
    let mut inputs: Vec<Option<(Vec<u8>, Vec<u8>)>> = vec![None; slots];
    for (index, z, m) in &round.ciphertexts {
        let i = *index as usize;
        if i >= slots {
            return Err(eyre!("application slot {i} outside the {slots} registered slots"));
        }
        inputs[i] = Some((z.clone(), m.clone()));
    }
    let rlk_dir = relin_key_dir(&CONFIG.relin_key_dir, CONFIG.chain_id, e3_id);
    for f in ckks_credit_program::ceremony_key_files() {
        if !rlk_dir.join(&f).exists() {
            return Err(eyre!(
                "ceremony key {} missing — is the two-level relin ceremony complete and CKKS_RELIN_KEY_DIR shared with the nodes?",
                rlk_dir.join(&f).display()
            ));
        }
    }

    info!(
        "[e3_id={e3_id}] evaluating: {} applications in {slots} slots, model {:?} + {} (σ_cubic on the encrypted logit: two ct×ct under rlk_level_1/2, three rescales, opens at level {})",
        round.ciphertexts.len(),
        round.model.weights,
        round.model.bias,
        ckks_credit_program::opening_level()
    );
    let t0 = Instant::now();
    let output = tokio::task::spawn_blocking(move || {
        ckks_credit_program::evaluate(&inputs, &rlk_dir)
    })
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
