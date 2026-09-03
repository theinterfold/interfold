// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Evaluation job: once a round's input window closed (or an admin asks),
//! load the committee's joint level-0 relin key, run the packed
//! statistics policy over the stored VERIFIED ciphertexts, and publish the
//! output ciphertext on-chain. The plaintext arrives later through the
//! indexer (`PlaintextOutputPublished`), which decodes the statistics.

use std::path::PathBuf;
use std::time::{Duration, Instant};

use alloy::primitives::U256;
use e3_sdk::indexer::SharedStore;
use eyre::{eyre, Result};
use log::{error, info, warn};

use super::chain::Chain;
use super::database::SledDB;
use super::models::{now_secs, EvaluationRecord, RoundStatus};
use super::repo::{list_round_ids, RoundRepository};

/// Where the joint key for `e3_id` lives: `<relin_key_dir>/<chain_id>:<e3_id>`.
pub fn relin_key_dir(base: &str, chain_id: u64, e3_id: &str) -> PathBuf {
    PathBuf::from(base).join(format!("{chain_id}:{e3_id}"))
}

/// Evaluate + publish one round. Errors are returned to the caller (admin
/// route) and logged by the periodic job.
pub async fn evaluate_and_publish(
    store: SharedStore<SledDB>,
    chain: &Chain,
    relin_key_base: &str,
    e3_id: &str,
) -> Result<EvaluationRecord> {
    let mut repo = RoundRepository::new(store, e3_id);
    let round = repo.require().await?;
    if round.evaluation.is_some() {
        return Err(eyre!("round {e3_id} already evaluated"));
    }
    if !matches!(round.status, RoundStatus::Open | RoundStatus::Closed) {
        return Err(eyre!(
            "round {e3_id} is {:?}, not open/closed",
            round.status
        ));
    }
    let now = chain.block_timestamp().await?;
    if now < round.input_window[1] {
        return Err(eyre!(
            "input window of round {e3_id} closes at {} (chain time {now})",
            round.input_window[1]
        ));
    }
    let cts = repo.ciphertexts().await?;
    let verified: Vec<Vec<u8>> = round
        .submissions
        .iter()
        .filter(|s| s.verified)
        .filter_map(|s| {
            cts.iter()
                .find(|(i, _)| *i == s.index)
                .map(|(_, b)| b.clone())
        })
        .collect();
    if verified.is_empty() {
        return Err(eyre!(
            "round {e3_id} has no verified ciphertexts to evaluate"
        ));
    }
    let rlk_dir = relin_key_dir(relin_key_base, round.chain_id, e3_id);
    let rlk = ckks_salary_program::load_relin_key(&rlk_dir).map_err(|e| {
        eyre!("{e} — is the relin ceremony complete and CKKS_RELIN_KEY_DIR shared with the nodes?")
    })?;
    info!(
        "[e3_id={e3_id}] evaluating packed statistics over {} verified ciphertexts (rlk {})",
        verified.len(),
        rlk_dir.display()
    );
    let t = Instant::now();
    let eval = tokio::task::spawn_blocking(move || ckks_salary_program::evaluate(&verified, &rlk))
        .await
        .map_err(|e| eyre!("evaluation task panicked: {e}"))?
        .map_err(|e| eyre!("{e}"))?;
    let eval_millis = t.elapsed().as_millis() as u64;
    info!(
        "[e3_id={e3_id}] evaluated in {eval_millis} ms: {} bytes, commitment 0x{}",
        eval.ciphertext.len(),
        hex::encode(eval.commitment)
    );
    let receipt = chain
        .publish_ciphertext_output(
            U256::from_str_radix(e3_id, 10)?,
            eval.ciphertext.clone(),
            eval.commitment,
        )
        .await?;
    let record = EvaluationRecord {
        input_count: round.submissions.iter().filter(|s| s.verified).count() as u64,
        ciphertext_bytes: eval.ciphertext.len(),
        commitment: format!("0x{}", hex::encode(eval.commitment)),
        publish_tx_hash: Some(format!("{:#x}", receipt.transaction_hash)),
        evaluated_at: now_secs(),
        eval_millis,
    };
    info!(
        "[e3_id={e3_id}] ciphertext output published tx={} — committee threshold-decrypting",
        receipt.transaction_hash
    );
    let rec = record.clone();
    repo.update(|r| {
        r.evaluation = Some(rec.clone());
        r.status = RoundStatus::Evaluating;
    })
    .await?;
    Ok(record)
}

/// Periodic sweep (CRISP's cron equivalent, in-process): every closed
/// round with verified submissions and no evaluation gets evaluated.
pub async fn run_auto_evaluator(
    store: SharedStore<SledDB>,
    db: SledDB,
    chain: Chain,
    relin_key_base: String,
    interval: Duration,
) {
    loop {
        tokio::time::sleep(interval).await;
        let chain_now = match chain.block_timestamp().await {
            Ok(t) => t,
            Err(e) => {
                warn!("auto-evaluator: chain time unavailable: {e}");
                continue;
            }
        };
        for e3_id in list_round_ids(&db) {
            let mut repo = RoundRepository::new(store.clone(), &e3_id);
            let Ok(Some(mut round)) = repo.get().await else {
                continue;
            };
            // Restart-safe window close: the indexer's `do_later` hooks
            // live in memory, so a round whose window elapsed while the
            // server was down is closed here from chain time.
            if round.status == RoundStatus::Open && chain_now > round.input_window[1] {
                info!(
                    "[e3_id={e3_id}] input window closed at {} ({} submissions)",
                    round.input_window[1],
                    round.submission_count()
                );
                match repo.set_status(RoundStatus::Closed).await {
                    Ok(r) => round = r,
                    Err(e) => {
                        error!("[e3_id={e3_id}] closing round failed: {e}");
                        continue;
                    }
                }
            }
            if round.status != RoundStatus::Closed || round.evaluation.is_some() {
                continue;
            }
            if !round.submissions.iter().any(|s| s.verified) {
                warn!("[e3_id={e3_id}] closed with no verified submissions; skipping evaluation");
                continue;
            }
            match evaluate_and_publish(store.clone(), &chain, &relin_key_base, &e3_id).await {
                Ok(rec) => info!("[e3_id={e3_id}] auto-evaluated: {}", rec.commitment),
                Err(e) => error!("[e3_id={e3_id}] auto-evaluation failed: {e}"),
            }
        }
    }
}
