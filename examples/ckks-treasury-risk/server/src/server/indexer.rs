// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! The chain indexer (CRISP `indexer.rs`): `E3Requested` → `CommitteePublished` (submissions
//! open, deadline hook) → `SubmissionPublished` (submission accepted by the seven-leg gate;
//! all three ciphertexts recovered from calldata; once EVERY registered DAO is in, evaluate
//! right away) → deadline: evaluate if ≥ MIN_DAOS submitted + publish →
//! `PlaintextOutputPublished` (decode the 64 coefficients; `risk = −opened[0]`).

use crate::config::CONFIG;
use crate::server::contract::{ciphertexts_from_calldata, SubmissionPublished, TreasuryProgram};
use crate::server::evaluate::evaluate_and_publish;
use crate::server::models::{IndexedSubmission, RoundResults, RoundStatus};
use crate::server::repo::{now_secs, TreasuryE3Repository};
use alloy::primitives::B256;
use alloy::sol_types::SolEvent;
use ckks_treasury_program::MIN_DAOS;
use e3_sdk::evm_helpers::contracts::ReadWrite;
use e3_sdk::evm_helpers::events::{CommitteePublished, E3Requested, PlaintextOutputPublished};
use e3_sdk::indexer::{DataStore, InterfoldIndexer, SharedStore};
use log::{error, info, warn};
use std::error::Error;

type Result<T> = std::result::Result<T, Box<dyn Error + Send + Sync>>;

/// Re-tries of the deadline hook, seconds after the input window closes.
const DEADLINE_RETRY_OFFSETS: [u64; 8] = [15, 30, 60, 90, 120, 180, 300, 600];

async fn register_e3_requested(
    indexer: InterfoldIndexer<impl DataStore, ReadWrite>,
) -> Result<InterfoldIndexer<impl DataStore, ReadWrite>> {
    indexer
        .add_event_handler(move |event: E3Requested, ctx| {
            let e3_id = event.e3Id.to_string();
            let store = ctx.store();
            async move {
                let repo = TreasuryE3Repository::new(store, &e3_id);
                match repo.try_get().await? {
                    Some(_) => info!("[e3_id={e3_id}] E3Requested indexed (round record present)"),
                    None => warn!("[e3_id={e3_id}] E3Requested for a round this server did not open — ignored"),
                }
                Ok(())
            }
        })
        .await;
    Ok(indexer)
}

async fn register_committee_published(
    indexer: InterfoldIndexer<impl DataStore, ReadWrite>,
) -> Result<InterfoldIndexer<impl DataStore, ReadWrite>> {
    indexer
        .add_event_handler(move |event: CommitteePublished, ctx| {
            let e3_id = event.e3Id.to_string();
            let store = ctx.store();
            async move {
                let mut repo = TreasuryE3Repository::new(store.clone(), &e3_id);
                let Some(round) = repo.try_get().await? else {
                    return Ok(());
                };
                info!(
                    "[e3_id={e3_id}] CommitteePublished: joint CKKS pk {} bytes — submissions open",
                    event.publicKey.len()
                );
                let requested_at = round
                    .stage_at
                    .iter()
                    .find(|(s, _)| s == "requested")
                    .map(|(_, t)| *t)
                    .unwrap_or(round.created_at);
                let now = now_secs();
                repo.record_timing("dkg_wall_secs", now.saturating_sub(requested_at))
                    .await?;
                repo.set_status(RoundStatus::Active).await?;

                let expiration = round.input_window[1];
                info!("[e3_id={e3_id}] evaluation hook at {expiration} (+retries)");
                for at in std::iter::once(expiration)
                    .chain(DEADLINE_RETRY_OFFSETS.iter().map(|o| expiration + o))
                {
                    let e3_id = e3_id.clone();
                    ctx.do_later(at, move |_, ctx| {
                        handle_deadline(e3_id.clone(), ctx.store())
                    });
                }
                Ok(())
            }
        })
        .await;
    Ok(indexer)
}

/// Input window closed: evaluate the round once (idempotent across the retry hooks) if at
/// least `MIN_DAOS` DAOs submitted.
async fn handle_deadline(e3_id: String, store: SharedStore<impl DataStore>) -> eyre::Result<()> {
    let mut repo = TreasuryE3Repository::new(store.clone(), &e3_id);
    let round = repo.get().await?;
    match round.status {
        RoundStatus::Active => {}
        RoundStatus::Evaluating => {
            if round.error.is_none() {
                return Ok(());
            }
        }
        _ => return Ok(()),
    }
    if round.submissions.len() < MIN_DAOS {
        warn!(
            "[e3_id={e3_id}] window closed with {} submission(s) (< {MIN_DAOS}) — not evaluating",
            round.submissions.len()
        );
        repo.set_error(format!(
            "round closed with {} submission(s); at least {MIN_DAOS} DAOs must submit",
            round.submissions.len()
        ))
        .await?;
        return Ok(());
    }
    repo.set_status(RoundStatus::Evaluating).await?;
    match evaluate_and_publish(store.clone(), &e3_id).await {
        Ok(()) => Ok(()),
        Err(e) => {
            error!("[e3_id={e3_id}] evaluation failed: {e:#}");
            repo.update(|r| {
                r.status = RoundStatus::Evaluating;
                r.error = Some(format!("{e:#}"));
            })
            .await?;
            Ok(())
        }
    }
}

/// `SubmissionPublished` carries no bytes — only the three keccaks — so this is a RAW log
/// handler: it keeps the transaction hash, fetches the calldata and recovers the ciphertexts.
async fn register_submission_published(
    indexer: InterfoldIndexer<impl DataStore, ReadWrite>,
    program_address: String,
) -> Result<InterfoldIndexer<impl DataStore, ReadWrite>> {
    let program_address = program_address.to_lowercase();
    indexer
        .add_raw_log_handler(move |log, ctx| {
            let store = ctx.store();
            let program_address = program_address.clone();
            async move {
                if log.address().to_string().to_lowercase() != program_address {
                    return Ok(());
                }
                if log.topics().first() != Some(&SubmissionPublished::SIGNATURE_HASH) {
                    return Ok(());
                }
                let decoded = log.log_decode::<SubmissionPublished>()?;
                let ev = decoded.inner.data;
                let e3_id = ev.e3Id.to_string();
                let mut repo = TreasuryE3Repository::new(store.clone(), &e3_id);
                if repo.try_get().await?.is_none() {
                    return Ok(());
                }
                let tx_hash: B256 = log.transaction_hash.ok_or_else(|| eyre::eyre!("log without transaction hash"))?;
                let block = log.block_number.unwrap_or_default();
                let program = TreasuryProgram::new(&CONFIG.http_rpc_url, &CONFIG.private_key, &CONFIG.e3_program_address).await?;
                let ciphertexts = match program.transaction_input(tx_hash).await {
                    Ok(input) => match ciphertexts_from_calldata(&input, ev.forwardCiphertextHash, ev.reversedCiphertextHash, ev.maskCiphertextHash) {
                        Ok(ct) => Some(ct),
                        Err(e) => {
                            error!("[e3_id={e3_id}] submission tx {tx_hash}: {e}");
                            None
                        }
                    },
                    Err(e) => {
                        error!("[e3_id={e3_id}] could not fetch submission tx {tx_hash}: {e}");
                        None
                    }
                };
                // The slot is assigned ON-CHAIN (position in the registered DAO list).
                let index: u64 = ev.index.to::<u64>();
                info!(
                    "[e3_id={e3_id}] SubmissionPublished slot {index}: DAO {} tx {tx_hash} cts {} + {} + {} bytes (7 Honk proofs verified on-chain)",
                    ev.dao,
                    ciphertexts.as_ref().map(|c| c.0.len()).unwrap_or(0),
                    ciphertexts.as_ref().map(|c| c.1.len()).unwrap_or(0),
                    ciphertexts.as_ref().map(|c| c.2.len()).unwrap_or(0)
                );
                repo.insert_submission(
                    IndexedSubmission {
                        index,
                        publisher: ev.dao.to_string(),
                        transaction_hash: tx_hash.to_string(),
                        block,
                        forward_ciphertext_hash: ev.forwardCiphertextHash.to_string(),
                        reversed_ciphertext_hash: ev.reversedCiphertextHash.to_string(),
                        mask_ciphertext_hash: ev.maskCiphertextHash.to_string(),
                        m_commitment_fwd: ev.mCommitmentFwd.to_string(),
                        m_commitment_rev: ev.mCommitmentRev.to_string(),
                        m_commitment_mask: ev.mCommitmentMask.to_string(),
                        ciphertext_available: ciphertexts.is_some(),
                    },
                    ciphertexts,
                )
                .await?;
                // Every registered DAO in: nothing else can arrive (one submission per registered
                // sender), so evaluate now instead of waiting for the window.
                let round = repo.get().await?;
                let all_in = round.submissions.len() == round.daos.len() && round.ciphertexts.len() == round.daos.len();
                if round.status == RoundStatus::Active && all_in && round.submissions.len() >= MIN_DAOS {
                    info!("[e3_id={e3_id}] all {} DAOs submitted — evaluating now", round.daos.len());
                    repo.set_status(RoundStatus::Evaluating).await?;
                    if let Err(e) = evaluate_and_publish(store, &e3_id).await {
                        error!("[e3_id={e3_id}] evaluation failed: {e:#}");
                        repo.update(|r| r.error = Some(format!("{e:#}"))).await?;
                    }
                }
                Ok(())
            }
        })
        .await;
    Ok(indexer)
}

async fn register_plaintext_output_published(
    indexer: InterfoldIndexer<impl DataStore, ReadWrite>,
) -> Result<InterfoldIndexer<impl DataStore, ReadWrite>> {
    indexer
        .add_event_handler(move |event: PlaintextOutputPublished, ctx| {
            let e3_id = event.e3Id.to_string();
            let store = ctx.store();
            async move {
                let mut repo = TreasuryE3Repository::new(store, &e3_id);
                let Some(round) = repo.try_get().await? else {
                    return Ok(());
                };
                let published_at = round.stage_at.iter().rev().find(|(s, _)| s == "published").map(|(_, t)| *t).unwrap_or(now_secs());
                repo.record_timing("threshold_decrypt_wall_secs", now_secs().saturating_sub(published_at)).await?;
                let opened = ckks_treasury_program::decode_opened(&event.plaintextOutput)
                    .map_err(|e| eyre::eyre!("{e:#}"))?;
                let risk = ckks_treasury_program::risk_from_opened(&opened)
                    .map_err(|e| eyre::eyre!("{e:#}"))?;
                info!(
                    "[e3_id={e3_id}] PlaintextOutputPublished: {} coefficients opened — risk = −c_0 = {risk:.4} (coefficients 1.. are mask-hidden cross terms)",
                    opened.len()
                );
                repo.set_results(RoundResults {
                    risk,
                    opened,
                    plaintext_hex: format!("0x{}", hex::encode(&event.plaintextOutput)),
                })
                .await?;
                Ok(())
            }
        })
        .await;
    Ok(indexer)
}

pub async fn start_indexer(
    ws_url: &str,
    interfold_address: &str,
    registry_address: &str,
    program_address: &str,
    store: SharedStore<impl DataStore>,
    private_key: &str,
) -> Result<()> {
    info!(
        "ckks-treasury: creating indexer (interfold {interfold_address}, program {program_address})"
    );
    let indexer = InterfoldIndexer::new_with_write_contract(
        ws_url,
        &[interfold_address, registry_address, program_address],
        store,
        private_key,
    )
    .await?;
    let indexer = register_e3_requested(indexer).await?;
    let indexer = register_committee_published(indexer).await?;
    let indexer = register_submission_published(indexer, program_address.to_string()).await?;
    let indexer = register_plaintext_output_published(indexer).await?;
    // Cursor tracking without history replay: the handlers are not pure (evaluation publishes).
    indexer.configure_backfill(None, None);
    info!("ckks-treasury: indexer listening");
    indexer.listen().await?;
    Ok(())
}
