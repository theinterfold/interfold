// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! The chain indexer (CRISP `indexer.rs`): `E3Requested` → `CommitteePublished` (applications
//! open, deadline hook) → `ApplicationPublished` (application accepted by the five-leg gate;
//! both ciphertexts recovered from calldata) → deadline: evaluate + publish →
//! `PlaintextOutputPublished` (decode the masked probability slots; the applicant unmasks in
//! the browser).

use crate::config::CONFIG;
use crate::server::contract::{ciphertexts_from_calldata, ApplicationPublished, CreditProgram};
use crate::server::evaluate::evaluate_and_publish;
use crate::server::models::{IndexedApplication, RoundResults, RoundStatus};
use crate::server::repo::{now_secs, CreditE3Repository};
use alloy::primitives::B256;
use alloy::sol_types::SolEvent;
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
                let repo = CreditE3Repository::new(store, &e3_id);
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
                let mut repo = CreditE3Repository::new(store.clone(), &e3_id);
                let Some(round) = repo.try_get().await? else {
                    return Ok(());
                };
                info!(
                    "[e3_id={e3_id}] CommitteePublished: joint CKKS pk {} bytes — applications open",
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

/// Input window closed: evaluate the round once (idempotent across the retry hooks).
async fn handle_deadline(e3_id: String, store: SharedStore<impl DataStore>) -> eyre::Result<()> {
    let mut repo = CreditE3Repository::new(store.clone(), &e3_id);
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
    if round.applications.is_empty() {
        warn!("[e3_id={e3_id}] window closed with no applications — not evaluating");
        repo.set_error("round closed with no applications".into())
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

/// `ApplicationPublished` carries no bytes — only the two keccaks — so this is a RAW log
/// handler: it keeps the transaction hash, fetches the calldata and recovers both ciphertexts.
async fn register_application_published(
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
                if log.topics().first() != Some(&ApplicationPublished::SIGNATURE_HASH) {
                    return Ok(());
                }
                let decoded = log.log_decode::<ApplicationPublished>()?;
                let ev = decoded.inner.data;
                let e3_id = ev.e3Id.to_string();
                let mut repo = CreditE3Repository::new(store, &e3_id);
                if repo.try_get().await?.is_none() {
                    return Ok(());
                }
                let tx_hash: B256 = log.transaction_hash.ok_or_else(|| eyre::eyre!("log without transaction hash"))?;
                let block = log.block_number.unwrap_or_default();
                let program = CreditProgram::new(&CONFIG.http_rpc_url, &CONFIG.private_key, &CONFIG.e3_program_address).await?;
                let ciphertexts = match program.transaction_input(tx_hash).await {
                    Ok(input) => match ciphertexts_from_calldata(&input, ev.logitCiphertextHash, ev.maskCiphertextHash) {
                        Ok(ct) => Some(ct),
                        Err(e) => {
                            error!("[e3_id={e3_id}] application tx {tx_hash}: {e}");
                            None
                        }
                    },
                    Err(e) => {
                        error!("[e3_id={e3_id}] could not fetch application tx {tx_hash}: {e}");
                        None
                    }
                };
                // The slot is assigned ON-CHAIN (position in the registered list).
                let index: u64 = ev.index.to::<u64>();
                info!(
                    "[e3_id={e3_id}] ApplicationPublished slot {index}: applicant {} tx {tx_hash} cts {} + {} bytes (5 Honk proofs verified on-chain)",
                    ev.applicant,
                    ciphertexts.as_ref().map(|c| c.0.len()).unwrap_or(0),
                    ciphertexts.as_ref().map(|c| c.1.len()).unwrap_or(0)
                );
                repo.insert_application(
                    IndexedApplication {
                        index,
                        publisher: ev.applicant.to_string(),
                        transaction_hash: tx_hash.to_string(),
                        block,
                        logit_ciphertext_hash: ev.logitCiphertextHash.to_string(),
                        mask_ciphertext_hash: ev.maskCiphertextHash.to_string(),
                        m_commitment_z: ev.mCommitmentZ.to_string(),
                        m_commitment_m: ev.mCommitmentM.to_string(),
                        ciphertext_available: ciphertexts.is_some(),
                    },
                    ciphertexts,
                )
                .await?;
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
                let mut repo = CreditE3Repository::new(store, &e3_id);
                let Some(round) = repo.try_get().await? else {
                    return Ok(());
                };
                let published_at = round.stage_at.iter().rev().find(|(s, _)| s == "published").map(|(_, t)| *t).unwrap_or(now_secs());
                repo.record_timing("threshold_decrypt_wall_secs", now_secs().saturating_sub(published_at)).await?;
                let opened = ckks_credit_program::decode_opened_slots(&event.plaintextOutput, round.snapshot.len())
                    .map_err(|e| eyre::eyre!("{e:#}"))?;
                info!(
                    "[e3_id={e3_id}] PlaintextOutputPublished: {} masked slot(s) opened — {:?} (σ(z_i) + m_i; meaningless without the applicants' masks)",
                    opened.len(),
                    opened
                );
                repo.set_results(RoundResults {
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
        "ckks-credit: creating indexer (interfold {interfold_address}, program {program_address})"
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
    let indexer = register_application_published(indexer, program_address.to_string()).await?;
    let indexer = register_plaintext_output_published(indexer).await?;
    // Cursor tracking without history replay: the handlers are not pure (evaluation publishes).
    indexer.configure_backfill(None, None);
    info!("ckks-credit: indexer listening");
    indexer.listen().await?;
    Ok(())
}
