// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! The chain indexer (CRISP `indexer.rs`): `E3Requested` → `CommitteePublished` (bidding opens,
//! deadline hook) → `VerifiedInputPublished` (bid accepted by the three-leg gate; ciphertext
//! recovered from calldata) → deadline: evaluate + publish → `PlaintextOutputPublished`
//! (decode the ±1 sign matrix, name the winner).

use crate::config::CONFIG;
use crate::server::contract::{ciphertext_from_calldata, AuctionProgram, VerifiedInputPublished};
use crate::server::evaluate::evaluate_and_publish;
use crate::server::models::{IndexedBid, RoundResults, RoundStatus};
use crate::server::repo::{now_secs, AuctionE3Repository};
use alloy::primitives::B256;
use alloy::sol_types::SolEvent;
use e3_sdk::evm_helpers::contracts::ReadWrite;
use e3_sdk::evm_helpers::events::{CommitteePublished, E3Requested, PlaintextOutputPublished};
use e3_sdk::indexer::{DataStore, InterfoldIndexer, SharedStore};
use log::{error, info, warn};
use std::error::Error;

type Result<T> = std::result::Result<T, Box<dyn Error + Send + Sync>>;

/// Re-tries of the deadline hook, seconds after the input window closes: the first pass can run
/// before the ceremony keys are on disk (~2.5 min DKG+ceremony on the dev stack).
const DEADLINE_RETRY_OFFSETS: [u64; 12] = [15, 30, 60, 90, 120, 180, 240, 300, 420, 600, 900, 1200];

async fn register_e3_requested(
    indexer: InterfoldIndexer<impl DataStore, ReadWrite>,
) -> Result<InterfoldIndexer<impl DataStore, ReadWrite>> {
    indexer
        .add_event_handler(move |event: E3Requested, ctx| {
            let e3_id = event.e3Id.to_string();
            let store = ctx.store();
            async move {
                let repo = AuctionE3Repository::new(store, &e3_id);
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
                let mut repo = AuctionE3Repository::new(store.clone(), &e3_id);
                let Some(round) = repo.try_get().await? else {
                    return Ok(());
                };
                info!(
                    "[e3_id={e3_id}] CommitteePublished: joint CKKS pk {} bytes — bidding open",
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

/// Input window closed: evaluate the auction once (idempotent across the retry hooks).
async fn handle_deadline(e3_id: String, store: SharedStore<impl DataStore>) -> eyre::Result<()> {
    let mut repo = AuctionE3Repository::new(store.clone(), &e3_id);
    let round = repo.get().await?;
    match round.status {
        RoundStatus::Active => {}
        RoundStatus::Evaluating => {
            // A previous pass is still waiting for ceremony keys / evaluating; let it be unless it
            // recorded an error we can retry.
            if round.error.is_none() {
                return Ok(());
            }
        }
        _ => return Ok(()),
    }
    if round.bids.len() < 2 {
        warn!(
            "[e3_id={e3_id}] window closed with {} bid(s) — need 2; not evaluating",
            round.bids.len()
        );
        repo.set_error(format!(
            "round closed with {} bid(s); need at least 2",
            round.bids.len()
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

/// `VerifiedInputPublished` carries no bytes — only `keccak(ciphertext)` — so this is a RAW log
/// handler: it keeps the transaction hash, fetches the calldata and recovers the ciphertext.
async fn register_verified_input_published(
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
                if log.topics().first() != Some(&VerifiedInputPublished::SIGNATURE_HASH) {
                    return Ok(());
                }
                let decoded = log.log_decode::<VerifiedInputPublished>()?;
                let ev = decoded.inner.data;
                let e3_id = ev.e3Id.to_string();
                let mut repo = AuctionE3Repository::new(store, &e3_id);
                if repo.try_get().await?.is_none() {
                    return Ok(());
                }
                let tx_hash: B256 = log.transaction_hash.ok_or_else(|| eyre::eyre!("log without transaction hash"))?;
                let block = log.block_number.unwrap_or_default();
                let program = AuctionProgram::new(&CONFIG.http_rpc_url, &CONFIG.private_key, &CONFIG.e3_program_address).await?;
                let ciphertext = match program.transaction_input(tx_hash).await {
                    Ok(input) => match ciphertext_from_calldata(&input, ev.ciphertextHash) {
                        Ok(ct) => Some(ct),
                        Err(e) => {
                            error!("[e3_id={e3_id}] bid tx {tx_hash}: {e}");
                            None
                        }
                    },
                    Err(e) => {
                        error!("[e3_id={e3_id}] could not fetch bid tx {tx_hash}: {e}");
                        None
                    }
                };
                let count = repo.get().await?.bids.len() as u64;
                let index = repo
                    .get()
                    .await?
                    .bids
                    .iter()
                    .position(|b| b.transaction_hash.eq_ignore_ascii_case(&tx_hash.to_string()))
                    .map(|i| i as u64)
                    .unwrap_or(count);
                info!(
                    "[e3_id={e3_id}] VerifiedInputPublished #{index}: publisher {} tx {tx_hash} ct {} bytes (3 Honk proofs verified on-chain)",
                    ev.publisher,
                    ciphertext.as_ref().map(|c| c.len()).unwrap_or(0)
                );
                repo.insert_bid(
                    IndexedBid {
                        index,
                        publisher: ev.publisher.to_string(),
                        transaction_hash: tx_hash.to_string(),
                        block,
                        ciphertext_hash: ev.ciphertextHash.to_string(),
                        m_commitment: ev.mCommitment.to_string(),
                        u_commitment: ev.uCommitment.to_string(),
                        ciphertext_available: ciphertext.is_some(),
                    },
                    ciphertext,
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
                let mut repo = AuctionE3Repository::new(store, &e3_id);
                let Some(round) = repo.try_get().await? else {
                    return Ok(());
                };
                let published_at = round.stage_at.iter().rev().find(|(s, _)| s == "published").map(|(_, t)| *t).unwrap_or(now_secs());
                repo.record_timing("threshold_decrypt_wall_secs", now_secs().saturating_sub(published_at)).await?;
                let outcome = ckks_auction_program::decode_outcome(&event.plaintextOutput, round.bids.len()).map_err(|e| eyre::eyre!("{e:#}"))?;
                let winner_address = round.bids.get(outcome.winner).map(|b| b.publisher.clone());
                info!(
                    "[e3_id={e3_id}] PlaintextOutputPublished: signs {:?} binarized={} → WINNER bidder #{} ({})",
                    outcome.signs,
                    outcome.binarized,
                    outcome.winner,
                    winner_address.clone().unwrap_or_default()
                );
                if !outcome.binarized {
                    warn!("[e3_id={e3_id}] some slots are not saturated ±1 (gap below ~2% of the bound): {:?}", outcome.values);
                }
                repo.set_results(RoundResults {
                    pairs: outcome.pairs,
                    values: outcome.values,
                    signs: outcome.signs,
                    binarized: outcome.binarized,
                    wins: outcome.wins,
                    winner: outcome.winner,
                    winner_address,
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
        "ckks-auction: creating indexer (interfold {interfold_address}, program {program_address})"
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
    let indexer = register_verified_input_published(indexer, program_address.to_string()).await?;
    let indexer = register_plaintext_output_published(indexer).await?;
    // Cursor tracking without history replay: the handlers are not pure (evaluation publishes).
    indexer.configure_backfill(None, None);
    info!("ckks-auction: indexer listening");
    indexer.listen().await?;
    Ok(())
}
