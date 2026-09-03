// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Chain indexer: subscribes to the Interfold + salary-program events and
//! keeps the round records current.
//!
//! * `E3Requested` (program == ours) → `Requested`
//! * `CommitteePublished` → joint pk stored, `Open`
//! * `VerifiedInputPublished` (program) → submission confirmed
//! * `CiphertextOutputPublished` → `Evaluating`
//! * `PlaintextOutputPublished` → statistics decoded, `Complete`
//!
//! Also schedules the input-window close (`Open` → `Closed`) so the
//! evaluator can pick the round up.

use std::sync::Arc;

use alloy::primitives::Address;
use alloy::sol_types::SolEvent;
use e3_sdk::evm_helpers::contracts::{InterfoldRead, ReadWrite};
use e3_sdk::evm_helpers::events::{
    CiphertextOutputPublished, CommitteePublished, E3Requested, PlaintextOutputPublished,
};
use e3_sdk::indexer::{DataStore, InterfoldIndexer, SharedStore};
use log::{error, info, warn};

use super::chain::VerifiedInputPublished;
use super::database::SledDB;
use super::models::{now_secs, Results, Round, RoundStatus, Submission};
use super::repo::RoundRepository;
use crate::config::CONFIG;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

pub struct IndexerConfig {
    pub ws_rpc_url: String,
    pub interfold_address: String,
    pub registry_address: String,
    pub program_address: String,
    pub private_key: String,
}

async fn register_e3_requested(
    indexer: InterfoldIndexer<SharedStore<SledDB>, ReadWrite>,
    program: Address,
) -> Result<InterfoldIndexer<SharedStore<SledDB>, ReadWrite>> {
    indexer
        .add_event_handler(move |event: E3Requested, ctx| {
            let store = ctx.store();
            async move {
                if event.e3.e3Program != program {
                    return Ok(());
                }
                let e3_id = event.e3Id.to_string();
                info!("[e3_id={e3_id}] E3Requested through the salary program");
                let mut repo = RoundRepository::new(store, &e3_id);
                if repo.get().await?.is_some() {
                    // Created optimistically by the admin route.
                    repo.update(|r| {
                        if r.status == RoundStatus::Requested {
                            r.input_window = [
                                event.e3.inputWindow[0].to::<u64>(),
                                event.e3.inputWindow[1].to::<u64>(),
                            ];
                        }
                    })
                    .await?;
                    return Ok(());
                }
                let round = Round {
                    e3_id: e3_id.clone(),
                    chain_id: ctx.chain_id(),
                    status: RoundStatus::Requested,
                    program_address: format!("{program:#x}"),
                    requester: format!("{:#x}", event.e3.requester),
                    param_set: event.e3.paramSet,
                    salary_cap: CONFIG.salary_cap,
                    input_window: [
                        event.e3.inputWindow[0].to::<u64>(),
                        event.e3.inputWindow[1].to::<u64>(),
                    ],
                    requested_at: now_secs(),
                    request_tx_hash: None,
                    request_block: event.e3.requestBlock.to::<u64>(),
                    committee: vec![],
                    public_key_hex: None,
                    key_published_at: None,
                    submissions: vec![],
                    evaluation: None,
                    results: None,
                    failure_reason: None,
                };
                repo.set(&round).await?;
                Ok(())
            }
        })
        .await;
    Ok(indexer)
}

async fn register_committee_published(
    indexer: InterfoldIndexer<SharedStore<SledDB>, ReadWrite>,
) -> Result<InterfoldIndexer<SharedStore<SledDB>, ReadWrite>> {
    indexer
        .add_event_handler(move |event: CommitteePublished, ctx| {
            let store = ctx.store();
            let contract = ctx.contract();
            async move {
                let e3_id = event.e3Id.to_string();
                let mut repo = RoundRepository::new(store.clone(), &e3_id);
                if repo.get().await?.is_none() {
                    return Ok(()); // not one of ours
                }
                info!(
                    "[e3_id={e3_id}] CommitteePublished: pk {} bytes, {} nodes",
                    event.publicKey.len(),
                    event.nodes.len()
                );
                let pk = format!("0x{}", hex::encode(&event.publicKey));
                let nodes: Vec<String> = event.nodes.iter().map(|a| format!("{a:#x}")).collect();
                let close_at = match contract.get_e3(event.e3Id).await {
                    Ok(e3) => Some(e3.inputWindow[1].to::<u64>()),
                    Err(e) => {
                        warn!("[e3_id={e3_id}] get_e3 failed: {e}");
                        None
                    }
                };
                let round = repo
                    .update(|r| {
                        r.public_key_hex = Some(pk.clone());
                        r.key_published_at = Some(now_secs());
                        r.committee = nodes.clone();
                        if let Some(c) = close_at {
                            r.input_window[1] = c;
                        }
                        if r.status == RoundStatus::Requested {
                            r.status = RoundStatus::Open;
                        }
                    })
                    .await?;
                // Close the window when it ends (plus retries in case the
                // block clock lags).
                for offset in [0u64, 5, 15, 60] {
                    let e3_id = e3_id.clone();
                    let store = store.clone();
                    ctx.do_later(round.input_window[1] + offset, move |_, _| {
                        let e3_id = e3_id.clone();
                        let store = store.clone();
                        async move {
                            close_round(store, &e3_id).await;
                            Ok(())
                        }
                    });
                }
                Ok(())
            }
        })
        .await;
    Ok(indexer)
}

pub async fn close_round<S: DataStore>(store: SharedStore<S>, e3_id: &str) {
    let mut repo = RoundRepository::new(store, e3_id);
    if let Ok(Some(r)) = repo.get().await {
        if r.status == RoundStatus::Open {
            info!(
                "[e3_id={e3_id}] input window closed ({} submissions)",
                r.submission_count()
            );
            if let Err(e) = repo.set_status(RoundStatus::Closed).await {
                error!("[e3_id={e3_id}] closing round failed: {e}");
            }
        }
    }
}

async fn register_verified_input_published(
    indexer: InterfoldIndexer<SharedStore<SledDB>, ReadWrite>,
    program: Address,
) -> Result<InterfoldIndexer<SharedStore<SledDB>, ReadWrite>> {
    indexer
        .add_raw_log_handler(move |log, ctx| {
            let store = ctx.store();
            async move {
                if log.address() != program {
                    return Ok(());
                }
                if log.topic0() != Some(&VerifiedInputPublished::SIGNATURE_HASH) {
                    return Ok(());
                }
                let decoded = log.log_decode::<VerifiedInputPublished>()?;
                let ev = decoded.inner.data;
                let e3_id = ev.e3Id.to_string();
                let mut repo = RoundRepository::new(store, &e3_id);
                if repo.get().await?.is_none() {
                    return Ok(());
                }
                let submission = Submission {
                    index: 0,
                    publisher: format!("{:#x}", ev.publisher),
                    tx_hash: log
                        .transaction_hash
                        .map(|h| format!("{h:#x}"))
                        .unwrap_or_default(),
                    block_number: log.block_number.unwrap_or_default(),
                    ciphertext_hash: format!("{:#x}", ev.ciphertextHash),
                    m_commitment: format!("{:#x}", ev.mCommitment),
                    u_commitment: format!("{:#x}", ev.uCommitment),
                    ciphertext_bytes: 0,
                    verified: true,
                    gas_used: None,
                    submitted_at: now_secs(),
                };
                let index = repo.add_submission(submission, &[]).await?;
                info!(
                    "[e3_id={e3_id}] VerifiedInputPublished #{index} u_commitment={:#x} tx={}",
                    ev.uCommitment,
                    log.transaction_hash
                        .map(|h| format!("{h:#x}"))
                        .unwrap_or_default()
                );
                Ok(())
            }
        })
        .await;
    Ok(indexer)
}

async fn register_ciphertext_output_published(
    indexer: InterfoldIndexer<SharedStore<SledDB>, ReadWrite>,
) -> Result<InterfoldIndexer<SharedStore<SledDB>, ReadWrite>> {
    indexer
        .add_event_handler(move |event: CiphertextOutputPublished, ctx| {
            let store = ctx.store();
            async move {
                let e3_id = event.e3Id.to_string();
                let mut repo = RoundRepository::new(store, &e3_id);
                if repo.get().await?.is_none() {
                    return Ok(());
                }
                info!(
                    "[e3_id={e3_id}] CiphertextOutputPublished ({} bytes) — committee decrypting",
                    event.ciphertextOutput.len()
                );
                repo.update(|r| {
                    if matches!(r.status, RoundStatus::Open | RoundStatus::Closed) {
                        r.status = RoundStatus::Evaluating;
                    }
                })
                .await?;
                Ok(())
            }
        })
        .await;
    Ok(indexer)
}

async fn register_plaintext_output_published(
    indexer: InterfoldIndexer<SharedStore<SledDB>, ReadWrite>,
) -> Result<InterfoldIndexer<SharedStore<SledDB>, ReadWrite>> {
    indexer
        .add_event_handler(move |event: PlaintextOutputPublished, ctx| {
            let store = ctx.store();
            async move {
                let e3_id = event.e3Id.to_string();
                let mut repo = RoundRepository::new(store, &e3_id);
                let Some(round) = repo.get().await? else {
                    return Ok(());
                };
                let count = round.submission_count() as u64;
                let plaintext = event.plaintextOutput.to_vec();
                let stats = ckks_salary_program::decode_statistics(
                    &plaintext,
                    count.max(1),
                    round.salary_cap,
                )
                .map_err(|e| eyre::eyre!("{e}"))?;
                let opened_slots =
                    ckks_salary_program::decode_fixed_point(&plaintext).unwrap_or_default();
                info!(
                    "[e3_id={e3_id}] PlaintextOutputPublished: count {count}, mean {:.2}, variance {:.2}, stddev {:.2} — individual salaries never decrypted",
                    stats.mean, stats.variance, stats.stddev
                );
                repo.update(|r| {
                    r.status = RoundStatus::Complete;
                    r.results = Some(Results {
                        count,
                        sum: stats.sum,
                        sum_of_squares: stats.sum_of_squares,
                        mean: stats.mean,
                        variance: stats.variance,
                        stddev: stats.stddev,
                        opened_slots: opened_slots.clone(),
                        plaintext_hex: format!("0x{}", hex::encode(&plaintext)),
                        plaintext_tx_hash: None,
                        decrypted_at: now_secs(),
                    });
                })
                .await?;
                Ok(())
            }
        })
        .await;
    Ok(indexer)
}

pub async fn start_indexer(cfg: IndexerConfig, store: SharedStore<SledDB>) -> Result<()> {
    let program: Address = cfg.program_address.parse()?;
    let watched = [
        cfg.interfold_address.as_str(),
        cfg.registry_address.as_str(),
        cfg.program_address.as_str(),
    ];
    let indexer = InterfoldIndexer::new_with_write_contract(
        &cfg.ws_rpc_url,
        &watched,
        store,
        &cfg.private_key,
    )
    .await?;
    let indexer = register_e3_requested(indexer, program).await?;
    let indexer = register_committee_published(indexer).await?;
    let indexer = register_verified_input_published(indexer, program).await?;
    let indexer = register_ciphertext_output_published(indexer).await?;
    let indexer = register_plaintext_output_published(indexer).await?;
    info!("salary-survey indexer: handlers registered, listening");
    let indexer = Arc::new(indexer);
    indexer.listen().await?;
    Ok(())
}
