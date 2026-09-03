// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Evaluate-and-publish job (CRISP's `program_server_request::run_compute`): once the input
//! window closes, run the sign-extraction policy over the indexed bid ciphertexts with the
//! committee's ceremony keys and publish the evaluated ciphertext on-chain, which triggers the
//! threshold decryption.

use crate::config::CONFIG;
use crate::server::contract::ciphertext_commitment;
use crate::server::models::RoundStatus;
use crate::server::repo::AuctionE3Repository;
use alloy::primitives::{Bytes, U256};
use e3_sdk::evm_helpers::contracts::{InterfoldContract, InterfoldWrite};
use e3_sdk::indexer::{DataStore, SharedStore};
use eyre::{eyre, Result};
use log::info;
use std::path::{Path, PathBuf};
use std::time::Instant;

/// `<CKKS_RELIN_KEY_DIR>/<chain_id>:<e3_id>` — how the ciphernodes key ceremony output.
pub fn ceremony_dir(e3_id: &str) -> PathBuf {
    Path::new(&CONFIG.ckks_relin_key_dir).join(format!("{}:{}", CONFIG.chain_id, e3_id))
}

/// Number of joint key files present for `e3_id` (the ONE `rlk_hybrid.bin` for the hybrid
/// ceremony ParamSet 2 runs; `rlk_level_*.bin` for a per-level plan).
pub fn ceremony_key_count(e3_id: &str) -> usize {
    let wanted = ckks_auction_program::ceremony_key_files();
    std::fs::read_dir(ceremony_dir(e3_id))
        .map(|d| {
            d.filter_map(|e| e.ok())
                .filter(|e| wanted.iter().any(|w| *w == e.file_name().to_string_lossy()))
                .count()
        })
        .unwrap_or(0)
}

pub async fn evaluate_and_publish(store: SharedStore<impl DataStore>, e3_id: &str) -> Result<()> {
    let mut repo = AuctionE3Repository::new(store, e3_id);
    let round = repo.get().await?;

    let expected = ckks_auction_program::expected_ceremony_keys();
    let have = ceremony_key_count(e3_id);
    if have < expected {
        return Err(eyre!(
            "relin ceremony incomplete: {have}/{expected} joint keys in {}",
            ceremony_dir(e3_id).display()
        ));
    }

    let mut bids: Vec<(u64, Vec<u8>)> = round.ciphertexts.clone();
    bids.sort_by_key(|(i, _)| *i);
    if bids.len() != round.bids.len() {
        return Err(eyre!(
            "{} bid(s) indexed but only {} ciphertext(s) recovered from calldata",
            round.bids.len(),
            bids.len()
        ));
    }
    let inputs: Vec<Vec<u8>> = bids.into_iter().map(|(_, ct)| ct).collect();

    info!(
        "[e3_id={e3_id}] evaluating: {} bids, {} pairs, bound {}, 12 sign iterations, ONE hybrid ceremony key from {}",
        inputs.len(),
        inputs.len() * (inputs.len() - 1) / 2,
        CONFIG.bid_bound,
        ceremony_dir(e3_id).display()
    );
    let t0 = Instant::now();
    let dir = ceremony_dir(e3_id);
    let bound = CONFIG.bid_bound;
    let output =
        tokio::task::spawn_blocking(move || ckks_auction_program::evaluate(&inputs, bound, &dir))
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
