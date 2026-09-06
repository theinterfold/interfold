// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Round opening: request the E3 THROUGH `CkksTreasuryE3Program` (the program address
//! selects the CKKS scheme and ParamSet 5), then REGISTER the round on the program: the
//! public risk weights `w[4]` (fixed point `× 2^16`, negatives as `p − |W|` words) and the
//! DAO list (slot `i` = position `i`) — what the on-chain gate checks every submission's
//! validity-leg `weights` / `index` / `address` public inputs against.

use crate::config::CONFIG;
use crate::server::contract::TreasuryProgram;
use crate::server::models::{E3Treasury, RoundStatus};
use crate::server::repo::{now_secs, RoundIndexRepository, TreasuryE3Repository};
use alloy::primitives::{Address, Bytes, U256};
use alloy::sol;
use ckks_treasury_program::{Weights, ASSETS, MIN_DAOS};
use e3_sdk::evm_helpers::contracts::{
    CommitteeSize, InterfoldContract, InterfoldRead, InterfoldWrite,
};
use e3_sdk::indexer::{DataStore, SharedStore};
use eyre::{eyre, Result};
use log::info;

sol! {
    #[sol(rpc)]
    contract ERC20 {
        function approve(address spender, uint256 amount) external returns (bool);
        function allowance(address owner, address spender) external view returns (uint256);
        function balanceOf(address owner) external view returns (uint256);
        function mint(address to, uint256 amount) external;
    }
}

/// Seconds between now and `inputWindow[0]` (covers the approve + request txs).
const INPUT_WINDOW_START_BUFFER_SECS: u64 = 20;
/// ParamSet 5 = the coefficient-encoded preset.
const PARAM_SET: u8 = ckks_treasury_program::PARAM_SET;

async fn approve_fee(fee: U256) -> Result<()> {
    use alloy::network::EthereumWallet;
    use alloy::providers::ProviderBuilder;
    use alloy::signers::local::PrivateKeySigner;
    let signer: PrivateKeySigner = CONFIG.private_key.parse()?;
    let owner = signer.address();
    let provider = ProviderBuilder::new()
        .wallet(EthereumWallet::from(signer))
        .connect(&CONFIG.http_rpc_url)
        .await?;
    let token = ERC20::new(CONFIG.fee_token_address.parse()?, &provider);
    let spender: Address = CONFIG.interfold_address.parse()?;
    let balance = token.balanceOf(owner).call().await?;
    if balance < fee {
        // MockUSDC on the dev stack is freely mintable (the hardhat task does the same).
        let mint = fee - balance + U256::from(1_000_000_000u64);
        token.mint(owner, mint).send().await?.get_receipt().await?;
        info!("minted {mint} fee tokens for the round opener");
    }
    if token.allowance(owner, spender).call().await? < fee {
        token
            .approve(spender, fee)
            .send()
            .await?
            .get_receipt()
            .await?;
    }
    Ok(())
}

/// Parses + validates the round's DAO list: distinct, non-zero, at least [`MIN_DAOS`].
pub fn parse_daos(daos: &[String]) -> Result<Vec<Address>> {
    let mut out = Vec::with_capacity(daos.len());
    for d in daos {
        let a: Address = d.parse().map_err(|e| eyre!("DAO {d}: {e}"))?;
        if a == Address::ZERO {
            return Err(eyre!("a DAO address must not be zero"));
        }
        if out.contains(&a) {
            return Err(eyre!("duplicate DAO {a}"));
        }
        out.push(a);
    }
    if out.len() < MIN_DAOS {
        return Err(eyre!(
            "a round needs at least {MIN_DAOS} DAOs (one DAO's aggregate is its own book); got {}",
            out.len()
        ));
    }
    Ok(out)
}

/// Parses + validates the round's public weights: exactly [`ASSETS`], each `|w| ≤ 1`.
pub fn parse_weights(weights: &[f64]) -> Result<Weights> {
    if weights.len() != ASSETS {
        return Err(eyre!("expected {ASSETS} weights, got {}", weights.len()));
    }
    let w = Weights(std::array::from_fn(|a| weights[a]));
    w.validate().map_err(|e| eyre!("{e}"))?;
    Ok(w)
}

/// Opens a round: request E3 → register `(weights, daos)` → store the record. Returns the e3Id.
pub async fn open_round(
    store: SharedStore<impl DataStore>,
    weights: Vec<f64>,
    daos: Vec<String>,
    duration_secs: Option<u64>,
) -> Result<String> {
    let weights = parse_weights(&weights)?;
    let daos = parse_daos(&daos)?;

    let program = TreasuryProgram::new(
        &CONFIG.http_rpc_url,
        &CONFIG.private_key,
        &CONFIG.e3_program_address,
    )
    .await?;

    let contract = InterfoldContract::new(
        &CONFIG.http_rpc_url,
        &CONFIG.private_key,
        &CONFIG.interfold_address,
    )
    .await?;
    let e3_program: Address = CONFIG.e3_program_address.parse()?;
    let committee_size = match CONFIG.e3_committee_size {
        0 => CommitteeSize::Minimum,
        1 => CommitteeSize::Micro,
        2 => CommitteeSize::Small,
        n => return Err(eyre!("invalid committee size {n}")),
    };
    let duration = duration_secs.unwrap_or(CONFIG.e3_duration);
    let now = program.latest_timestamp().await?;
    let start = now + INPUT_WINDOW_START_BUFFER_SECS;
    let input_window = [U256::from(start), U256::from(start + duration)];
    // The CKKS programs ignore compute-provider params; the decryption verifier is the mock.
    let compute_params = Bytes::new();
    let custom_params = Bytes::new();

    let fee = contract
        .get_e3_quote(
            committee_size,
            input_window,
            e3_program,
            PARAM_SET,
            compute_params.clone(),
        )
        .await?;
    approve_fee(fee).await?;
    info!(
        "requesting E3 through CkksTreasuryE3Program {} (ParamSet {PARAM_SET}, window {start}..{})",
        e3_program,
        start + duration
    );
    let (receipt, e3_id) = contract
        .request_e3(
            committee_size,
            input_window,
            e3_program,
            PARAM_SET,
            compute_params,
            custom_params,
        )
        .await
        .map_err(|e| eyre!("request_e3 reverted: {e}"))?;
    let e3_id = e3_id.to_string();
    info!(
        "[e3_id={e3_id}] E3 requested: tx {}",
        receipt.transaction_hash
    );

    let fixed = weights.fixed_point();
    let reg_receipt = program
        .register_round(U256::from_str_radix(&e3_id, 10)?, &fixed, daos.clone())
        .await?;
    info!(
        "[e3_id={e3_id}] round registered on-chain (weights {:?} = {:?} ×2^16, {} DAOs): tx {}",
        weights.0,
        fixed.0,
        daos.len(),
        reg_receipt.transaction_hash
    );

    let created = now_secs();
    let record = E3Treasury {
        e3_id: e3_id.clone(),
        status: RoundStatus::Requested,
        created_at: created,
        input_window: [start, start + duration],
        weights: weights.0,
        daos: daos.iter().map(|a| a.to_string()).collect(),
        submissions: vec![],
        ciphertexts: vec![],
        results: None,
        error: None,
        timings: vec![],
        stage_at: vec![("requested".into(), created)],
    };
    TreasuryE3Repository::new(store.clone(), &e3_id)
        .set(&record)
        .await?;
    RoundIndexRepository::new(store)
        .record_round(&e3_id)
        .await?;
    Ok(e3_id)
}

/// The default dev DAOs: anvil accounts 6, 7 and 8 — the wallets the client offers
/// and `scripts/e2e.mjs` uses (1–5 are the ciphernodes, 0 is the round opener).
pub fn get_mock_daos() -> Vec<String> {
    vec![
        "0x976EA74026E726554dB657fA54763abd0C3a0aa9".to_string(),
        "0x14dC79964da2C08b23698B3D3cc7Ca32193d9955".to_string(),
        "0x23618e81E3f5cdF7f54C3d65f7FBc0aBf5B21E8f".to_string(),
    ]
}

/// The default dev weights: the contract fixture's `[0.5, −0.25, 1.0, 0.125]`.
pub fn get_mock_weights() -> [f64; ASSETS] {
    [0.5, -0.25, 1.0, 0.125]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dao_list_needs_two_distinct_non_zero_addresses() {
        let daos = get_mock_daos();
        assert_eq!(parse_daos(&daos).unwrap().len(), 3);
        assert!(parse_daos(&daos[..1]).is_err());
        assert!(parse_daos(&[daos[0].clone(), daos[0].clone()]).is_err());
        assert!(parse_daos(&[daos[0].clone(), format!("0x{}", "0".repeat(40))]).is_err());
        assert!(parse_daos(&[daos[0].clone(), "nope".into()]).is_err());
    }

    #[test]
    fn weights_need_four_bounded_entries() {
        let w = parse_weights(&get_mock_weights()).unwrap();
        assert_eq!(w.fixed_point().0, [32768, -16384, 65536, 8192]);
        assert!(parse_weights(&[0.5, 0.5, 0.5]).is_err());
        assert!(parse_weights(&[1.5, 0.0, 0.0, 0.0]).is_err());
        assert!(parse_weights(&[f64::NAN, 0.0, 0.0, 0.0]).is_err());
    }
}
