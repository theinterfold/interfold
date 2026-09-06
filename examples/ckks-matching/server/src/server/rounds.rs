// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Round opening: request the E3 THROUGH `CkksMatchingE3Program` (the program address
//! selects the CKKS scheme and ParamSet 5), then REGISTER the round on the program: the
//! two parties `[A, B]` (slot `i` = position `i` = role bit) — what the on-chain gate checks
//! every submission's validity-leg `role` / `index` / `address` public inputs against.

use crate::config::CONFIG;
use crate::server::contract::MatchingProgram;
use crate::server::models::{E3Matching, RoundStatus};
use crate::server::repo::{now_secs, MatchingE3Repository, RoundIndexRepository};
use alloy::primitives::{Address, Bytes, U256};
use alloy::sol;
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
const PARAM_SET: u8 = ckks_matching_program::PARAM_SET;

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

/// Opens a round: request E3 → register `[A, B]` → store the record. Returns the e3Id.
pub async fn open_round(
    store: SharedStore<impl DataStore>,
    party_a: String,
    party_b: String,
    duration_secs: Option<u64>,
) -> Result<String> {
    let a: Address = party_a
        .parse()
        .map_err(|e| eyre!("party A {party_a}: {e}"))?;
    let b: Address = party_b
        .parse()
        .map_err(|e| eyre!("party B {party_b}: {e}"))?;
    if a == b {
        return Err(eyre!("party A and party B must be distinct addresses"));
    }
    if a == Address::ZERO || b == Address::ZERO {
        return Err(eyre!("a party address must not be zero"));
    }

    let program = MatchingProgram::new(
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
        "requesting E3 through CkksMatchingE3Program {} (ParamSet {PARAM_SET}, window {start}..{})",
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

    let reg_receipt = program
        .register_round(U256::from_str_radix(&e3_id, 10)?, a, b)
        .await?;
    info!(
        "[e3_id={e3_id}] round registered on-chain (A = {a} forward, B = {b} reversed): tx {}",
        reg_receipt.transaction_hash
    );

    let created = now_secs();
    let record = E3Matching {
        e3_id: e3_id.clone(),
        status: RoundStatus::Requested,
        created_at: created,
        input_window: [start, start + duration],
        parties: vec![a.to_string(), b.to_string()],
        submissions: vec![],
        ciphertexts: vec![],
        results: None,
        error: None,
        timings: vec![],
        stage_at: vec![("requested".into(), created)],
    };
    MatchingE3Repository::new(store.clone(), &e3_id)
        .set(&record)
        .await?;
    RoundIndexRepository::new(store)
        .record_round(&e3_id)
        .await?;
    Ok(e3_id)
}

/// The default dev pair: anvil accounts 6 (A) and 7 (B) — the wallets the client offers
/// and `scripts/e2e.mjs` uses (1–5 are the ciphernodes, 0 is the round opener).
pub fn get_mock_parties() -> (String, String) {
    (
        "0x976EA74026E726554dB657fA54763abd0C3a0aa9".to_string(),
        "0x14dC79964da2C08b23698B3D3cc7Ca32193d9955".to_string(),
    )
}
