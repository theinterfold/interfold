// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Round opening (CRISP `cli/commands.rs::request_e3` + `E3Requested` census handling): build the
//! balance snapshot tree, request the E3 THROUGH `CkksAuctionE3Program` (the program address
//! selects the CKKS scheme and ParamSet 2), and publish the root on the program for the round.

use crate::config::CONFIG;
use crate::server::contract::AuctionProgram;
use crate::server::models::{E3Auction, RoundStatus, TokenHolder};
use crate::server::repo::{now_secs, AuctionE3Repository, RoundIndexRepository};
use crate::server::token_holders::{build_tree, compute_token_holder_hashes};
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
/// ParamSet 2 = the CKKS sign-extraction ladder.
const PARAM_SET: u8 = ckks_auction_program::PARAM_SET;

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

/// Opens a round: tree → request E3 → set balance root → store the record. Returns the e3Id.
pub async fn open_round(
    store: SharedStore<impl DataStore>,
    snapshot: Vec<TokenHolder>,
    duration_secs: Option<u64>,
) -> Result<String> {
    let tree = build_tree(&snapshot)?;
    let hashes = compute_token_holder_hashes(&snapshot)?;
    let root_hex = tree.root_hex();

    let program = AuctionProgram::new(
        &CONFIG.http_rpc_url,
        &CONFIG.private_key,
        &CONFIG.e3_program_address,
    )
    .await?;
    let bid_cap: u64 = program.bid_cap().await?.to::<u64>();

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
        "requesting E3 through CkksAuctionE3Program {} (ParamSet {PARAM_SET}, window {start}..{})",
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

    let root_receipt = program
        .set_balance_root(U256::from_str_radix(&e3_id, 10)?, tree.root_bytes())
        .await?;
    info!(
        "[e3_id={e3_id}] balance root {root_hex} set on-chain: tx {} ({} holders)",
        root_receipt.transaction_hash,
        snapshot.len()
    );

    let created = now_secs();
    let record = E3Auction {
        e3_id: e3_id.clone(),
        status: RoundStatus::Requested,
        created_at: created,
        input_window: [start, start + duration],
        bid_cap,
        snapshot,
        token_holder_hashes: hashes,
        balance_root: Some(root_hex),
        bids: vec![],
        ciphertexts: vec![],
        results: None,
        error: None,
        timings: vec![],
        stage_at: vec![("requested".into(), created)],
    };
    AuctionE3Repository::new(store.clone(), &e3_id)
        .set(&record)
        .await?;
    RoundIndexRepository::new(store)
        .record_round(&e3_id)
        .await?;
    Ok(e3_id)
}
