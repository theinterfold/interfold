// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Round opening: build the issuer snapshot tree, request the E3 THROUGH `CkksCreditE3Program`
//! (the program address selects the CKKS scheme and ParamSet 4), then REGISTER the round on the
//! program: the issuer root, the public model in the circuit's fixed point (`×2^16`) and the
//! applicant list (slot `i` = snapshot position `i`) — the three things the on-chain gate
//! checks every application's validity-leg public inputs against.

use crate::config::CONFIG;
use crate::server::contract::CreditProgram;
use crate::server::models::{Applicant, E3Credit, RoundStatus};
use crate::server::repo::{now_secs, CreditE3Repository, RoundIndexRepository};
use crate::server::snapshot::{build_tree, compute_leaf_hashes};
use alloy::primitives::{Address, Bytes, U256};
use alloy::sol;
use ckks_credit_program::Model;
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
/// ParamSet 4 = the credit-scoring preset.
const PARAM_SET: u8 = ckks_credit_program::PARAM_SET;
/// The public normalization cap every feature is over (`x_j / cap`).
pub const FEATURE_CAP: u64 = 1000;

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

/// Opens a round: tree → request E3 → register root + model + applicants → store the record.
/// Returns the e3Id.
pub async fn open_round(
    store: SharedStore<impl DataStore>,
    snapshot: Vec<Applicant>,
    model: Model,
    duration_secs: Option<u64>,
) -> Result<String> {
    model.validate().map_err(|e| eyre!("{e:#}"))?;
    let max = ckks_credit_program::max_applicants().map_err(|e| eyre!("{e:#}"))?;
    if snapshot.len() > max {
        return Err(eyre!(
            "{} applicants exceed the {max} slots of one ParamSet-{PARAM_SET} output",
            snapshot.len()
        ));
    }
    let mut seen = std::collections::HashSet::new();
    for a in &snapshot {
        if !seen.insert(a.address.to_lowercase()) {
            return Err(eyre!("duplicate applicant {} in the snapshot", a.address));
        }
    }

    let program = CreditProgram::new(
        &CONFIG.http_rpc_url,
        &CONFIG.private_key,
        &CONFIG.e3_program_address,
    )
    .await?;
    let cap: u64 = FEATURE_CAP;
    let tree = build_tree(&snapshot, cap)?;
    let hashes = compute_leaf_hashes(&snapshot, cap)?;
    let root_hex = tree.root_hex();

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
        "requesting E3 through CkksCreditE3Program {} (ParamSet {PARAM_SET}, window {start}..{})",
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

    let fixed = model.fixed_point();
    let applicants: Vec<Address> = snapshot
        .iter()
        .map(|a| a.address.parse::<Address>())
        .collect::<std::result::Result<_, _>>()?;
    let root_receipt = program
        .register_round(
            U256::from_str_radix(&e3_id, 10)?,
            tree.root_bytes(),
            cap,
            &fixed,
            applicants,
        )
        .await?;
    info!(
        "[e3_id={e3_id}] round registered on-chain (root {root_hex}, {} applicants, cap {cap}, model ×2^16 {:?} + {}): tx {}",
        snapshot.len(),
        fixed.weights,
        fixed.bias,
        root_receipt.transaction_hash
    );

    let created = now_secs();
    let record = E3Credit {
        e3_id: e3_id.clone(),
        status: RoundStatus::Requested,
        created_at: created,
        input_window: [start, start + duration],
        cap,
        model,
        fixed_point_model: Some(fixed),
        snapshot,
        leaf_hashes: hashes,
        issuer_root: Some(root_hex),
        applications: vec![],
        ciphertexts: vec![],
        results: None,
        error: None,
        timings: vec![],
        stage_at: vec![("requested".into(), created)],
    };
    CreditE3Repository::new(store.clone(), &e3_id)
        .set(&record)
        .await?;
    RoundIndexRepository::new(store)
        .record_round(&e3_id)
        .await?;
    Ok(e3_id)
}
