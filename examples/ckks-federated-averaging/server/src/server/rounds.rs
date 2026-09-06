// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Round opening: request the E3 THROUGH `CkksFedAvgE3Program` (the program address selects
//! the CKKS scheme and ParamSet 5), then REGISTER the round on the program: the squared-norm
//! bound in the circuit's fixed point (`× 2^32`), the public minimum client count and the
//! client list (slot `i` = position `i`) — what the on-chain gate checks every update's
//! validity-leg public inputs against.

use crate::config::CONFIG;
use crate::server::contract::FedAvgProgram;
use crate::server::models::{E3FedAvg, RoundStatus};
use crate::server::repo::{now_secs, FedAvgE3Repository, RoundIndexRepository};
use alloy::primitives::{Address, Bytes, U256};
use alloy::sol;
use ckks_fedavg_program::RoundParams;
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
/// ParamSet 5 = the coefficient-transport preset.
const PARAM_SET: u8 = ckks_fedavg_program::PARAM_SET;

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

/// Opens a round: request E3 → register bound + min clients + client list → store the record.
/// Returns the e3Id.
pub async fn open_round(
    store: SharedStore<impl DataStore>,
    clients: Vec<String>,
    params: RoundParams,
    duration_secs: Option<u64>,
) -> Result<String> {
    params.validate().map_err(|e| eyre!("{e:#}"))?;
    if clients.is_empty() {
        return Err(eyre!("client list must not be empty"));
    }
    if params.min_clients > clients.len() {
        return Err(eyre!(
            "min_clients {} exceeds the {} registered clients",
            params.min_clients,
            clients.len()
        ));
    }
    let mut seen = std::collections::HashSet::new();
    let addresses: Vec<Address> = clients
        .iter()
        .map(|a| {
            a.parse::<Address>()
                .map_err(|e| eyre!("invalid client address {a}: {e}"))
        })
        .collect::<Result<_>>()?;
    for a in &addresses {
        if !seen.insert(*a) {
            return Err(eyre!("duplicate client {a} in the list"));
        }
    }

    let program = FedAvgProgram::new(
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
        "requesting E3 through CkksFedAvgE3Program {} (ParamSet {PARAM_SET}, window {start}..{})",
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

    let bound_fp = params.norm_bound_fixed_point();
    let reg_receipt = program
        .register_round(
            U256::from_str_radix(&e3_id, 10)?,
            bound_fp,
            params.min_clients,
            addresses,
        )
        .await?;
    info!(
        "[e3_id={e3_id}] round registered on-chain (d {}, norm bound {} = {bound_fp} ×2^-32, min clients {}, {} clients): tx {}",
        params.d,
        params.norm_bound,
        params.min_clients,
        clients.len(),
        reg_receipt.transaction_hash
    );

    let created = now_secs();
    let record = E3FedAvg {
        e3_id: e3_id.clone(),
        status: RoundStatus::Requested,
        created_at: created,
        input_window: [start, start + duration],
        params,
        norm_bound_fixed_point: bound_fp,
        clients,
        updates: vec![],
        ciphertexts: vec![],
        results: None,
        error: None,
        timings: vec![],
        stage_at: vec![("requested".into(), created)],
    };
    FedAvgE3Repository::new(store.clone(), &e3_id)
        .set(&record)
        .await?;
    RoundIndexRepository::new(store)
        .record_round(&e3_id)
        .await?;
    Ok(e3_id)
}

/// The default dev client list: anvil accounts 6–9 + 0 (the wallets the client offers and
/// `scripts/e2e.mjs` uses; 1–5 are the ciphernodes).
pub fn get_mock_clients() -> Vec<String> {
    [
        "0x976EA74026E726554dB657fA54763abd0C3a0aa9",
        "0x14dC79964da2C08b23698B3D3cc7Ca32193d9955",
        "0x23618e81E3f5cdF7f54C3d65f7FBc0aBf5B21E8f",
        "0xa0Ee7A142d267C1f36714E4a8F75612F20a79720",
        "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
    ]
    .into_iter()
    .map(str::to_string)
    .collect()
}

/// The demo round parameters: `d = 8`, `B = 2.5`, at least 3 clients.
pub fn demo_params() -> RoundParams {
    RoundParams {
        d: ckks_fedavg_program::D,
        norm_bound: 2.5,
        min_clients: 3,
    }
}
