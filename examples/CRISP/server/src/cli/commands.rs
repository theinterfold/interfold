// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use alloy::primitives::{Address, Bytes, U256};
use crisp::config::CONFIG;
use crisp::deployments::{self, LOCALHOST_CHAIN_ID};
use crisp::e3_request::{self, ComputeProviderParams};
use crisp::server::rpc;
use e3_sdk::evm_helpers::contracts::{InterfoldContract, InterfoldRead, InterfoldWrite};
use evm_helpers::CRISPContract;
use eyre::{bail, eyre, Result};
use log::info;
use serde_json::json;

use super::approve;

const ZERO_ADDRESS: &str = "0x0000000000000000000000000000000000000000";

/// `InsufficientCiphernodes(uint256,uint256)` on CiphernodeRegistry.
const INSUFFICIENT_CIPHERNODES_SELECTOR: &str = "0x44ec930f";

fn format_request_e3_revert(err: impl std::fmt::Display) -> eyre::Report {
    let msg = err.to_string();
    if msg.contains(INSUFFICIENT_CIPHERNODES_SELECTOR) {
        let (label, n) = e3_request::committee(CONFIG.e3_committee_size)
            .map_or(("unknown", 0), |committee| {
                (committee.label, committee.members)
            });
        return eyre!(
            "request_e3 reverted: InsufficientCiphernodes — CommitteeSize::{label} (e3_committee_size={size}) \
             requires at least {n} active operators (bondingRegistry.numActiveOperators() is too low). \
             Register ciphernodes before init: run full `pnpm dev:up`, or from examples/CRISP run \
             `pnpm ciphernode:add --ciphernode-address <addr> --network localhost` until at least {n} \
             nodes are active. Default dev config uses Minimum (N=3, cn1–cn3 in interfold.config.yaml).",
            size = CONFIG.e3_committee_size,
        );
    }
    eyre!(
        "request_e3 reverted: {msg}. Common causes: stale E3_PROGRAM_ADDRESS in server/.env \
         (must match deployed CRISPProgram), inputWindow start in the past, or no registered \
         ciphernodes on the chain."
    )
}

/// The address of `contract` from the latest localhost deploy, or the zero address.
pub fn default_hint(contract: &str) -> String {
    deployments::deployed_address(LOCALHOST_CHAIN_ID, contract)
        .ok()
        .flatten()
        .unwrap_or_else(|| ZERO_ADDRESS.to_string())
}

/// `addr` when it names a contract: not blank and not the zero address.
fn explicit(addr: &str) -> Option<&str> {
    let addr = addr.trim();
    (!addr.is_empty() && !addr.eq_ignore_ascii_case(ZERO_ADDRESS)).then_some(addr)
}

/// The token of a token-census round: an explicit address, `CRISP_VOTING_TOKEN`, or the deployed
/// `MockVotingToken`.
fn resolve_voting_token(token_address: &str) -> Result<String> {
    if let Some(addr) = explicit(token_address) {
        return Ok(addr.to_owned());
    }
    if let Some(addr) = CONFIG.crisp_voting_token.as_deref().and_then(explicit) {
        return Ok(addr.to_owned());
    }
    if let Some(addr) = deployments::deployed_address(LOCALHOST_CHAIN_ID, "MockVotingToken")? {
        info!("Using MockVotingToken from deployed_contracts.json: {addr}");
        return Ok(addr);
    }
    bail!(
        "Voting token address is unset. After `pnpm dev:up`, copy `CRISP_VOTING_TOKEN` from deploy \
         output into server/.env, or pass `--token-address <MockVotingToken>`."
    )
}

/// The token of an open-registration round: an explicit address, or the deployed `SelfRegistry`.
///
/// This does not fall through to the config and mock-token defaults of `resolve_voting_token`. A
/// defaulted ERC20Votes token would silently swap "anyone can register" for "whoever held the
/// mock token", which is a different electorate.
fn resolve_registry(token_address: &str) -> Result<String> {
    if let Some(addr) = explicit(token_address) {
        return Ok(addr.to_owned());
    }
    if let Some(addr) = deployments::deployed_address(LOCALHOST_CHAIN_ID, "SelfRegistry")? {
        info!("Using SelfRegistry from deployed_contracts.json: {addr}");
        return Ok(addr);
    }
    bail!(
        "No SelfRegistry found. Deploy the CRISP contracts (which now include it), or pass \
         `--token-address <SelfRegistry or votes token>`."
    )
}

pub async fn check_committee_key_published(e3_id: &str) -> Result<bool> {
    let round_id = U256::from_str_radix(e3_id, 10)?.to_string();
    let response = rpc::HTTP
        .post(format!(
            "{}/rounds/public-key",
            CONFIG.interfold_server_url_for_clients()
        ))
        .json(&json!({ "round_id": round_id, "pk_bytes": [] }))
        .send()
        .await?;

    if response.status() == reqwest::StatusCode::NOT_FOUND {
        return Ok(false);
    }
    response.error_for_status()?;
    Ok(true)
}

pub async fn initialize_crisp_round(
    token_address: &str,
    balance_threshold: &str,
    onchain: bool,
) -> Result<U256> {
    let contract = InterfoldContract::new(
        &CONFIG.http_rpc_url,
        &CONFIG.private_key,
        &CONFIG.interfold_address,
    )
    .await?;
    let e3_program: Address = CONFIG.e3_program_address.parse()?;

    info!("Enabling E3 Program with address: {e3_program}");
    e3_request::ensure_program_enabled(&contract, e3_program).await;

    let token_address = if onchain {
        resolve_registry(token_address)?
    } else {
        resolve_voting_token(token_address)?
    };
    info!(
        "Starting new CRISP round with token address: {token_address} and balance threshold: {balance_threshold}"
    );

    // Census mode 0 = Token: the coordinator derives the electorate from token balances. Census
    // mode 2 = Onchain: eligibility is read from the token per input, and the threshold doubles
    // as the round's `minVotingPower` floor. BY_REQUESTER is not offered: the requester here is
    // this CLI's EOA, which cannot answer `getCensus`.
    let custom_params = e3_request::custom_params(
        token_address.parse()?,
        U256::from_str_radix(balance_threshold, 10)?,
        if onchain { 2 } else { 0 },
    );
    let committee = e3_request::committee(CONFIG.e3_committee_size)?;
    let compute_provider_params =
        Bytes::from(serde_json::to_vec(&ComputeProviderParams::from_config())?);
    let crisp_program = CRISPContract::new(
        &CONFIG.http_rpc_url,
        &CONFIG.private_key,
        &CONFIG.e3_program_address,
    )
    .await?;

    info!("Getting fee quote...");
    let quote_window = e3_request::voting_window(&crisp_program).await?;
    let fee_amount = contract
        .get_e3_quote(
            committee.size,
            quote_window,
            e3_program,
            CONFIG.e3_param_set,
            compute_provider_params.clone(),
        )
        .await?;
    info!("Fee required: {fee_amount} tokens");

    info!("Approving fee token...");
    approve::approve_fee_token(fee_amount).await?;

    // The quote and the approval take time: schedule the window from a fresh timestamp.
    let input_window = e3_request::voting_window(&crisp_program).await?;
    info!("Requesting E3 on contract: {}", CONFIG.interfold_address);
    info!(
        "Requesting E3 with input_window [{}, {}] (buffer {}s)",
        input_window[0], input_window[1], CONFIG.voting_start_buffer_seconds
    );

    let (res, e3_id) = contract
        .request_e3(
            committee.size,
            input_window,
            e3_program,
            CONFIG.e3_param_set,
            compute_provider_params,
            custom_params,
        )
        .await
        .map_err(format_request_e3_revert)?;
    info!("E3 request sent. TxHash: {:?}", res.transaction_hash);
    info!("E3 ID: {e3_id}");

    Ok(e3_id)
}
