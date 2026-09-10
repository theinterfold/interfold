// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use dialoguer::{theme::ColorfulTheme, FuzzySelect, Input};
use e3_fhe_params::{BfvParamSet, BfvPreset};
use evm_helpers::CRISPContract;
use log::info;
use reqwest::Client;
use serde::{Deserialize, Serialize};

use super::approve;
use super::CLI_DB;
use alloy::primitives::{Address, Bytes, U256};
use alloy::providers::{Provider, ProviderBuilder};
use alloy::sol_types::SolValue;
use anyhow::anyhow;
use crisp::config::CONFIG;
use crisp::deployments;
use e3_fhe_params::build_bfv_params_from_set_arc;
use e3_sdk::evm_helpers::contracts::{
    CommitteeSize, InterfoldContract, InterfoldRead, InterfoldWrite,
};
use fhe::bfv::{BfvParameters, Ciphertext, Encoding, Plaintext, PublicKey, SecretKey};
use fhe_traits::{
    DeserializeParametrized, FheDecoder, FheDecrypter, FheEncoder, FheEncrypter,
    Serialize as FheSerialize,
};
use rand::rng;
use std::sync::Arc;

// Legacy interactive CLI flows; kept for revival alongside the HTTP server path.
#[allow(dead_code)]
#[derive(Debug, Deserialize, Serialize)]
struct FHEParams {
    params: Vec<u8>,
    pk: Vec<u8>,
    sk: Vec<i64>,
}

#[derive(Debug, Deserialize, Serialize)]
struct ComputeProviderParams {
    name: String,
    parallel: bool,
    batch_size: u32,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize, Serialize)]
struct PKRequest {
    round_id: String,
    pk_bytes: Vec<u8>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize, Serialize)]
struct CTRequest {
    round_id: String,
    ct_bytes: Vec<u8>,
}

/// Seconds between `block.timestamp` and `inputWindow[0]` (covers approve + enable txs on Anvil).
const INPUT_WINDOW_START_BUFFER_SECS: u64 = 60;

const ZERO_ADDRESS: &str = "0x0000000000000000000000000000000000000000";

/// `InsufficientCiphernodes(uint256,uint256)` on CiphernodeRegistry.
const INSUFFICIENT_CIPHERNODES_SELECTOR: &str = "0x44ec930f";

/// `(CommitteeSize label, total committee N)` for `CONFIG.e3_committee_size` (0=Minimum, 1=Micro, 2=Small).
fn committee_size_n_required(e3_committee_size: u8) -> (&'static str, u32) {
    match e3_committee_size {
        0 => ("Minimum", 3),
        1 => ("Micro", 9),
        2 => ("Small", 19),
        _ => ("unknown", 0),
    }
}

fn format_request_e3_revert(err: impl std::fmt::Display) -> anyhow::Error {
    let msg = err.to_string();
    if msg.contains(INSUFFICIENT_CIPHERNODES_SELECTOR) {
        let (label, n) = committee_size_n_required(CONFIG.e3_committee_size);
        return anyhow!(
            "request_e3 reverted: InsufficientCiphernodes — CommitteeSize::{label} (e3_committee_size={size}) \
             requires at least {n} active operators (bondingRegistry.numActiveOperators() is too low). \
             Register ciphernodes before init: run full `pnpm dev:up`, or from examples/CRISP run \
             `pnpm ciphernode:add --ciphernode-address <addr> --network localhost` until at least {n} \
             nodes are active. Default dev config uses Minimum (N=3, cn1–cn3 in interfold.config.yaml).",
            label = label,
            size = CONFIG.e3_committee_size,
            n = n,
        );
    }
    anyhow!(
        "request_e3 reverted: {msg}. Common causes: stale E3_PROGRAM_ADDRESS in server/.env \
         (must match deployed CRISPProgram), inputWindow start in the past, or no registered \
         ciphernodes on the chain."
    )
}

pub fn default_voting_token_hint() -> String {
    deployments::localhost_mock_voting_token()
        .ok()
        .flatten()
        .unwrap_or_else(|| ZERO_ADDRESS.to_string())
}

pub fn default_registry_hint() -> String {
    deployments::localhost_self_registry()
        .ok()
        .flatten()
        .unwrap_or_else(|| ZERO_ADDRESS.to_string())
}

fn resolve_voting_token(
    token_address: &str,
) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    let trimmed = token_address.trim();
    if !trimmed.is_empty() && !trimmed.eq_ignore_ascii_case(ZERO_ADDRESS) {
        return Ok(trimmed.to_string());
    }
    if let Some(ref configured) = CONFIG.crisp_voting_token {
        let configured = configured.trim();
        if !configured.is_empty() && !configured.eq_ignore_ascii_case(ZERO_ADDRESS) {
            return Ok(configured.to_string());
        }
    }
    if let Some(addr) = deployments::localhost_mock_voting_token()? {
        info!("Using MockVotingToken from deployed_contracts.json: {addr}");
        return Ok(addr);
    }
    Err(anyhow!(
        "Voting token address is unset. After `pnpm dev:up`, copy `CRISP_VOTING_TOKEN` from deploy \
         output into server/.env, or pass `--token-address <MockVotingToken>`."
    )
    .into())
}

/// The token of an open-registration round: an explicit address, or the deployed `SelfRegistry`.
///
/// Deliberately not falling through to `resolve_voting_token`'s config and mock-token defaults.
/// An ONCHAIN round against an ERC20Votes token is a valid thing to request explicitly, but a
/// *defaulted* one would silently swap "anyone can register" for "whoever held the mock token",
/// which is a different electorate with nothing to show for it.
fn resolve_registry(
    token_address: &str,
) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    let trimmed = token_address.trim();
    if !trimmed.is_empty() && !trimmed.eq_ignore_ascii_case(ZERO_ADDRESS) {
        return Ok(trimmed.to_string());
    }
    if let Some(addr) = deployments::localhost_self_registry()? {
        info!("Using SelfRegistry from deployed_contracts.json: {addr}");
        return Ok(addr);
    }
    Err(anyhow!(
        "No SelfRegistry found. Deploy the CRISP contracts (which now include it), or pass \
         `--token-address <SelfRegistry or votes token>`."
    )
    .into())
}

#[allow(dead_code)]
async fn ensure_e3_program_deployed(
    e3_program: Address,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if let Some(deployed) = deployments::localhost_crisp_program()? {
        let deployed_addr: Address = deployed.parse()?;
        if deployed_addr != e3_program {
            return Err(anyhow!(
                "E3_PROGRAM_ADDRESS in server/.env ({e3_program}) does not match deployed \
                 CRISPProgram ({deployed_addr}). Re-run `pnpm dev:up` and update server/.env from \
                 deploy output (PRINT_ENV_VARS=true)."
            )
            .into());
        }
    }

    let provider = ProviderBuilder::new().connect(&CONFIG.http_rpc_url).await?;
    let code = provider.get_code_at(e3_program).await?;
    if code.is_empty() {
        return Err(anyhow!(
            "No contract bytecode at E3_PROGRAM_ADDRESS {e3_program}. Stale server/.env after \
             redeploy is the usual cause — sync from packages/crisp-contracts/deployed_contracts.json."
        )
        .into());
    }
    Ok(())
}

pub async fn get_current_timestamp() -> Result<u64, Box<dyn std::error::Error + Send + Sync>> {
    let provider = ProviderBuilder::new().connect(&CONFIG.http_rpc_url).await?;
    let block = provider
        .get_block_by_number(alloy::eips::BlockNumberOrTag::Latest)
        .await
        .unwrap()
        .ok_or_else(|| anyhow::anyhow!("Latest block not found"))?;

    Ok(block.header.timestamp)
}

pub async fn check_committee_key_published(
    e3_id: &str,
) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
    let e3_id = U256::from_str_radix(e3_id, 10)?.to_string();
    let response = Client::new()
        .post(format!(
            "{}/rounds/public-key",
            CONFIG.interfold_server_url_for_clients()
        ))
        .json(&PKRequest {
            round_id: e3_id,
            pk_bytes: Vec::new(),
        })
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
) -> Result<U256, Box<dyn std::error::Error + Send + Sync>> {
    let contract = InterfoldContract::new(
        &CONFIG.http_rpc_url,
        &CONFIG.private_key,
        &CONFIG.interfold_address,
    )
    .await?;
    let e3_program: Address = CONFIG.e3_program_address.parse()?;

    info!("Enabling E3 Program with address: {}", e3_program);
    match contract.is_e3_program_enabled(e3_program).await {
        Ok(enabled) => {
            info!("Debug - E3 Program enabled status: {}", enabled);
            if !enabled {
                info!("E3 Program not enabled, attempting to enable...");
                match contract.register_e3_program(e3_program).await {
                    Ok(res) => info!("E3 Program enabled. TxHash: {:?}", res.transaction_hash),
                    Err(e) => info!("Error enabling E3 Program: {:?}", e),
                }
            } else {
                info!("E3 Program already enabled");
            }
        }
        Err(e) => info!("Error checking E3 Program enabled: {:?}", e),
    }

    let token_address_str = if onchain {
        resolve_registry(token_address)?
    } else {
        resolve_voting_token(token_address)?
    };

    info!(
        "Starting new CRISP round with token address: {} and balance threshold: {}",
        token_address_str, balance_threshold
    );

    let token_address: Address = token_address_str.parse()?;
    let balance_threshold = U256::from_str_radix(balance_threshold, 10)?;
    // We default to two options for the main CRISP app
    let num_options = U256::from(2);
    // The credit mode is constant for the CRISP app (everyone gets the same credits)
    let credit_mode = U256::from(0);
    // everyone gets 1 credit
    let credits = U256::from(1);

    // Serialize the custom parameters to bytes.
    // Census mode 0 = Token: the coordinator derives the electorate from token balances, as this
    // CLI always has. Census mode 2 = Onchain: eligibility is read from the token per input, and
    // the threshold above doubles as the round's `minVotingPower` floor — `1` for a
    // `SelfRegistry`, whose power is 1 or 0. BY_REQUESTER is not offered: the requester here is
    // this CLI's EOA, which cannot answer `getCensus`.
    let census_mode = U256::from(if onchain { 2u64 } else { 0u64 });
    // Seventh field: the ONCHAIN voting-power divisor. Zero here for two reasons — a TOKEN round
    // never reads it, and zero is also the "derive it from the token's decimals" sentinel. It is
    // not optional: `_initRound` decodes exactly seven fields, so a six-field encoding reverts the
    // request with empty data rather than defaulting to anything.
    let voting_power_divisor = U256::from(0);
    let custom_params_bytes = Bytes::from(
        (
            token_address,
            balance_threshold,
            num_options,
            credit_mode,
            credits,
            census_mode,
            voting_power_divisor,
        )
            .abi_encode(),
    );

    let committee_size = match CONFIG.e3_committee_size {
        0 => CommitteeSize::Minimum,
        1 => CommitteeSize::Micro,
        2 => CommitteeSize::Small,
        invalid => {
            return Err(anyhow::anyhow!("Invalid committee size: {}", invalid).into());
        }
    };
    let param_set = match CONFIG.e3_param_set {
        0 | 1 => CONFIG.e3_param_set,
        invalid => {
            return Err(anyhow::anyhow!("Invalid param set: {}", invalid).into());
        }
    };
    let compute_provider_params = ComputeProviderParams {
        name: CONFIG.e3_compute_provider_name.to_string(),
        parallel: CONFIG.e3_compute_provider_parallel,
        batch_size: CONFIG.e3_compute_provider_batch_size,
    };
    let compute_provider_params_bytes = Bytes::from(serde_json::to_vec(&compute_provider_params)?);

    info!("Getting fee quote...");

    let mut current_timestamp = get_current_timestamp().await?;
    info!(
        "Debug Before Fee Quote - current timestamp: {:?}",
        current_timestamp
    );
    // Buffer so tx can mine before window opens; end = start + duration so voting window equals e3_duration
    let window_start = current_timestamp + INPUT_WINDOW_START_BUFFER_SECS;
    let input_window: [U256; 2] = [
        U256::from(window_start),
        U256::from(window_start + CONFIG.e3_duration),
    ];

    let fee_amount = contract
        .get_e3_quote(
            committee_size,
            input_window,
            e3_program,
            param_set,
            compute_provider_params_bytes.clone(),
        )
        .await?;
    info!("Fee required: {} tokens", fee_amount);

    info!("Approving fee token...");
    approve::approve_token(
        &CONFIG.http_rpc_url,
        &CONFIG.private_key,
        &CONFIG.fee_token_address,
        &CONFIG.interfold_address,
        fee_amount,
    )
    .await?;

    current_timestamp = get_current_timestamp().await?;

    info!("Requesting E3 on contract: {}", CONFIG.interfold_address);

    info!("Debug - committee_size: {:?}", committee_size);
    info!("Debug - input_window: {:?}", input_window);
    info!("Debug - current timestamp: {:?}", current_timestamp);
    info!("Debug - e3_program: {}", e3_program);

    info!(
        "Debug - Checking ciphernode registry at: {}",
        CONFIG.ciphernode_registry_address
    );

    // Recompute the current timestamp to ensure it's as up-to-date as possible before sending the transaction,
    // since there are multiple steps (fee quote, token approval) that could take time.
    let current_timestamp = get_current_timestamp().await?;
    // Buffer so tx can mine before window opens; end = start + duration so voting window equals e3_duration
    let window_start = current_timestamp + INPUT_WINDOW_START_BUFFER_SECS;
    let input_window: [U256; 2] = [
        U256::from(window_start),
        U256::from(window_start + CONFIG.e3_duration),
    ];

    info!(
        "Requesting E3 with input_window [{}, {}] (buffer {}s)",
        window_start,
        window_start + CONFIG.e3_duration,
        INPUT_WINDOW_START_BUFFER_SECS
    );

    let (res, e3_id) = contract
        .request_e3(
            committee_size,
            input_window,
            e3_program,
            param_set,
            compute_provider_params_bytes,
            custom_params_bytes,
        )
        .await
        .map_err(format_request_e3_revert)?;
    info!("E3 request sent. TxHash: {:?}", res.transaction_hash);
    info!("E3 ID: {}", e3_id);

    Ok(e3_id)
}

#[allow(dead_code)]
pub async fn participate_in_existing_round(
    client: &Client,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let input_crisp_id: String = Input::with_theme(&ColorfulTheme::default())
        .with_prompt("Enter CRISP round ID.")
        .interact_text()?;

    let url = format!(
        "{}/rounds/public-key",
        CONFIG.interfold_server_url_for_clients()
    );
    let resp = client
        .post(&url)
        .json(&PKRequest {
            round_id: input_crisp_id.clone(),
            pk_bytes: vec![0],
        })
        .send()
        .await?;

    let pk_res: PKRequest = resp.json().await?;
    let params = generate_bfv_parameters();
    let pk_deserialized = PublicKey::from_bytes(&pk_res.pk_bytes, &params)?;

    let vote_choice = get_user_vote()?;
    if let Some(vote) = vote_choice {
        let ct = encrypt_vote(vote, &pk_deserialized, &params)?;
        let contract = CRISPContract::new(
            &CONFIG.http_rpc_url,
            &CONFIG.private_key,
            &CONFIG.interfold_address,
        )
        .await?;
        let res = contract
            .publish_input(
                U256::from_str_radix(&input_crisp_id, 10)?,
                Bytes::from(ct.to_bytes()),
            )
            .await?;
        info!("Vote broadcast. TxHash: {:?}", res.transaction_hash);
    }

    Ok(())
}

#[allow(dead_code)]
pub async fn decrypt_and_publish_result(
    client: &Client,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let input_crisp_id: String = Input::with_theme(&ColorfulTheme::default())
        .with_prompt("Enter CRISP round ID.")
        .interact_text()?;

    let url = format!(
        "{}/rounds/ciphertext",
        CONFIG.interfold_server_url_for_clients()
    );
    let resp = client
        .post(&url)
        .json(&CTRequest {
            round_id: input_crisp_id.clone(),
            ct_bytes: vec![0],
        })
        .send()
        .await?;

    let ct_res: CTRequest = resp.json().await?;

    let db = CLI_DB.read().await;
    let params_bytes = db
        .get(format!("_e3:{}", input_crisp_id))?
        .ok_or("Key not found")?;
    let e3_params: FHEParams = serde_json::from_slice(&params_bytes)?;
    let params = generate_bfv_parameters();
    let sk_deserialized = SecretKey::new(e3_params.sk, &params);

    let ct = Ciphertext::from_bytes(&ct_res.ct_bytes, &params)?;
    let pt = sk_deserialized.try_decrypt(&ct)?;
    let votes = Vec::<u64>::try_decode(&pt, Encoding::poly())?[0];
    info!("Vote count: {:?}", votes);

    let proof = Bytes::from(vec![0]);

    let contract = InterfoldContract::new(
        &CONFIG.http_rpc_url,
        &CONFIG.private_key,
        &CONFIG.interfold_address,
    )
    .await?;
    let res = contract
        .publish_plaintext_output(
            U256::from_str_radix(&input_crisp_id, 10)?,
            Bytes::from(votes.to_be_bytes()),
            proof,
        )
        .await?;
    info!("Vote broadcast. TxHash: {:?}", res.transaction_hash);

    Ok(())
}

#[allow(dead_code)]
fn generate_bfv_parameters() -> Arc<BfvParameters> {
    let preset = BfvPreset::from_on_chain_param_set(CONFIG.e3_param_set)
        .expect("E3_PARAM_SET must be 0 or 1");
    build_bfv_params_from_set_arc(BfvParamSet::from(preset))
}

#[allow(dead_code)]
fn generate_keys(params: &Arc<BfvParameters>) -> (SecretKey, PublicKey) {
    let mut rng = rng();
    let sk = SecretKey::random(params, &mut rng);
    let pk = PublicKey::new(&sk, &mut rng);
    (sk, pk)
}

#[allow(dead_code)]
fn get_user_vote() -> Result<Option<u64>, Box<dyn std::error::Error + Send + Sync>> {
    let selections = &["Abstain.", "Vote yes.", "Vote no."];
    let selection = FuzzySelect::with_theme(&ColorfulTheme::default())
        .with_prompt("Please select your voting option.")
        .default(0)
        .items(&selections[..])
        .interact()?;

    match selection {
        0 => Ok(None),
        1 => Ok(Some(1)),
        2 => Ok(Some(0)),
        _ => Err("Invalid selection".into()),
    }
}

#[allow(dead_code)]
fn encrypt_vote(
    vote: u64,
    public_key: &PublicKey,
    params: &std::sync::Arc<BfvParameters>,
) -> Result<Ciphertext, Box<dyn std::error::Error + Send + Sync>> {
    let pt = Plaintext::try_encode(&[vote], Encoding::poly(), params)?;
    Ok(public_key.try_encrypt(&pt, &mut rng())?)
}
