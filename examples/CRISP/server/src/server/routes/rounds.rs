// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use std::fmt::Display;
use std::future::Future;

use actix_web::http::StatusCode;
use actix_web::{web, HttpRequest, HttpResponse};
use alloy::primitives::{Address, Bytes, U256};
use alloy::sol;
use alloy::sol_types::SolEvent;
use e3_sdk::evm_helpers::contracts::{InterfoldContract, InterfoldWrite};
use evm_helpers::CRISPContract;
use log::{error, info};
use serde::{Deserialize, Serialize};

use super::scan::{scan_logs, served_address, unavailable, ScanCtx, Target, NOT_INDEXED};
use super::{chain::charge, json_message};
use crate::config::CONFIG;
use crate::deployments;
use crate::e3_request::{self, ComputeProviderParams};
use crate::server::app_data::AppData;
use crate::server::models::{
    canonical_e3_id, e3_id_to_u256, CTRequest, PKRequest, RoundRequest, RoundRequestWithRequester,
};
use crate::server::rate_limit::ChainRateLimiter;

pub fn setup_routes(config: &mut web::ServiceConfig) {
    config.service(
        web::scope("/rounds")
            .route("/current", web::post().to(get_current_round))
            .route("/public-key", web::post().to(get_public_key))
            .route("/ciphertext", web::post().to(get_ciphertext))
            .route("/request", web::post().to(request_new_round))
            .route("/inputs", web::post().to(round_inputs)),
    );
}

sol! {
    /// The CRISP program's content-addressed input event.
    event InputPublished(
        uint256 indexed e3Id,
        address indexed slotAddress,
        bytes32 encryptedVoteCommitment,
        bytes32 encryptedVoteHash,
        uint32 availabilityBlock,
        uint128 availabilityLeafIndex,
        uint256 index,
        uint40 parentIndexPlusOne
    );
}

/// Cost charged to the caller's read window.
const INPUTS_READ_COST: usize = 4;
const CENSUS_MODE_TOKEN: u64 = 0;
const CENSUS_MODE_ONCHAIN: u64 = 2;

/// Serializes `/rounds/request`: two concurrent requests would sign with the same nonce.
static REQUEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

#[derive(Debug, Deserialize)]
struct RoundInputsRequest {
    round_id: String,
    /// The E3 program that emitted them. Defaults to the configured one; a round created against
    /// a different program names it here.
    #[serde(default)]
    program: Option<String>,
    #[serde(default)]
    from_block: Option<u64>,
}

#[derive(Debug, Clone, Serialize)]
struct PublishedInput {
    index: String,
    block: u64,
    transaction_hash: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
struct RoundInputsResponse {
    program: String,
    round_id: String,
    scanned_from: u64,
    scanned_to: u64,
    indexed_head: u64,
    inputs: Vec<PublishedInput>,
}

/// When each encrypted ballot landed in a round, for the activity feed.
///
/// `/state/lite` reports how many inputs a round holds, not when each arrived or in which
/// transaction. The event holds only the content hash and Avail coordinates, and a mask and a
/// vote have the same shape, so ballots stay indistinguishable.
async fn round_inputs(
    http_request: HttpRequest,
    data: web::Json<RoundInputsRequest>,
    store: web::Data<AppData>,
    limiter: web::Data<ChainRateLimiter>,
) -> HttpResponse {
    match read_round_inputs(&http_request, data.into_inner(), &store, &limiter).await {
        Ok(body) => HttpResponse::Ok().json(body),
        Err(response) => response,
    }
}

async fn read_round_inputs(
    http_request: &HttpRequest,
    request: RoundInputsRequest,
    store: &web::Data<AppData>,
    limiter: &ChainRateLimiter,
) -> Result<RoundInputsResponse, HttpResponse> {
    charge(http_request, limiter, INPUTS_READ_COST, "/rounds/inputs")?;

    let e3_id = e3_id_to_u256(&request.round_id)
        .map_err(|e| HttpResponse::BadRequest().body(e.to_string()))?;
    let requested = request
        .program
        .as_deref()
        .unwrap_or(&CONFIG.e3_program_address);
    let program = served_address(requested, "program", "Program")?;
    let ctx = ScanCtx::open(
        store,
        "/rounds/inputs",
        program,
        program,
        request.from_block,
        NOT_INDEXED,
    )
    .await?;

    let target = Target {
        topics: [Some(e3_id.into()), None, None],
        ..ctx.target(InputPublished::SIGNATURE_HASH)
    };
    let logs = scan_logs(store, ctx.provider, &target, ctx.scan_from, ctx.block)
        .await
        .map_err(|e| {
            unavailable(
                "rounds/inputs: scanning InputPublished failed",
                e,
                "Failed to read the input history",
            )
        })?;

    // Newest first, as the feed renders them.
    let inputs = logs
        .into_iter()
        .rev()
        .filter_map(|log| {
            let decoded =
                InputPublished::decode_raw_log(log.topics.iter().copied(), &log.data).ok()?;
            Some(PublishedInput {
                index: decoded.index.to_string(),
                block: log.block_number,
                transaction_hash: log.transaction_hash,
            })
        })
        .collect();

    Ok(RoundInputsResponse {
        program: program.to_string(),
        round_id: e3_id.to_string(),
        scanned_from: ctx.scan_from,
        scanned_to: ctx.block,
        indexed_head: ctx.indexed_head,
        inputs,
    })
}

/// Compare in time that depends on the lengths only, so the response time does not reveal how
/// much of a guess matches.
fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    let mut difference = left.len() ^ right.len();
    for i in 0..left.len().max(right.len()) {
        let l = left.get(i).copied().unwrap_or(0);
        let r = right.get(i).copied().unwrap_or(0);
        difference |= usize::from(std::hint::black_box(l ^ r));
    }
    difference == 0
}

fn valid_cron_api_key(configured: Option<&str>, provided: &str) -> bool {
    matches!(
        configured,
        Some(expected) if !expected.trim().is_empty()
            && constant_time_eq(expected.as_bytes(), provided.as_bytes())
    )
}

async fn request_new_round(data: web::Json<RoundRequest>) -> HttpResponse {
    if !valid_cron_api_key(CONFIG.cron_api_key.as_deref(), &data.cron_api_key) {
        return json_message(StatusCode::UNAUTHORIZED, "Invalid API key");
    }
    if data.token_address.is_empty() {
        return json_message(StatusCode::BAD_REQUEST, "Token address is required");
    }
    if data.balance_threshold.is_empty() {
        return json_message(StatusCode::BAD_REQUEST, "Balance threshold is required");
    }

    let self_registry = match deployments::deployed_address(CONFIG.chain_id, "SelfRegistry") {
        Ok(address) => address,
        Err(e) => {
            error!("Failed to read CRISP deployment addresses: {e}");
            return json_message(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to read CRISP deployment configuration",
            );
        }
    };
    let census_mode = match resolve_request_census_mode(
        &data.token_address,
        data.census_mode,
        self_registry.as_deref(),
    ) {
        Ok(mode) => mode,
        Err(message) => return json_message(StatusCode::BAD_REQUEST, message),
    };

    let _one_request_at_a_time = REQUEST_LOCK.lock().await;
    match initialize_crisp_round(&data.token_address, &data.balance_threshold, census_mode).await {
        Ok(()) => json_message(StatusCode::OK, "New E3 round requested successfully"),
        Err(e) => {
            error!("Failed to request new E3 round: {e}");
            json_message(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to request new E3 round: {e}"),
            )
        }
    }
}

fn resolve_request_census_mode(
    token_address: &str,
    requested: Option<u64>,
    self_registry: Option<&str>,
) -> Result<u64, String> {
    let self_registry_requested = self_registry
        .is_some_and(|address| address.trim().eq_ignore_ascii_case(token_address.trim()));

    match requested {
        Some(CENSUS_MODE_TOKEN) if self_registry_requested => Err(
            "SelfRegistry rounds must use census_mode 2 (ONCHAIN). census_mode 0 would try \
             token-holder discovery and make the round invisible to clients."
                .to_string(),
        ),
        Some(mode @ (CENSUS_MODE_TOKEN | CENSUS_MODE_ONCHAIN)) => Ok(mode),
        Some(mode) => Err(format!(
            "Unsupported census mode {mode}: this route can request 0 (TOKEN) or 2 (ONCHAIN)"
        )),
        None if self_registry_requested => Ok(CENSUS_MODE_ONCHAIN),
        None => Ok(CENSUS_MODE_TOKEN),
    }
}

async fn get_current_round(
    data: web::Json<RoundRequestWithRequester>,
    store: web::Data<AppData>,
) -> HttpResponse {
    let result = match data.into_inner().requesters.into_iter().next() {
        Some(requester) => {
            store
                .current_round()
                .get_current_round_for_requester(requester)
                .await
        }
        None => store.current_round().get_current_round().await,
    };

    match result {
        Ok(Some(current_round)) => HttpResponse::Ok().json(current_round),
        Ok(None) => json_message(StatusCode::NOT_FOUND, "No current round found"),
        Err(e) => json_message(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to retrieve current round: {e}"),
        ),
    }
}

/// Read `what` of a round through `read`. The round id is canonicalised: a malformed id is a 400
/// with the parse error as a plain-text body.
async fn read_round_bytes<E: Display, Fut: Future<Output = Result<Vec<u8>, E>>>(
    round_id: &str,
    what: &str,
    read: impl FnOnce(String) -> Fut,
) -> Result<(String, Vec<u8>), HttpResponse> {
    let e3_id =
        canonical_e3_id(round_id).map_err(|e| HttpResponse::BadRequest().body(e.to_string()))?;
    match read(e3_id.clone()).await {
        Ok(bytes) => Ok((e3_id, bytes)),
        Err(e) => Err(json_message(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to retrieve {what}: {e}"),
        )),
    }
}

async fn get_ciphertext(data: web::Json<CTRequest>, store: web::Data<AppData>) -> HttpResponse {
    let mut request = data.into_inner();
    let read = |id: String| {
        let store = store.clone();
        async move { store.e3(id).get_ciphertext_output().await }
    };
    match read_round_bytes(&request.round_id, "ciphertext output", read).await {
        Ok((round_id, ct_bytes)) => {
            request.round_id = round_id;
            request.ct_bytes = ct_bytes;
            HttpResponse::Ok().json(request)
        }
        Err(response) => response,
    }
}

async fn get_public_key(data: web::Json<PKRequest>, store: web::Data<AppData>) -> HttpResponse {
    let mut request = data.into_inner();
    let read = |id: String| {
        let store = store.clone();
        async move { store.e3(id).get_committee_public_key().await }
    };
    match read_round_bytes(&request.round_id, "public key", read).await {
        Ok((round_id, pk_bytes)) => {
            request.round_id = round_id;
            request.pk_bytes = pk_bytes;
            HttpResponse::Ok().json(request)
        }
        Err(response) => response,
    }
}

/// Request a new CRISP round on-chain.
///
/// For an ONCHAIN round `balance_threshold` becomes the round's `minVotingPower` floor in the
/// token's raw units: `1` for a `SelfRegistry`, whose power is 1 or 0. `census_mode` is the
/// `CRISPProgram.CensusMode` discriminant, 0 (TOKEN) or 2 (ONCHAIN).
async fn initialize_crisp_round(
    token_address: &str,
    balance_threshold: &str,
    census_mode: u64,
) -> eyre::Result<()> {
    info!(
        "Starting new CRISP round with token address: {token_address} and balance threshold: {balance_threshold}"
    );

    let contract = InterfoldContract::new(
        &CONFIG.http_rpc_url,
        &CONFIG.private_key,
        &CONFIG.interfold_address,
    )
    .await?;
    let e3_program: Address = CONFIG.e3_program_address.parse()?;
    e3_request::ensure_program_enabled(&contract, e3_program).await;

    let custom_params = e3_request::custom_params(
        token_address.parse()?,
        U256::from_str_radix(balance_threshold, 10)?,
        census_mode,
    );
    let committee = e3_request::committee(CONFIG.e3_committee_size)?;

    let crisp_program = CRISPContract::new(
        &CONFIG.http_rpc_url,
        &CONFIG.private_key,
        &CONFIG.e3_program_address,
    )
    .await?;
    let input_window = e3_request::voting_window(&crisp_program).await?;
    let compute_provider_params =
        Bytes::from(bincode::serialize(&ComputeProviderParams::from_config())?);

    let (receipt, e3_id) = contract
        .request_e3(
            committee.size,
            input_window,
            e3_program,
            CONFIG.e3_param_set,
            compute_provider_params,
            custom_params,
        )
        .await?;
    info!(
        "E3 request sent. TxHash: {:?}, E3 ID: {}",
        receipt.transaction_hash, e3_id
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_input_published_signature_is_the_program_event_not_interfold_s() {
        // Cross-checked against viem's `toEventSelector`. Interfold has a different event with the
        // same name; using that one here would return an empty feed.
        assert_eq!(
            format!("{:#x}", InputPublished::SIGNATURE_HASH),
            "0xbeebd5a7c46bb399523934784209bdeb6e68a004964282d7555fcc286169377c"
        );
    }

    #[test]
    fn self_registry_defaults_to_onchain_census() {
        let mode = resolve_request_census_mode(
            "0x00a2Aaf566593b28EDEb614b81B2Ada01327db7e",
            None,
            Some("0x00a2aaf566593b28edeb614b81b2ada01327db7e"),
        )
        .unwrap();

        assert_eq!(mode, CENSUS_MODE_ONCHAIN);
    }

    #[test]
    fn normal_token_keeps_token_census_default() {
        let mode = resolve_request_census_mode(
            "0x1111111111111111111111111111111111111111",
            None,
            Some("0x00a2aaf566593b28edeb614b81b2ada01327db7e"),
        )
        .unwrap();

        assert_eq!(mode, CENSUS_MODE_TOKEN);
    }

    #[test]
    fn self_registry_rejects_token_census() {
        let err = resolve_request_census_mode(
            "0x00a2Aaf566593b28EDEb614b81B2Ada01327db7e",
            Some(CENSUS_MODE_TOKEN),
            Some("0x00a2aaf566593b28edeb614b81b2ada01327db7e"),
        )
        .unwrap_err();

        assert!(err.contains("SelfRegistry rounds must use census_mode 2"));
    }

    #[test]
    fn unsupported_census_mode_is_rejected() {
        let err = resolve_request_census_mode(
            "0x1111111111111111111111111111111111111111",
            Some(1),
            Some("0x00a2aaf566593b28edeb614b81b2ada01327db7e"),
        )
        .unwrap_err();

        assert!(err.contains("Unsupported census mode 1"));
    }

    #[test]
    fn cron_authentication_fails_closed() {
        assert!(!valid_cron_api_key(None, "provided"));
        assert!(!valid_cron_api_key(Some(""), ""));
        assert!(!valid_cron_api_key(Some("configured"), "wrong"));
        assert!(!valid_cron_api_key(Some("configured"), "config"));
        assert!(!valid_cron_api_key(
            Some("configured"),
            "configured-and-more"
        ));
        assert!(valid_cron_api_key(Some("configured"), "configured"));
    }
}
