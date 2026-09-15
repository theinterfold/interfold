// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::config::CONFIG;
use crate::deployments;
use crate::server::app_data::AppData;
use crate::server::indexer::get_current_timestamp_rpc;
use crate::server::models::{
    canonical_e3_id, CTRequest, ComputeProviderParams, JsonResponse, PKRequest, RoundRequest,
    RoundRequestWithRequester,
};

use super::chain::{admit, is_allowed, parse_address, too_many_requests, upstream};
use super::scan::{coverage_for, scan_logs, Target};
use crate::server::rate_limit::ChainRateLimiter;

use actix_web::{web, HttpRequest, HttpResponse, Responder};
use alloy::primitives::{Address, Bytes, U256};
use alloy::providers::Provider;
use alloy::sol;
use alloy::sol_types::{SolEvent, SolValue};
use e3_sdk::evm_helpers::contracts::{
    CommitteeSize, InterfoldContract, InterfoldRead, InterfoldWrite,
};
use log::{error, info};
use serde::{Deserialize, Serialize};

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

#[derive(Debug, Deserialize)]
pub struct RoundInputsRequest {
    pub round_id: String,
    /// The E3 program that emitted them. Defaults to the configured one; a round created against
    /// a different program names it here.
    #[serde(default)]
    pub program: Option<String>,
    #[serde(default)]
    pub from_block: Option<u64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PublishedInput {
    pub index: String,
    pub block: u64,
    pub transaction_hash: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RoundInputsResponse {
    pub program: String,
    pub round_id: String,
    pub scanned_from: u64,
    pub scanned_to: u64,
    pub indexed_head: u64,
    pub inputs: Vec<PublishedInput>,
}

/// When each encrypted ballot landed in a round, for the activity feed.
///
/// `/state/lite` already reports how MANY inputs a round holds, but not when each arrived or in
/// which transaction, which is what the feed links to — so this is not the same question.
///
/// The event holds only the content hash and Avail coordinates. The feed needs only the index,
/// Ethereum block, and transaction link. Ballots stay indistinguishable: a mask and a vote have
/// the same event shape.
async fn round_inputs(
    http_request: HttpRequest,
    data: web::Json<RoundInputsRequest>,
    store: web::Data<AppData>,
    limiter: web::Data<ChainRateLimiter>,
) -> impl Responder {
    if let Err((caller, cost)) = admit(&http_request, &limiter, INPUTS_READ_COST) {
        return too_many_requests(&caller, cost, "/rounds/inputs");
    }

    let request = data.into_inner();

    let e3_id = match canonical_e3_id(&request.round_id) {
        Ok(id) => id,
        Err(e) => return HttpResponse::BadRequest().body(e.to_string()),
    };
    let Ok(e3_id_u256) = U256::from_str_radix(&e3_id, 10) else {
        return HttpResponse::BadRequest().json(JsonResponse {
            response: format!("Invalid round id: {e3_id}"),
        });
    };

    let requested = request
        .program
        .clone()
        .unwrap_or_else(|| CONFIG.e3_program_address.clone());
    let Some(program) = parse_address(&requested) else {
        return HttpResponse::BadRequest().json(JsonResponse {
            response: format!("Invalid program address: {requested}"),
        });
    };

    if !is_allowed(&program) {
        return HttpResponse::NotFound().json(JsonResponse {
            response: format!("Program {program} is not served by this indexer"),
        });
    }

    let program_key = program.to_string().to_lowercase();
    let indexed = coverage_for(&store, &program_key).await;
    let indexed_head = indexed.map(|(_, head)| head).unwrap_or(0);

    let Some(scan_from) = request.from_block.or(indexed.map(|(from, _)| from)) else {
        return HttpResponse::BadRequest().json(JsonResponse {
            response: format!(
                "from_block is required for {program}: its logs are not indexed here"
            ),
        });
    };

    let provider = match upstream().await {
        Ok(p) => p,
        Err(e) => {
            error!("rounds/inputs: provider unavailable: {e}");
            return HttpResponse::ServiceUnavailable().json(JsonResponse {
                response: "Upstream RPC unavailable".to_string(),
            });
        }
    };

    let block = match provider.get_block_number().await {
        Ok(number) => number,
        Err(e) => {
            error!("rounds/inputs: could not read the head: {e}");
            return HttpResponse::ServiceUnavailable().json(JsonResponse {
                response: "Upstream RPC unavailable".to_string(),
            });
        }
    };

    let target = Target {
        address: program,
        key: &program_key,
        topic0: InputPublished::SIGNATURE_HASH,
        topics: [Some(e3_id_u256.into()), None, None],
        indexed,
    };

    let logs = match scan_logs(&store, provider, &target, scan_from, block).await {
        Ok(found) => found,
        Err(e) => {
            error!("rounds/inputs: scanning InputPublished failed: {e}");
            return HttpResponse::ServiceUnavailable().json(JsonResponse {
                response: "Failed to read the input history".to_string(),
            });
        }
    };

    let mut inputs = Vec::with_capacity(logs.len());
    for log in logs {
        let Ok(decoded) = InputPublished::decode_raw_log(log.topics.iter().copied(), &log.data)
        else {
            continue;
        };
        inputs.push(PublishedInput {
            index: decoded.index.to_string(),
            block: log.block_number,
            transaction_hash: log.transaction_hash,
        });
    }

    // Newest first, as the feed renders them.
    inputs.reverse();

    HttpResponse::Ok().json(RoundInputsResponse {
        program: program.to_string(),
        round_id: e3_id,
        scanned_from: scan_from,
        scanned_to: block,
        indexed_head,
        inputs,
    })
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
}

/// Request a new E3 round
///
/// # Arguments
///
/// * `data` - The request data containing the cron API key and token address
///
/// # Returns
///
/// * A JSON response indicating the success of the operation
async fn request_new_round(data: web::Json<RoundRequest>) -> impl Responder {
    if data.cron_api_key != CONFIG.cron_api_key {
        return HttpResponse::Unauthorized().json(JsonResponse {
            response: "Invalid API key".to_string(),
        });
    }

    if data.token_address.is_empty() {
        return HttpResponse::BadRequest().json(JsonResponse {
            response: "Token address is required".to_string(),
        });
    }

    if data.balance_threshold.is_empty() {
        return HttpResponse::BadRequest().json(JsonResponse {
            response: "Balance threshold is required".to_string(),
        });
    }

    let self_registry = match deployments::self_registry_for_chain_id(CONFIG.chain_id) {
        Ok(address) => address,
        Err(e) => {
            error!("Failed to read CRISP deployment addresses: {e}");
            return HttpResponse::InternalServerError().json(JsonResponse {
                response: "Failed to read CRISP deployment configuration".to_string(),
            });
        }
    };

    let census_mode = match resolve_request_census_mode(
        &data.token_address,
        data.census_mode,
        self_registry.as_deref(),
    ) {
        Ok(mode) => mode,
        Err(response) => {
            return HttpResponse::BadRequest().json(JsonResponse { response });
        }
    };

    let result =
        initialize_crisp_round(&data.token_address, &data.balance_threshold, census_mode).await;

    match result {
        Ok(_) => HttpResponse::Ok().json(JsonResponse {
            response: "New E3 round requested successfully".to_string(),
        }),
        Err(e) => HttpResponse::InternalServerError().json(JsonResponse {
            response: format!("Failed to request new E3 round: {}", e),
        }),
    }
}

fn same_address(left: &str, right: &str) -> bool {
    left.trim().eq_ignore_ascii_case(right.trim())
}

fn is_known_self_registry(token_address: &str, self_registry: Option<&str>) -> bool {
    self_registry.is_some_and(|address| same_address(token_address, address))
}

fn resolve_request_census_mode(
    token_address: &str,
    requested: Option<u64>,
    self_registry: Option<&str>,
) -> Result<u64, String> {
    let self_registry_requested = is_known_self_registry(token_address, self_registry);

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

/// Get the current E3 round
///
/// # Returns
///
/// * A JSON response containing the current round
async fn get_current_round(
    data: web::Json<RoundRequestWithRequester>,
    store: web::Data<AppData>,
) -> impl Responder {
    let incoming = data.into_inner();

    // Get the first requester if any exist
    // .get(0) returns Option<&String>, so we need to handle that
    let result = if let Some(requester) = incoming.requesters.first() {
        // We have a requester, filter by it
        store
            .current_round()
            .get_current_round_for_requester(requester.clone())
            .await
    } else {
        // No requester provided (empty array)
        store.current_round().get_current_round().await
    };

    match result {
        Ok(Some(current_round)) => HttpResponse::Ok().json(current_round),
        Ok(None) => HttpResponse::NotFound().json(JsonResponse {
            response: "No current round found".to_string(),
        }),
        Err(e) => HttpResponse::InternalServerError().json(JsonResponse {
            response: format!("Failed to retrieve current round: {}", e),
        }),
    }
}

/// Get the ciphertext for a given round
///
/// # Arguments
///
/// * `CTRequest` - The request data containing the round ID
///
/// # Returns
///
/// * A JSON response containing the ciphertext
async fn get_ciphertext(data: web::Json<CTRequest>, store: web::Data<AppData>) -> impl Responder {
    let mut incoming = data.into_inner();
    let e3_id = match canonical_e3_id(&incoming.round_id) {
        Ok(e3_id) => e3_id,
        Err(e) => return HttpResponse::BadRequest().body(e.to_string()),
    };
    incoming.round_id = e3_id.clone();

    match store.e3(e3_id).get_ciphertext_output().await {
        Ok(ct_bytes) => {
            incoming.ct_bytes = ct_bytes;
            HttpResponse::Ok().json(incoming)
        }
        Err(e) => HttpResponse::InternalServerError().json(JsonResponse {
            response: format!("Failed to retrieve ciphertext output: {}", e),
        }),
    }
}

/// Get the public key for a given round
///
/// # Arguments
///
/// * `PKRequest` - The request data containing the round ID
///
/// # Returns
///
/// * A JSON response containing the public key
async fn get_public_key(data: web::Json<PKRequest>, store: web::Data<AppData>) -> impl Responder {
    let mut incoming = data.into_inner();
    let e3_id = match canonical_e3_id(&incoming.round_id) {
        Ok(e3_id) => e3_id,
        Err(e) => return HttpResponse::BadRequest().body(e.to_string()),
    };
    incoming.round_id = e3_id.clone();

    match store.e3(e3_id).get_committee_public_key().await {
        Ok(pk_bytes) => {
            incoming.pk_bytes = pk_bytes;
            HttpResponse::Ok().json(incoming)
        }
        Err(e) => HttpResponse::InternalServerError().json(JsonResponse {
            response: format!("Failed to retrieve public key: {}", e),
        }),
    }
}

/// Initialize a new CRISP round
///
/// Creates a new CRISP round by enabling the E3 program, generating the necessary parameters,
/// and requesting E3.
///
/// # Arguments
///
/// * `token_address` - The token contract address
/// * `balance_threshold` - The balance threshold. For an ONCHAIN round this becomes the round's
///   `minVotingPower` floor, in the token's raw units — `1` for a `SelfRegistry`, whose power is
///   1 or 0.
/// * `census_mode` - The `CRISPProgram.CensusMode` discriminant: 0 (TOKEN) or 2 (ONCHAIN)
///
/// # Returns
///
/// * A result indicating the success of the operation
pub async fn initialize_crisp_round(
    token_address: &str,
    balance_threshold: &str,
    census_mode: u64,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    info!(
        "Starting new CRISP round with token address: {} and balance threshold: {}",
        token_address, balance_threshold
    );

    // Continue with the existing E3 initialization
    let contract = InterfoldContract::new(
        &CONFIG.http_rpc_url,
        &CONFIG.private_key,
        &CONFIG.interfold_address,
    )
    .await?;
    let e3_program: Address = CONFIG.e3_program_address.parse()?;

    // Enable E3 Program
    info!("Enabling E3 Program...");
    match contract.is_e3_program_enabled(e3_program).await {
        Ok(enabled) => {
            if !enabled {
                match contract.register_e3_program(e3_program).await {
                    Ok(res) => println!("E3 Program enabled. TxHash: {:?}", res.transaction_hash),
                    Err(e) => println!("Error enabling E3 Program: {:?}", e),
                }
            } else {
                info!("E3 Program already enabled");
            }
        }
        Err(e) => error!("Error checking E3 Program enabled: {:?}", e),
    }

    let token_address: Address = token_address.parse()?;
    let balance_threshold = U256::from_str_radix(balance_threshold, 10)?;

    // Serialize the custom parameters to bytes.
    //
    // This encoded two fields where every consumer reads six, so rounds requested through this
    // route could never be indexed — `abi_decode` failed on them and the round was dropped. Fixed
    // here rather than left, because a route that silently produces unusable rounds is worse than
    // one that does not exist.
    //
    // Two options and constant credits of one are the defaults this route always implied. The
    // census source is the caller's choice between token discovery and the on-chain read; for
    // ONCHAIN the threshold doubles as the contract's `minVotingPower` floor, which the tuple
    // position below already carries.
    let num_options = U256::from(2);
    let credit_mode = U256::from(0); // Constant
    let credits = U256::from(1);
    let census_mode = U256::from(census_mode);
    // Seventh field: the ONCHAIN voting-power divisor. Zero is the "derive from the token's
    // decimals" sentinel — for a token without `decimals()`, such as `SelfRegistry`, that derives
    // to 1. Required regardless — `_initRound` decodes exactly seven fields, so a shorter
    // encoding reverts the request with empty data.
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

    info!("Requesting E3...");
    let committee_size = match CONFIG.e3_committee_size {
        0 => CommitteeSize::Minimum,
        1 => CommitteeSize::Micro,
        2 => CommitteeSize::Small,
        _ => return Err(format!("Invalid committee size: {}", CONFIG.e3_committee_size).into()),
    };

    let current_timestamp = get_current_timestamp_rpc().await?;
    // Buffer so tx can mine before window opens; end = start + duration so voting window equals e3_duration
    let window_start = current_timestamp + 20;
    let input_window: [U256; 2] = [
        U256::from(window_start),
        U256::from(window_start + CONFIG.e3_duration),
    ];
    let param_set = match CONFIG.e3_param_set {
        0 | 1 => CONFIG.e3_param_set,
        invalid => return Err(format!("Invalid param set: {}", invalid).into()),
    };
    let compute_provider_params = ComputeProviderParams {
        name: CONFIG.e3_compute_provider_name.clone(),
        parallel: CONFIG.e3_compute_provider_parallel,
        batch_size: CONFIG.e3_compute_provider_batch_size,
    };

    let compute_provider_params = Bytes::from(bincode::serialize(&compute_provider_params)?);
    let (receipt, e3_id) = contract
        .request_e3(
            committee_size,
            input_window,
            e3_program,
            param_set,
            compute_provider_params,
            custom_params_bytes,
        )
        .await?;
    info!(
        "E3 request sent. TxHash: {:?}, E3 ID: {}",
        receipt.transaction_hash, e3_id
    );

    Ok(())
}
