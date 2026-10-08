// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use super::{
    chain::{admit, identify},
    state::job_response,
};
use crate::server::{
    app_data::AppData,
    data_availability::{input_rejection_message, AvailabilityService},
    models::{
        canonical_e3_id, e3_id_to_u256, InputSelectionRequest, VoteRequest, VoteResponse,
        VoteResponseStatus, VoteStatusRequest, VoteStatusResponse,
    },
    rate_limit::{ChainRateLimiter, RateLimiter},
    repo::parse_slot_address,
    CONFIG,
};
use actix_web::{web, HttpRequest, HttpResponse, Responder};
use alloy::primitives::B256;
use log::{error, info, warn};
use std::str::FromStr;

/// Cost of one selection read in the caller's read window. The server answers from its own index
/// and makes no upstream call.
const SELECTION_READ_COST: usize = 1;

pub fn setup_routes(config: &mut web::ServiceConfig) {
    config.route(
        "/availability/objects/{content_hash}",
        web::get().to(get_available_object),
    );
    config.service(
        web::scope("/voting")
            .service(
                web::resource("/broadcast")
                    .app_data(crate::server::payloads::encrypted_json())
                    .route(web::post().to(broadcast_encrypted_vote)),
            )
            .route(
                "/availability/{job_id}",
                web::get().to(get_availability_status),
            )
            .route("/status", web::post().to(get_vote_status))
            .route("/selection", web::post().to(get_input_selection)),
    );
}

/// A `FailedBroadcast` body that carries only `message`.
fn failed(message: impl Into<String>) -> VoteResponse {
    VoteResponse {
        status: VoteResponseStatus::FailedBroadcast,
        tx_hash: None,
        job_id: None,
        encoded_proof: None,
        message: Some(message.into()),
    }
}

/// The answer to an availability-service error: 400 when the service conclusively rejected the
/// ballot, 503 for any other failure.
fn availability_error(e3_key: &str, error: &anyhow::Error) -> HttpResponse {
    if let Some(message) = input_rejection_message(error) {
        warn!("[e3_id={e3_key}] Vote rejected: {error}");
        return HttpResponse::BadRequest().json(failed(message));
    }
    error!("[e3_id={e3_key}] Availability service failed: {error}");
    HttpResponse::ServiceUnavailable().json(failed(
        "The availability service is temporarily unavailable",
    ))
}

async fn get_available_object(
    content_hash: web::Path<String>,
    availability: web::Data<AvailabilityService>,
) -> impl Responder {
    let normalized = content_hash.strip_prefix("0x").unwrap_or(&content_hash);
    if normalized.len() != 64 || !normalized.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return HttpResponse::BadRequest().body("Invalid content hash");
    }
    match availability.object(&content_hash) {
        Ok(Some(bytes)) => HttpResponse::Ok()
            .content_type("application/octet-stream")
            .body(bytes),
        Ok(None) => HttpResponse::NotFound().finish(),
        Err(error) => {
            error!("Failed to read an availability object: {error}");
            HttpResponse::InternalServerError().body("Availability storage is unavailable")
        }
    }
}

/// The slot activity for an address in a round.
///
/// Reports whether the slot holds any published entry, not whether its owner voted: a mask is
/// indistinguishable from a vote by design, and the server does not track who submitted what.
/// A client that wants "did I vote" must remember its own submissions.
async fn get_vote_status(
    data: web::Json<VoteStatusRequest>,
    store: web::Data<AppData>,
) -> impl Responder {
    let request = data.into_inner();
    let e3_id = match canonical_e3_id(&request.round_id) {
        Ok(e3_id) => e3_id,
        Err(e) => return HttpResponse::BadRequest().json(e.to_string()),
    };
    info!("[e3_id={e3_id}] Checking slot activity");

    // Validated before any storage access: a malformed address is the client's error, not a
    // database failure.
    let slot = match parse_slot_address(&request.address) {
        Ok(slot) => slot,
        Err(e) => return HttpResponse::BadRequest().json(e.to_string()),
    };

    let round = store.e3(&e3_id);
    let slot_active = match round.slot_has_activity(slot).await {
        Ok(active) => active,
        Err(e) => {
            error!("[e3_id={e3_id}] Database error checking slot activity: {e:?}");
            return HttpResponse::InternalServerError().json("Internal server error");
        }
    };

    // A round without readable state still answers; `round_status` is null.
    let round_status = match round.get_e3_state_lite().await {
        Ok(state) => Some(state.status),
        Err(e) => {
            warn!("[e3_id={e3_id}] Could not read the round status: {e:?}");
            None
        }
    };

    HttpResponse::Ok().json(VoteStatusResponse {
        round_id: e3_id,
        address: request.address,
        slot_active,
        round_status,
    })
}

/// Report where one submitted input stands in the selection of its slot.
///
/// The body names the input by round, slot, commitment, content hash, and parent, so no
/// identifier travels in the URL. The answer is `not_indexed`, `selection_pending`, `selected`,
/// or `excluded` with a reason, and the tree index of the current slot head. 404 when this
/// server has no record of the round. Each call is charged to the caller's read window, and 429
/// answers a caller past it.
async fn get_input_selection(
    http_request: HttpRequest,
    data: web::Json<InputSelectionRequest>,
    store: web::Data<AppData>,
    limiter: web::Data<ChainRateLimiter>,
) -> impl Responder {
    if admit(&http_request, &limiter, SELECTION_READ_COST).is_err() {
        // The caller stays out of the log line: on a voting route it would tie a caller to the
        // inputs that it follows.
        warn!("Rate limit refused /voting/selection");
        return HttpResponse::TooManyRequests()
            .json("Too many requests from this address, slow down");
    }
    let request = data.into_inner();
    let e3_id = match canonical_e3_id(&request.round_id) {
        Ok(e3_id) => e3_id,
        Err(e) => return HttpResponse::BadRequest().json(e.to_string()),
    };
    let Ok(slot) = parse_slot_address(&request.slot_address) else {
        return HttpResponse::BadRequest().json("Invalid slot address");
    };
    let Ok(commitment) = B256::from_str(&request.encrypted_vote_commitment) else {
        return HttpResponse::BadRequest().json("Invalid encrypted vote commitment");
    };
    let Ok(content_hash) = B256::from_str(&request.encrypted_vote_hash) else {
        return HttpResponse::BadRequest().json("Invalid encrypted vote hash");
    };

    match store
        .e3(&e3_id)
        .get_input_selection(
            slot,
            commitment.0,
            request.parent_index_plus_one,
            content_hash.0,
        )
        .await
    {
        Ok(Some(selection)) => HttpResponse::Ok().json(selection),
        Ok(None) => HttpResponse::NotFound().json(format!("No record of round {e3_id}")),
        Err(e) => {
            error!("[e3_id={e3_id}] Could not resolve an input selection: {e}");
            HttpResponse::InternalServerError().json("Internal server error")
        }
    }
}

/// Broadcast an encrypted vote to the blockchain.
///
/// The relay signs and pays for the transaction, so the input is dry-run first — an invalid
/// proof, a stale parent, or a closed window is refused as a client error instead of costing a
/// reverted transaction — and traffic is rate limited per caller and globally.
async fn broadcast_encrypted_vote(
    request: HttpRequest,
    data: web::Json<VoteRequest>,
    limiter: web::Data<RateLimiter>,
    availability: web::Data<AvailabilityService>,
) -> impl Responder {
    // Same identity rule as the read routes, and it matters more here: this window is what stops
    // one caller spending the relay's gas. A forgeable key is no key at all — see `identify`.
    let caller = identify(&request, CONFIG.trust_proxy_headers);

    // Caller admission only. A later global reservation is returned if validation or
    // infrastructure fails before a durable availability job is admitted.
    if limiter.check_caller(&caller).is_err() {
        warn!("Rate limit (caller) refused a broadcast from {caller}");
        return HttpResponse::TooManyRequests()
            .json(failed("Too many votes from this address, slow down"));
    }

    let vote = data.into_inner();
    let e3_id = match e3_id_to_u256(&vote.round_id) {
        Ok(e3_id) => e3_id,
        Err(e) => return HttpResponse::BadRequest().json(e.to_string()),
    };
    let e3_key = e3_id.to_string();

    info!("[e3_id={e3_key}] Broadcasting encrypted vote");

    // The client already encodes the proof; this only decodes the hex.
    let hex_str = vote
        .encoded_proof
        .strip_prefix("0x")
        .unwrap_or(&vote.encoded_proof);
    let encoded_proof = match hex::decode(hex_str) {
        Ok(decoded) => decoded,
        Err(e) => {
            error!("[e3_id={e3_key}] Failed to decode encoded_proof: {e:?}");
            return HttpResponse::BadRequest().json(failed("Invalid hex encoded proof"));
        }
    };

    // A repeat of a statement that already has durable work creates nothing and spends nothing.
    // Answer it before the funding window is touched: charging a replay would let one caller
    // consume the allowance that new votes need, and near the commitment cutoff that stops
    // honest voters. The caller traffic window above still bounds a replay loop.
    match availability
        .existing_input_job(&e3_key, &encoded_proof)
        .await
    {
        Ok(Some(job)) => return job_response(job),
        Ok(None) => {}
        Err(error) => return availability_error(&e3_key, &error),
    }

    // Reserve a global slot before the service can admit work that may spend relay funds. The
    // guard owns this request's reservation and returns it on any path that admits nothing.
    let Ok(reservation) = limiter.try_reserve_global() else {
        warn!("Rate limit (global) refused a broadcast from {caller}");
        return HttpResponse::TooManyRequests()
            .json(failed("The relay is busy, please try again shortly"));
    };

    // The service commits the reservation in the step that writes the durable job and returns
    // it on every path that admits nothing. Committing here, after the await, would let a
    // client that closes the connection mid-stage cancel this handler and release quota for a
    // job the background worker still holds.
    match availability
        .stage_input(
            &e3_key,
            encoded_proof,
            vote.send_from_wallet,
            Some(reservation),
        )
        .await
    {
        Ok(staged) => job_response(staged.view),
        Err(error) => availability_error(&e3_key, &error),
    }
}

async fn get_availability_status(
    job_id: web::Path<String>,
    availability: web::Data<AvailabilityService>,
) -> impl Responder {
    match availability.refreshed_view(&job_id).await {
        Ok(Some(job)) => HttpResponse::Ok().json(job),
        Ok(None) => HttpResponse::NotFound().finish(),
        Err(error) => {
            error!(
                "Failed to read availability job {}: {error}",
                job_id.as_str()
            );
            HttpResponse::ServiceUnavailable()
                .body("Availability status is temporarily unavailable")
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::server::{
        app_data::AppData,
        database::SledDB,
        models::{CensusMode, CreditMode, CustomParams},
        rate_limit::ChainRateLimiter,
    };
    use actix_web::{http::StatusCode, test, web, App};
    use alloy_primitives::Address;
    use e3_sdk::indexer::SharedStore;
    use serde_json::json;
    use std::sync::Arc;
    use tokio::sync::RwLock;

    /// The selection route reads the input from the JSON body and answers in the documented
    /// shape. A round this server has no record of is 404, and a malformed field is 400.
    #[actix_web::test]
    async fn the_selection_route_reads_the_input_from_the_body() {
        let store = SharedStore::new(Arc::new(RwLock::new(
            SledDB::from_db(sled::Config::new().temporary(true).open().unwrap()).unwrap(),
        )));
        let data = AppData::new(store);
        data.e3("5")
            .initialize_round(
                CustomParams {
                    token_address: "0x0000000000000000000000000000000000000001".to_owned(),
                    balance_threshold: "1".to_owned(),
                    num_options: "2".to_owned(),
                    credit_mode: CreditMode::Constant,
                    credits: Some("1".to_owned()),
                    census_mode: CensusMode::Token,
                    voting_power_divisor: "0".to_owned(),
                },
                Address::ZERO,
                "requester".to_owned(),
                100,
                100,
                1,
            )
            .await
            .unwrap();
        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(data))
                .app_data(web::Data::new(ChainRateLimiter::with_trust(false)))
                .configure(super::super::setup_routes),
        )
        .await;
        let request = |round_id: &str, encrypted_vote_hash: &str| {
            test::TestRequest::post()
                .uri("/voting/selection")
                .set_json(json!({
                    "round_id": round_id,
                    "slot_address": format!("0x{}", "77".repeat(20)),
                    "encrypted_vote_commitment": format!("0x{}", "11".repeat(32)),
                    "encrypted_vote_hash": encrypted_vote_hash,
                    "parent_index_plus_one": 0,
                }))
                .to_request()
        };
        let hash = format!("0x{}", "22".repeat(32));

        let response = test::call_service(&app, request("5", &hash)).await;
        assert_eq!(response.status(), StatusCode::OK);
        let body: serde_json::Value = test::read_body_json(response).await;
        assert_eq!(
            body,
            json!({ "status": "not_indexed", "index": null, "head_index": null, "reason": null })
        );

        let unknown_round = test::call_service(&app, request("6", &hash)).await;
        assert_eq!(unknown_round.status(), StatusCode::NOT_FOUND);
        let malformed_hash = test::call_service(&app, request("5", "0x1234")).await;
        assert_eq!(malformed_hash.status(), StatusCode::BAD_REQUEST);
    }
}
