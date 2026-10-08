// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use std::{fmt::Debug, future::Future, str::FromStr};

use crate::server::{
    app_data::AppData,
    data_availability::{AvailabilityJobView, AvailabilityService},
    models::{
        canonical_e3_id, GetRoundRequest, PreviousCiphertextRequest, PreviousCiphertextResponse,
        RoundRequestWithRequester, WebhookPayload,
    },
    rate_limit::ChainRateLimiter,
};
use actix_web::{http::StatusCode, web, HttpRequest, HttpResponse, Responder};
use alloy::primitives::Address;
use log::{error, info};
use serde::Serialize;

use super::{
    chain::{admit, too_many_requests},
    json_message,
};

/// Upstream reads performed before a new aggregate-output job is admitted.
const OUTPUT_CALLBACK_READ_COST: usize = 6;

pub fn setup_routes(config: &mut web::ServiceConfig) {
    config.service(
        web::scope("/state")
            .route("/result", web::post().to(get_round_result))
            .route("/all", web::post().to(get_all_round_results))
            .route("/lite", web::post().to(get_round_state_lite))
            // The handler verifies the compute proof on Ethereum before it creates an Avail job.
            // Valid retries are idempotent, so this endpoint needs no separate caller identity.
            .service(
                web::resource("/add-result")
                    .app_data(crate::server::payloads::encrypted_json())
                    .route(web::post().to(handle_program_server_result)),
            )
            .route("/token-holders", web::post().to(get_token_holders_hashes))
            .route(
                "/eligible-addresses",
                web::post().to(handle_get_eligible_addresses),
            )
            .route(
                "/previous-ciphertext",
                web::post().to(handle_get_previous_ciphertext),
            ),
    );
}

/// The canonical round id, or the 400 plain-text answer for a malformed one.
fn round_id(raw: &str) -> Result<String, HttpResponse> {
    canonical_e3_id(raw).map_err(|e| HttpResponse::BadRequest().body(e.to_string()))
}

/// 200 for a finished job, 202 while it is still in progress.
pub(super) fn job_response(view: AvailabilityJobView) -> HttpResponse {
    if view.status == "success" {
        HttpResponse::Ok().json(view)
    } else {
        HttpResponse::Accepted().json(view)
    }
}

/// Answer a store read of one round: 200 with the value, `missing` when the store has none, and
/// a logged 500 with `failure` as the plain-text body when the read fails.
async fn respond<T: Serialize, E: Debug>(
    read: Result<Option<T>, E>,
    e3_id: &str,
    failure: &'static str,
    missing: impl Future<Output = HttpResponse>,
) -> HttpResponse {
    match read {
        Ok(Some(value)) => HttpResponse::Ok().json(value),
        Ok(None) => missing.await,
        Err(e) => {
            error!("{failure} for round {e3_id}: {e:?}");
            HttpResponse::InternalServerError().body(failure)
        }
    }
}

/// The answer for a round this server has no record of.
///
/// 404, not 500: the request was well formed and the server is fine. The id may not exist, or the
/// indexer may not have written it yet, and both frontends poll this once per block while a
/// committee forms. It is not 204 either: the SDK parses every 2xx body, so an empty success
/// would fail inside `response.json()` instead of giving the caller a status to branch on.
fn round_not_found(e3_id: &str) -> HttpResponse {
    json_message(StatusCode::NOT_FOUND, format!("No state for round {e3_id}"))
}

/// The round is indexed, but verified public-key bytes are not available.
///
/// Same status as an unknown round, never the same message: one means the request was never
/// seen, the other means the byte publication has not arrived or did not verify. `KeyPublished`
/// on chain is not sufficient because that stage records the proof-backed commitment before the
/// byte event.
async fn round_state_pending(store: &web::Data<AppData>, e3_id: &str) -> HttpResponse {
    match store.e3(e3_id).has_crisp_record().await {
        Ok(true) => json_message(
            StatusCode::NOT_FOUND,
            format!(
                "Round {e3_id} is indexed, but verified committee public-key bytes are not \
                 available, so there is no state to serve. KeyPublished on chain confirms only \
                 the commitment. Check the byte-publication event and the on-chain failure state."
            ),
        ),
        Ok(false) => round_not_found(e3_id),
        // A store failure is not an absent round: a 404 would tell a caller that a round it can
        // see on chain does not exist here.
        Err(e) => {
            error!("Error checking whether round {e3_id} is recorded: {e:?}");
            HttpResponse::InternalServerError().body("Failed to get E3 state")
        }
    }
}

/// The ciphertext a slot currently holds, for every ballot and not only masks, and the tree index
/// of that entry.
///
/// This is the end of the slot's chain of usable entries, not the newest entry published: an
/// entry whose bytes do not reproduce its commitment is never selected by the Secure Process and
/// is never a valid parent, so building on it would drop the client's input from the tally.
async fn handle_get_previous_ciphertext(
    data: web::Json<PreviousCiphertextRequest>,
    store: web::Data<AppData>,
) -> impl Responder {
    let incoming = data.into_inner();
    let e3_id = match round_id(&incoming.round_id) {
        Ok(e3_id) => e3_id,
        Err(response) => return response,
    };
    let address = match Address::from_str(&incoming.address) {
        Ok(address) => address,
        Err(e) => {
            error!("Invalid address format: {e:?}");
            return HttpResponse::BadRequest().body("Invalid address format");
        }
    };

    // Whether an entry's bytes reproduce its commitment is decided once, when the indexer stores
    // it, so resolving the chain is a walk over flags.
    let head = store.e3(&e3_id).get_slot_head(address.into()).await;
    respond(
        head.map(|head| {
            head.map(|(ciphertext, index)| PreviousCiphertextResponse { ciphertext, index })
        }),
        &e3_id,
        "Failed to get previous ciphertext",
        async { HttpResponse::NotFound().body("Ciphertext not found") },
    )
    .await
}

/// Webhook callback from the program server.
async fn handle_program_server_result(
    request: HttpRequest,
    data: web::Json<WebhookPayload>,
    availability: web::Data<AvailabilityService>,
    limiter: web::Data<ChainRateLimiter>,
) -> impl Responder {
    match data.into_inner() {
        WebhookPayload::Failed { e3_id, error } => {
            // This callback is not authenticated. A caller must not move durable round state by
            // claiming that the program server failed.
            let message = format!("Computation failed for E3 ID: {e3_id}. Error: {error}");
            error!("{message}");
            HttpResponse::Ok().json(message)
        }
        WebhookPayload::Completed {
            e3_id,
            ciphertext,
            ciphertext_commitment,
            proof,
        } => {
            info!(
                "Received program server result for E3 ID: {e3_id}, ciphertext len: {}, proof len: {}",
                ciphertext.len(),
                proof.len()
            );

            // In dev mode, proof might be empty
            if ciphertext.is_empty() && proof.is_empty() {
                info!("Both ciphertext and proof are empty for E3 ID: {e3_id} - skipping chain publication");
                return HttpResponse::Ok()
                    .json(format!("Computation completed for E3 ID: {e3_id}"));
            }

            let Ok(commitment) = <[u8; 32]>::try_from(ciphertext_commitment.as_slice()) else {
                return HttpResponse::BadRequest()
                    .body("ciphertext_commitment must be exactly 32 bytes");
            };
            if let Err((caller, cost)) = admit(&request, &limiter, OUTPUT_CALLBACK_READ_COST) {
                return too_many_requests(&caller, cost, "/state/add-result");
            }

            match availability
                .stage_output(&e3_id, ciphertext, commitment, proof)
                .await
            {
                Ok(job) => job_response(job),
                Err(error) => {
                    error!("Failed to stage aggregate ciphertext: {error}");
                    HttpResponse::ServiceUnavailable()
                        .body("Aggregate ciphertext publication is temporarily unavailable")
                }
            }
        }
    }
}

/// The result for one round.
async fn get_round_result(
    data: web::Json<GetRoundRequest>,
    store: web::Data<AppData>,
) -> impl Responder {
    let e3_id = match round_id(&data.round_id) {
        Ok(e3_id) => e3_id,
        Err(response) => return response,
    };
    respond(
        store.e3(&e3_id).try_get_web_result_request().await,
        &e3_id,
        "Failed to get E3 state",
        round_state_pending(&store, &e3_id),
    )
    .await
}

/// The results for all rounds, filtered by requester when the request names any.
async fn get_all_round_results(
    data: web::Json<RoundRequestWithRequester>,
    store: web::Data<AppData>,
) -> impl Responder {
    let round_ids = match store.current_round().get_round_ids().await {
        Ok(ids) => ids,
        Err(e) => {
            error!("Error retrieving round index: {e:?}");
            return HttpResponse::InternalServerError().body("Failed to retrieve round index");
        }
    };

    let requesters = &data.requesters;
    let mut states = Vec::new();
    for e3_id in round_ids {
        match store.e3(&e3_id).try_get_web_result_request().await {
            Ok(Some(w)) if requesters.is_empty() || requesters.contains(&w.requester) => {
                states.push(w)
            }
            Ok(Some(_)) => {}
            Ok(None) => info!("Round {e3_id} has no verified public-key bytes yet; skipping it"),
            Err(error) => {
                error!("Could not read round {e3_id} from the store: {error:?}");
                return HttpResponse::InternalServerError().body("Failed to retrieve round state");
            }
        }
    }

    HttpResponse::Ok().json(states)
}

/// The lightweight state of one round.
async fn get_round_state_lite(
    data: web::Json<GetRoundRequest>,
    store: web::Data<AppData>,
) -> impl Responder {
    let e3_id = match round_id(&data.round_id) {
        Ok(e3_id) => e3_id,
        Err(response) => return response,
    };
    respond(
        store.e3(&e3_id).try_get_e3_state_lite().await,
        &e3_id,
        "Failed to get E3 state",
        round_state_pending(&store, &e3_id),
    )
    .await
}

/// The hashes of a round's token holders. Each hash is `hash(address, token balance)`.
async fn get_token_holders_hashes(
    data: web::Json<GetRoundRequest>,
    store: web::Data<AppData>,
) -> impl Responder {
    let e3_id = match round_id(&data.round_id) {
        Ok(e3_id) => e3_id,
        Err(response) => return response,
    };
    respond(
        store.e3(&e3_id).try_get_token_holder_hashes().await,
        &e3_id,
        "Failed to get token holders hashes",
        async { round_not_found(&e3_id) },
    )
    .await
}

/// The addresses eligible to vote in a round, with their balances.
async fn handle_get_eligible_addresses(
    data: web::Json<GetRoundRequest>,
    store: web::Data<AppData>,
) -> impl Responder {
    let e3_id = match round_id(&data.round_id) {
        Ok(e3_id) => e3_id,
        Err(response) => return response,
    };
    respond(
        store.e3(&e3_id).try_get_eligible_addresses().await,
        &e3_id,
        "Failed to get eligible addresses",
        async { round_not_found(&e3_id) },
    )
    .await
}
