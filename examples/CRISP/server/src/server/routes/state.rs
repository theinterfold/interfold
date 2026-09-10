// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use std::str::FromStr;

use crate::server::{
    app_data::AppData,
    data_availability::AvailabilityService,
    models::{
        canonical_e3_id, e3_id_to_u256, ArchivePage, ArchiveRequest, GetRoundRequest, JsonResponse,
        PreviousCiphertextRequest, PreviousCiphertextResponse, RoundRequestWithRequester,
        WebhookPayload,
    },
    rate_limit::ChainRateLimiter,
};
use actix_web::{web, HttpRequest, HttpResponse, Responder};
use alloy::primitives::Address;
use log::{error, info};

use super::chain::{admit, too_many_requests};

/// Upstream reads performed before a new aggregate-output job is admitted.
const OUTPUT_CALLBACK_READ_COST: usize = 6;

pub fn setup_routes(config: &mut web::ServiceConfig) {
    config.service(
        web::scope("/state")
            .route("/result", web::post().to(get_round_result))
            .route("/all", web::post().to(get_all_round_results))
            .route("/archive", web::post().to(get_archive_page))
            .route("/lite", web::post().to(get_round_state_lite))
            // The handler verifies the compute proof on Ethereum before it creates an Avail job.
            // Valid retries are idempotent, so this endpoint needs no separate caller identity.
            .route("/add-result", web::post().to(handle_program_server_result))
            // Get the token holders hashes for a given round
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

/// The answer for a round this server has no record of.
///
/// 404, not 500: the request was well formed and the server is fine — there is simply no such
/// round here, either because the id does not exist or because the indexer has not written it
/// yet. Both frontends poll this for a round whose committee is still forming, once per block,
/// so answering "internal server error" made a normal state of a normal round look like an
/// outage in every console and every log.
///
/// Not 204 either: the SDK treats a 2xx as a body it can parse, so an empty success would fail
/// inside `response.json()` with a parse error instead of a status a caller can branch on.
fn round_not_found(e3_id: &str) -> HttpResponse {
    HttpResponse::NotFound().json(JsonResponse {
        response: format!("No state for round {e3_id}"),
    })
}

/// The round is indexed, but verified public-key bytes are not available.
///
/// Same status as an unknown round, because there is still nothing to serve, but never the same
/// message. The two have completely different causes: one means the request was never seen, the
/// other means the byte publication has not arrived or did not verify. `KeyPublished` on chain is
/// not sufficient because that stage records the proof-backed commitment before the byte event.
async fn round_state_pending(store: &web::Data<AppData>, e3_id: &str) -> HttpResponse {
    match store.e3(e3_id).has_crisp_record().await {
        Ok(true) => HttpResponse::NotFound().json(JsonResponse {
            response: format!(
                "Round {e3_id} is indexed, but verified committee public-key bytes are not \
                 available, so there is no state to serve. KeyPublished on chain confirms only \
                 the commitment. Check the byte-publication event and the on-chain failure state."
            ),
        }),
        Ok(false) => round_not_found(e3_id),
        // A store failure is not an absent round. Collapsing it into 404 would tell a caller that
        // a round it can see on chain does not exist here — the same conflation this function was
        // added to remove, one level down.
        Err(e) => {
            error!("Error checking whether round {e3_id} is recorded: {e:?}");
            HttpResponse::InternalServerError().body("Failed to get E3 state")
        }
    }
}

/// Endpoint to get the ciphertext a slot currently holds. Used for every ballot, not only masks.
///
/// Answers with the end of the slot's chain of usable entries, and the tree index of that entry.
/// Not simply the newest entry published: an entry whose bytes do not reproduce its commitment is
/// never selected by the Secure Process and is never a valid parent, so building on it would have
/// the client's input dropped from the tally.
///
/// # Arguments
/// * `data` - The round id and the slot address
///
/// # Returns
/// * A JSON response with the ciphertext and its index, or 404 when the slot holds nothing usable.
async fn handle_get_previous_ciphertext(
    data: web::Json<PreviousCiphertextRequest>,
    store: web::Data<AppData>,
) -> impl Responder {
    let incoming = data.into_inner();

    let e3_id = match e3_id_to_u256(&incoming.round_id) {
        Ok(e3_id) => e3_id,
        Err(e) => return HttpResponse::BadRequest().body(e.to_string()),
    };
    let e3_key = e3_id.to_string();

    let address = match Address::from_str(incoming.address.as_str()) {
        Ok(addr) => addr,
        Err(e) => {
            error!("Invalid address format: {:?}", e);
            return HttpResponse::BadRequest().body("Invalid address format");
        }
    };

    // No BFV work and no parameters here. Whether an entry's bytes reproduce its commitment is
    // decided once, when the indexer stores it, so resolving the chain is a walk over flags.
    match store.e3(e3_key).get_slot_head(address.into()).await {
        Ok(Some((ciphertext, index))) => {
            HttpResponse::Ok().json(PreviousCiphertextResponse { ciphertext, index })
        }
        Ok(None) => HttpResponse::NotFound().body("Ciphertext not found"),
        Err(e) => {
            error!("Error getting previous ciphertext: {:?}", e);
            HttpResponse::InternalServerError().body("Failed to get previous ciphertext")
        }
    }
}

/// Webhook callback from program server
///
/// # Arguments
/// * `data` - The request data containing the result from the program server
///
/// # Returns
/// * A JSON response indicating the success of the operation
async fn handle_program_server_result(
    request: HttpRequest,
    data: web::Json<WebhookPayload>,
    availability: web::Data<AvailabilityService>,
    limiter: web::Data<ChainRateLimiter>,
) -> impl Responder {
    let incoming = data.into_inner();

    match incoming {
        WebhookPayload::Failed { e3_id, error } => {
            error!("Computation failed for E3 ID: {}. Error: {}", e3_id, error);

            // This callback is not authenticated. Do not let a caller move durable round state by
            // claiming that the program server failed.

            HttpResponse::Ok().json(format!(
                "Computation failed for E3 ID: {}. Error: {}",
                e3_id, error
            ))
        }
        WebhookPayload::Completed {
            e3_id,
            ciphertext,
            ciphertext_commitment,
            proof,
        } => {
            info!(
                "Received program server result for E3 ID: {}, ciphertext len: {}, proof len: {}",
                e3_id,
                ciphertext.len(),
                proof.len()
            );

            // In dev mode, proof might be empty
            if ciphertext.is_empty() && proof.is_empty() {
                info!(
                    "Both ciphertext and proof are empty for E3 ID: {} - skipping chain publication",
                    e3_id
                );
                return HttpResponse::Ok()
                    .json(format!("Computation completed for E3 ID: {}", e3_id));
            }

            if ciphertext_commitment.len() != 32 {
                return HttpResponse::BadRequest()
                    .body("ciphertext_commitment must be exactly 32 bytes");
            }
            if let Err((caller, cost)) = admit(&request, &limiter, OUTPUT_CALLBACK_READ_COST) {
                return too_many_requests(&caller, cost, "/state/add-result");
            }

            let mut commitment = [0u8; 32];
            commitment.copy_from_slice(&ciphertext_commitment);
            match availability
                .stage_output(&e3_id, ciphertext, commitment, proof)
                .await
            {
                Ok(job) if job.status == "success" => HttpResponse::Ok().json(job),
                Ok(job) => HttpResponse::Accepted().json(job),
                Err(error) => {
                    error!("Failed to stage aggregate ciphertext: {error}");
                    HttpResponse::ServiceUnavailable()
                        .body("Aggregate ciphertext publication is temporarily unavailable")
                }
            }
        }
    }
}

/// Get the result for a given round
///
/// # Arguments
///
/// * `GetRoundRequest` - The request data containing the round ID
///
/// # Returns
///
async fn get_round_result(
    data: web::Json<GetRoundRequest>,
    store: web::Data<AppData>,
) -> impl Responder {
    let incoming = data.into_inner();
    let e3_id = match canonical_e3_id(&incoming.round_id) {
        Ok(e3_id) => e3_id,
        Err(e) => return HttpResponse::BadRequest().body(e.to_string()),
    };

    match store.e3(&e3_id).try_get_web_result_request().await {
        Ok(Some(response)) => HttpResponse::Ok().json(response),
        Ok(None) => round_state_pending(&store, &e3_id).await,
        Err(e) => {
            error!("Error getting E3 state for {e3_id}: {e:?}");
            HttpResponse::InternalServerError().body("Failed to get E3 state")
        }
    }
}

/// Get all the results for all rounds
///
/// # Returns
///
/// * A JSON response containing the results for all rounds
async fn get_all_round_results(
    data: web::Json<RoundRequestWithRequester>,
    store: web::Data<AppData>,
) -> impl Responder {
    let incoming = data.into_inner();

    let round_ids = match store.current_round().get_round_ids().await {
        Ok(ids) => ids,
        Err(e) => {
            info!("Error retrieving round index: {:?}", e);
            return HttpResponse::InternalServerError().body("Failed to retrieve round index");
        }
    };

    let mut states = Vec::new();
    let requesters = incoming.requesters;

    for e3_id in round_ids {
        match store.e3(&e3_id).try_get_web_result_request().await {
            Ok(Some(w)) => {
                if !requesters.is_empty() {
                    // if we have any requesters to filter by, do it
                    if requesters.contains(&w.requester) {
                        states.push(w);
                    }
                } else {
                    states.push(w);
                }
            }
            Ok(None) => {
                info!(
                    "Round {} has no verified public-key bytes yet; skipping it",
                    e3_id
                );
            }
            Err(error) => {
                error!("Could not read round {e3_id} from the store: {error:?}");
                return HttpResponse::InternalServerError().body("Failed to retrieve round state");
            }
        }
    }

    HttpResponse::Ok().json(states)
}

async fn get_archive_page(
    data: web::Json<ArchiveRequest>,
    store: web::Data<AppData>,
) -> impl Responder {
    let before = match data.before() {
        Ok(before) => before,
        Err(error) => return HttpResponse::BadRequest().body(error.to_string()),
    };
    let (ids, next_cursor) = match store
        .current_round()
        .get_archive_round_ids(&data.requesters, before, data.limit)
        .await
    {
        Ok(page) => page,
        Err(error) => {
            error!("Could not read the archive index: {error}");
            return HttpResponse::InternalServerError().body("Could not read the archive index");
        }
    };
    let mut items = Vec::with_capacity(ids.len());
    for id in ids {
        match store.e3(id).try_get_web_result_request().await {
            Ok(Some(summary)) => items.push(summary),
            Ok(None) => {}
            Err(error) => {
                error!("Could not read an archive summary: {error}");
                return HttpResponse::InternalServerError()
                    .body("Could not read an archive summary");
            }
        }
    }
    HttpResponse::Ok().json(ArchivePage { items, next_cursor })
}

/// Get the state for a given round
///
/// # Arguments
///
/// * `GetRoundRequest` - The request data containing the round ID
///
/// # Returns
///
async fn get_round_state_lite(
    data: web::Json<GetRoundRequest>,
    store: web::Data<AppData>,
) -> impl Responder {
    let incoming = data.into_inner();
    let e3_id = match canonical_e3_id(&incoming.round_id) {
        Ok(e3_id) => e3_id,
        Err(e) => return HttpResponse::BadRequest().body(e.to_string()),
    };

    match store.e3(&e3_id).try_get_e3_state_lite().await {
        Ok(Some(state_lite)) => HttpResponse::Ok().json(state_lite),
        Ok(None) => round_state_pending(&store, &e3_id).await,
        Err(e) => {
            // Reaches here only on a store failure now, so it is worth a log line: it used to be
            // the ordinary "round not indexed yet" path and was silently discarded.
            error!("Error getting E3 state for {e3_id}: {e:?}");
            HttpResponse::InternalServerError().body("Failed to get E3 state")
        }
    }
}

/// Get the hashes of token holders for a given round
/// The hash is hash(address, token balance)
/// # Arguments
/// * `GetRoundRequest` - The request data containing the round ID
/// # Returns
/// * A JSON response containing the list of token holder hashes
async fn get_token_holders_hashes(
    data: web::Json<GetRoundRequest>,
    store: web::Data<AppData>,
) -> impl Responder {
    let incoming = data.into_inner();
    let e3_id = match canonical_e3_id(&incoming.round_id) {
        Ok(e3_id) => e3_id,
        Err(e) => return HttpResponse::BadRequest().body(e.to_string()),
    };

    match store.e3(&e3_id).try_get_token_holder_hashes().await {
        Ok(Some(hashes)) => HttpResponse::Ok().json(hashes),
        Ok(None) => round_not_found(&e3_id),
        Err(e) => {
            error!("Error getting token holders hashes for {e3_id}: {e:?}");
            HttpResponse::InternalServerError().body("Failed to get token holders hashes")
        }
    }
}

/// Get the eligible addresses for a given round
/// # Arguments
/// * `GetRoundRequest` - The request data containing the round ID
/// # Returns
/// * A JSON response containing the list of eligible addresses and their balances
async fn handle_get_eligible_addresses(
    data: web::Json<GetRoundRequest>,
    store: web::Data<AppData>,
) -> impl Responder {
    let incoming = data.into_inner();
    let e3_id = match canonical_e3_id(&incoming.round_id) {
        Ok(e3_id) => e3_id,
        Err(e) => return HttpResponse::BadRequest().body(e.to_string()),
    };

    match store.e3(&e3_id).try_get_eligible_addresses().await {
        Ok(Some(addresses)) => HttpResponse::Ok().json(addresses),
        Ok(None) => round_not_found(&e3_id),
        Err(e) => {
            error!("Error getting eligible addresses for {e3_id}: {e:?}");
            HttpResponse::InternalServerError().body("Failed to get eligible addresses")
        }
    }
}

#[cfg(test)]
mod archive_tests {
    use super::setup_routes;
    use crate::server::{app_data::AppData, database::SledDB};
    use actix_web::{http::StatusCode, test, web, App};
    use e3_sdk::{
        evm_helpers::contracts::CommitteeSize,
        indexer::{models::E3, DataStore, SharedStore},
    };
    use serde_json::{json, Value};
    use std::sync::Arc;
    use tokio::sync::RwLock;

    const FULL_WIDTH_ID: &str = "340282366920938463463374607431768211456";

    async fn fixture() -> (web::Data<AppData>, SharedStore<SledDB>) {
        let db = SledDB {
            db: sled::Config::new().temporary(true).open().unwrap(),
        };
        let mut store = SharedStore::new(Arc::new(RwLock::new(db)));
        store
            .insert(
                "_e3:round_index",
                &json!({
                    "ids": [FULL_WIDTH_ID, "1", "2"], "schema_version": 1,
                    "requesters": {"requester": [0, 2], "other": [1]}
                }),
            )
            .await
            .unwrap();
        let crisp = json!({
            "emojis": ["one", "two"], "start_time": 0, "end_time": 100,
            "status": "Finished", "tally": ["7", "3"], "token_holder_hashes": [],
            "eligible_addresses": [], "token_address": "token", "balance_threshold": "1",
            "ciphertext_inputs": [], "requester": "requester", "num_options": "2",
            "credit_mode": 0, "credits": "1"
        });
        for id in [FULL_WIDTH_ID, "2"] {
            store
                .insert(&format!("_e3:crisp:{id}"), &crisp)
                .await
                .unwrap();
        }
        store
            .insert("_e3:1", &"unselected invalid record")
            .await
            .unwrap();
        let e3 = E3 {
            chain_id: 1,
            id: FULL_WIDTH_ID.into(),
            input_window: [0, 100],
            ciphertext_inputs: vec![],
            ciphertext_output: vec![],
            ciphertext_output_reference: None,
            ciphertext_commitment: vec![],
            committee_public_key: vec![1],
            committee_public_key_hash: vec![],
            e3_params: vec![],
            custom_params: vec![],
            interfold_address: "contract".into(),
            encryption_scheme_id: vec![],
            crypto_config_id: vec![],
            plaintext_output: vec![],
            request_block: 1,
            seed: [0; 32],
            committee_size: CommitteeSize::Minimum,
            requester: "requester".into(),
        };
        store
            .insert(&format!("_e3:{FULL_WIDTH_ID}"), &e3)
            .await
            .unwrap();
        (web::Data::new(AppData::new(store.clone())), store)
    }

    #[actix_web::test]
    async fn archive_http_pages_pending_rounds_and_returns_full_width_summary_ids() {
        let (data, _) = fixture().await;
        let app = test::init_service(App::new().app_data(data).configure(setup_routes)).await;
        let first: Value = test::call_and_read_body_json(
            &app,
            test::TestRequest::post()
                .uri("/state/archive")
                .set_json(json!({"requesters": ["REQUESTER"], "limit": 1}))
                .to_request(),
        )
        .await;
        assert_eq!(first, json!({"items": [], "next_cursor": "v1:2"}));
        let second: Value = test::call_and_read_body_json(
            &app,
            test::TestRequest::post()
                .uri("/state/archive")
                .set_json(json!({
                    "requesters": ["requester"], "limit": 1, "cursor": first["next_cursor"]
                }))
                .to_request(),
        )
        .await;
        assert_eq!(
            second,
            json!({"items": [{
            "round_id": FULL_WIDTH_ID, "tally": ["7", "3"], "option_1_emoji": "one",
            "option_2_emoji": "two", "total_votes": 0, "end_time": 100, "requester": "requester"
        }], "next_cursor": null})
        );
    }

    #[actix_web::test]
    async fn archive_http_reports_bad_requests_and_store_failures() {
        let (data, mut store) = fixture().await;
        let app = test::init_service(App::new().app_data(data).configure(setup_routes)).await;
        for body in [
            json!({"limit": 0}),
            json!({"limit": 51}),
            json!({"cursor": "v2:1"}),
        ] {
            let response = test::call_service(
                &app,
                test::TestRequest::post()
                    .uri("/state/archive")
                    .set_json(body)
                    .to_request(),
            )
            .await;
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        }
        let response = test::call_service(
            &app,
            test::TestRequest::post()
                .uri("/state/archive")
                .set_json(json!({"requesters": ["other"]}))
                .to_request(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        store
            .insert("_e3:round_index", &"invalid index")
            .await
            .unwrap();
        let response = test::call_service(
            &app,
            test::TestRequest::post()
                .uri("/state/archive")
                .set_json(json!({}))
                .to_request(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }
}
