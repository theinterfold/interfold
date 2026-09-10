// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::server::{
    app_data::AppData,
    data_availability::{input_rejection_message, AvailabilityService},
    models::{
        canonical_e3_id, e3_id_to_u256, VoteRequest, VoteResponse, VoteResponseStatus,
        VoteStatusRequest, VoteStatusResponse,
    },
    rate_limit::RateLimiter,
    repo::parse_slot_address,
    CONFIG,
};
use actix_web::{web, HttpRequest, HttpResponse, Responder};
use alloy::primitives::Bytes;
use log::{error, info, warn};

pub fn setup_routes(config: &mut web::ServiceConfig) {
    config.route(
        "/availability/objects/{content_hash}",
        web::get().to(get_available_object),
    );
    config.service(
        web::scope("/voting")
            .route("/broadcast", web::post().to(broadcast_encrypted_vote))
            .route(
                "/availability/{job_id}",
                web::get().to(get_availability_status),
            )
            .route("/status", web::post().to(get_vote_status)),
    );
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

/// Get the slot activity for an address in a specific round.
///
/// Reports whether the slot holds any published entry, not whether its owner voted: a mask is
/// indistinguishable from a vote by design, and the server does not track who submitted what.
/// A client that wants "did I vote" must remember its own submissions.
///
/// # Arguments
///
/// * `VoteStatusRequest` - The request containing round_id and address
///
/// # Returns
///
/// * A JSON response with the slot activity
async fn get_vote_status(
    data: web::Json<VoteStatusRequest>,
    store: web::Data<AppData>,
) -> impl Responder {
    let request = data.into_inner();
    let e3_id = match canonical_e3_id(&request.round_id) {
        Ok(e3_id) => e3_id,
        Err(e) => return HttpResponse::BadRequest().json(e.to_string()),
    };
    info!(
        "[e3_id={}] Checking slot activity for address: {}",
        e3_id, request.address
    );

    // Validated before any storage access: a malformed address is the client's error, not a
    // database failure.
    let slot = match parse_slot_address(&request.address) {
        Ok(slot) => slot,
        Err(e) => return HttpResponse::BadRequest().json(e.to_string()),
    };

    let slot_active = match store.e3(&e3_id).slot_has_activity(slot).await {
        Ok(active) => active,
        Err(e) => {
            error!(
                "[e3_id={}] Database error checking slot activity: {:?}",
                e3_id, e
            );
            return HttpResponse::InternalServerError().json("Internal server error");
        }
    };

    let round_status = match store.e3(&e3_id).get_e3_state_lite().await {
        Ok(state) => Some(state.status),
        Err(_) => None,
    };

    HttpResponse::Ok().json(VoteStatusResponse {
        round_id: e3_id,
        address: request.address,
        slot_active,
        round_status,
    })
}

/// Broadcast an encrypted vote to the blockchain
///
/// The relay signs and pays for the transaction, so the input is dry-run first — an invalid
/// proof, a stale parent, or a closed window is refused as a client error instead of costing a
/// reverted transaction — and traffic is rate limited per caller and globally.
///
/// # Arguments
///
/// * `EncryptedVote` - The vote data to be broadcast
///
/// # Returns
///
/// * A JSON response indicating the success or failure of the operation
async fn broadcast_encrypted_vote(
    request: HttpRequest,
    data: web::Json<VoteRequest>,
    limiter: web::Data<RateLimiter>,
    availability: web::Data<AvailabilityService>,
) -> impl Responder {
    // Same identity rule as the read routes, and it matters more here: this window is what stops
    // one caller spending the relay's gas. A forgeable key is no key at all — see `caller_id`.
    let caller = super::chain::identify(&request, CONFIG.trust_proxy_headers);

    // Caller admission only. A later global reservation is returned if validation or
    // infrastructure fails before a durable availability job is admitted.
    if limiter.check_caller(&caller).is_err() {
        warn!("Rate limit (caller) refused a broadcast from {caller}");

        return HttpResponse::TooManyRequests().json(VoteResponse {
            status: VoteResponseStatus::FailedBroadcast,
            tx_hash: None,
            job_id: None,
            encoded_proof: None,
            message: Some("Too many votes from this address, slow down".to_string()),
        });
    }

    let vote = data.into_inner();
    let e3_id = match e3_id_to_u256(&vote.round_id) {
        Ok(e3_id) => e3_id,
        Err(e) => return HttpResponse::BadRequest().json(e.to_string()),
    };
    let e3_key = e3_id.to_string();

    info!("[e3_id={}] Broadcasting encrypted vote", e3_key);

    // encoded_proof is already encoded in JavaScript, just decode from hex
    let hex_str = vote
        .encoded_proof
        .strip_prefix("0x")
        .unwrap_or(&vote.encoded_proof);
    let encoded_proof = match hex::decode(hex_str) {
        Ok(decoded) => Bytes::from(decoded),
        Err(e) => {
            error!("[e3_id={}] Failed to decode encoded_proof: {:?}", e3_key, e);

            return HttpResponse::BadRequest().json(VoteResponse {
                status: VoteResponseStatus::FailedBroadcast,
                tx_hash: None,
                job_id: None,
                encoded_proof: None,
                message: Some("Invalid hex encoded proof".to_string()),
            });
        }
    };

    // Reserve a global slot before the service can admit work that may spend relay funds.
    if limiter.try_reserve_global().is_err() {
        warn!("Rate limit (global) refused a broadcast from {caller}");

        return HttpResponse::TooManyRequests().json(VoteResponse {
            status: VoteResponseStatus::FailedBroadcast,
            tx_hash: None,
            job_id: None,
            encoded_proof: None,
            message: Some("The relay is busy, please try again shortly".to_string()),
        });
    }

    match availability
        .stage_input(&e3_key, encoded_proof.to_vec())
        .await
    {
        Ok(job) if job.status == "success" => HttpResponse::Ok().json(job),
        Ok(job) => HttpResponse::Accepted().json(job),
        Err(error) => {
            limiter.release_global_reservation();
            if let Some(message) = input_rejection_message(&error) {
                warn!("[e3_id={}] Vote rejected: {}", e3_key, error);
                return HttpResponse::BadRequest().json(VoteResponse {
                    status: VoteResponseStatus::FailedBroadcast,
                    tx_hash: None,
                    job_id: None,
                    encoded_proof: None,
                    message: Some(message.to_string()),
                });
            }
            error!("[e3_id={}] Availability service failed: {}", e3_key, error);
            HttpResponse::ServiceUnavailable().json(VoteResponse {
                status: VoteResponseStatus::FailedBroadcast,
                tx_hash: None,
                job_id: None,
                encoded_proof: None,
                message: Some("The availability service is temporarily unavailable".to_string()),
            })
        }
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
