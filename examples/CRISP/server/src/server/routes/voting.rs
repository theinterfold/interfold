// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::server::{
    app_data::AppData,
    models::{
        VoteRequest, VoteResponse, VoteResponseStatus, VoteStatusRequest, VoteStatusResponse,
    },
    CONFIG,
};
use actix_web::{web, HttpResponse, Responder};
use alloy::primitives::{Bytes, U256};
use evm_helpers::CRISPContract;
use eyre::Error;
use log::{error, info};

pub fn setup_routes(config: &mut web::ServiceConfig) {
    config.service(
        web::scope("/voting")
            .route("/broadcast", web::post().to(broadcast_encrypted_vote))
            .route("/status", web::post().to(get_vote_status)),
    );
}

/// Get the vote status for a user in a specific round
///
/// # Arguments
///
/// * `VoteStatusRequest` - The request containing round_id and address
///
/// # Returns
///
/// * A JSON response with the vote status
async fn get_vote_status(
    data: web::Json<VoteStatusRequest>,
    store: web::Data<AppData>,
) -> impl Responder {
    let request = data.into_inner();
    info!(
        "[e3_id={}] Checking vote status for address: {}",
        request.round_id, request.address
    );

    let has_voted = match store
        .e3(request.round_id)
        .has_voted(request.address.clone())
        .await
    {
        Ok(voted) => voted,
        Err(e) => {
            error!(
                "[e3_id={}] Database error checking vote status: {:?}",
                request.round_id, e
            );
            return HttpResponse::InternalServerError().json("Internal server error");
        }
    };

    let round_status = match store.e3(request.round_id).get_e3_state_lite().await {
        Ok(state) => Some(state.status),
        Err(_) => None,
    };

    HttpResponse::Ok().json(VoteStatusResponse {
        round_id: request.round_id,
        address: request.address,
        has_voted,
        round_status,
    })
}

/// Broadcast an encrypted vote to the blockchain
///
/// # Arguments
///
/// * `EncryptedVote` - The vote data to be broadcast
///
/// # Returns
///
/// * A JSON response indicating the success or failure of the operation
async fn broadcast_encrypted_vote(
    data: web::Json<VoteRequest>,
    store: web::Data<AppData>,
) -> impl Responder {
    let vote = data.into_inner();
    info!("[e3_id={}] Broadcasting encrypted vote", vote.round_id);

    // Check if user has already voted
    let has_voted = match store
        .e3(vote.round_id)
        .has_voted(vote.address.clone())
        .await
    {
        Ok(voted) => voted,
        Err(e) => {
            error!(
                "[e3_id={}] Database error checking vote status: {:?}",
                vote.round_id, e
            );
            return HttpResponse::InternalServerError().json("Internal server error");
        }
    };

    let is_vote_update = has_voted;
    if is_vote_update {
        info!("[e3_id={}] User is updating their vote", vote.round_id);
    }

    let mut repo = store.e3(vote.round_id);

    let e3_id = U256::from(vote.round_id);

    // encoded_proof is already encoded in JavaScript, just decode from hex
    let hex_str = vote
        .encoded_proof
        .strip_prefix("0x")
        .unwrap_or(&vote.encoded_proof);
    let encoded_proof = match hex::decode(hex_str) {
        Ok(decoded) => Bytes::from(decoded),
        Err(e) => {
            error!(
                "[e3_id={}] Failed to decode encoded_proof: {:?}",
                vote.round_id, e
            );

            return HttpResponse::BadRequest().json(VoteResponse {
                status: VoteResponseStatus::FailedBroadcast,
                tx_hash: None,
                message: Some("Invalid hex encoded proof".to_string()),
                is_vote_update: Some(is_vote_update),
            });
        }
    };

    // Broadcast vote to blockchain
    let contract = match CRISPContract::new(
        &CONFIG.http_rpc_url,
        &CONFIG.private_key,
        &CONFIG.e3_program_address,
    )
    .await
    {
        Ok(c) => c,
        Err(e) => {
            error!("[e3_id={}] Contract creation error: {:?}", vote.round_id, e);
            return HttpResponse::InternalServerError().json("Internal server error");
        }
    };

    match contract.publish_input(e3_id, encoded_proof).await {
        Ok(hash) => {
            if !has_voted {
                if let Err(e) = repo.insert_voter_address(vote.address.clone()).await {
                    error!(
                        "[e3_id={}] Vote on-chain but failed to record voter locally: {:?}",
                        vote.round_id, e
                    );
                }
            }

            let message = if is_vote_update {
                "Vote Updated Successfully"
            } else {
                "Vote Successful"
            };
            info!(
                "[e3_id={}] Vote broadcasted successfully (update: {})",
                vote.round_id, is_vote_update
            );
            HttpResponse::Ok().json(VoteResponse {
                status: VoteResponseStatus::Success,
                tx_hash: Some(hash.transaction_hash.to_string()),
                message: Some(message.to_string()),
                is_vote_update: Some(is_vote_update),
            })
        }
        Err(e) => handle_vote_error(e, has_voted).await,
    }
}

/// Extract an error message from an error
fn extract_error_message(e: &Error) -> String {
    let error_str = e.to_string();

    if error_str.contains("Internal error") || error_str.contains("-32603") {
        return "Transaction rejected by the blockchain".to_string();
    }
    if error_str.contains("insufficient funds") {
        return "Insufficient funds to process transaction".to_string();
    }
    if error_str.contains("nonce") {
        return "Transaction conflict, please try again".to_string();
    }
    if error_str.contains("gas") {
        return "Transaction failed due to gas issues".to_string();
    }
    if error_str.contains("reverted") {
        return "Transaction was reverted by the contract".to_string();
    }
    if error_str.contains("timeout") || error_str.contains("Timeout") {
        return "Transaction timed out, please try again".to_string();
    }

    "Transaction failed, please try again".to_string()
}

/// Handle the vote error
///
/// # Arguments
///
/// * `e` - The error that occurred
/// * `was_update` - Whether this was a vote update
async fn handle_vote_error(e: Error, was_update: bool) -> HttpResponse {
    // Log the full error for debugging
    error!("Error while sending vote transaction: {:?}", e);

    let user_message = extract_error_message(&e);

    HttpResponse::InternalServerError().json(VoteResponse {
        status: VoteResponseStatus::FailedBroadcast,
        tx_hash: None,
        message: Some(user_message),
        is_vote_update: Some(was_update),
    })
}
