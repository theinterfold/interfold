// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! HTTP API (CRISP `routes/`):
//!
//! - `GET  /status`
//! - `GET  /rounds`                                  round summaries
//! - `POST /rounds/request`                          open a round (admin; body = issuer snapshot + model)
//! - `GET  /rounds/{id}`                             round detail (model, applicants, applications, results, timings)
//! - `GET  /rounds/{id}/public-key`                  committee CKKS pk (hex) once published
//! - `GET  /rounds/{id}/feature-proof/{address}`     the applicant's attested features + Merkle opening
//! - `POST /rounds/{id}/evaluate`                    force evaluation now (admin / dev)
//!
//! Nothing here accepts an application: they go straight from the applicant's wallet to the
//! program contract. The server never sees a mask.

use crate::config::CONFIG;
use crate::server::app_data::AppData;
use crate::server::evaluate::evaluate_and_publish;
use crate::server::models::{RoundDetail, RoundRequest, RoundStatus, RoundSummary};
use crate::server::rounds::open_round;
use crate::server::snapshot::build_tree;
use actix_web::{web, HttpResponse, Responder};
use alloy::providers::{Provider, ProviderBuilder};
use log::error;
use serde_json::json;

pub fn setup_routes(config: &mut web::ServiceConfig) {
    config.route("/status", web::get().to(status)).service(
        web::scope("/rounds")
            .route("", web::get().to(list_rounds))
            .route("/request", web::post().to(request_round))
            .route("/{id}", web::get().to(round_detail))
            .route("/{id}/public-key", web::get().to(public_key))
            .route(
                "/{id}/feature-proof/{address}",
                web::get().to(feature_proof),
            )
            .route("/{id}/evaluate", web::post().to(evaluate_now)),
    );
}

fn bad(e: impl std::fmt::Display) -> HttpResponse {
    HttpResponse::BadRequest().json(json!({ "error": e.to_string() }))
}

fn internal(e: impl std::fmt::Display) -> HttpResponse {
    error!("{e}");
    HttpResponse::InternalServerError().json(json!({ "error": e.to_string() }))
}

async fn status() -> impl Responder {
    let block = match ProviderBuilder::new().connect(&CONFIG.http_rpc_url).await {
        Ok(p) => p.get_block_number().await.unwrap_or(0),
        Err(_) => 0,
    };
    HttpResponse::Ok().json(json!({
        "chainId": CONFIG.chain_id,
        "block": block,
        "programAddress": CONFIG.e3_program_address,
        "interfoldAddress": CONFIG.interfold_address,
        "paramSet": ckks_credit_program::PARAM_SET,
        "features": ckks_credit_program::FEATURES,
        "maskBound": ckks_credit_program::MASK_BOUND,
        "weightBound": ckks_credit_program::WEIGHT_BOUND,
        "logitBound": ckks_credit_program::LOGIT_BOUND,
        "featureCap": crate::server::rounds::FEATURE_CAP,
        "openingLevel": ckks_credit_program::opening_level(),
        "ceremonyKeys": ckks_credit_program::ceremony_key_files(),
        "maxApplicants": ckks_credit_program::max_applicants().unwrap_or(0),
    }))
}

async fn list_rounds(data: web::Data<AppData>) -> impl Responder {
    let ids = match data.rounds().round_ids().await {
        Ok(ids) => ids,
        Err(e) => return internal(e),
    };
    let mut out = Vec::new();
    for id in ids.into_iter().rev() {
        if let Ok(Some(r)) = data.e3(&id).try_get().await {
            out.push(RoundSummary {
                e3_id: r.e3_id,
                status: r.status,
                cap: r.cap,
                input_window: r.input_window,
                application_count: r.applications.len(),
                created_at: r.created_at,
            });
        }
    }
    HttpResponse::Ok().json(out)
}

async fn request_round(data: web::Data<AppData>, body: web::Json<RoundRequest>) -> impl Responder {
    let req = body.into_inner();
    if req.snapshot.is_empty() {
        return bad("snapshot must not be empty");
    }
    match open_round(data.store(), req.snapshot, req.model, req.duration_secs).await {
        Ok(e3_id) => HttpResponse::Ok().json(json!({ "e3Id": e3_id })),
        Err(e) => internal(format!("open_round: {e:#}")),
    }
}

async fn round_detail(data: web::Data<AppData>, path: web::Path<String>) -> impl Responder {
    let id = path.into_inner();
    let repo = data.e3(&id);
    let round = match repo.try_get().await {
        Ok(Some(r)) => r,
        Ok(None) => return HttpResponse::NotFound().json(json!({ "error": "no such round" })),
        Err(e) => return internal(e),
    };
    let public_key_available =
        matches!(repo.interfold_e3().await, Ok(Some(e3)) if !e3.committee_public_key.is_empty());
    HttpResponse::Ok().json(RoundDetail {
        summary: RoundSummary {
            e3_id: round.e3_id.clone(),
            status: round.status,
            cap: round.cap,
            input_window: round.input_window,
            application_count: round.applications.len(),
            created_at: round.created_at,
        },
        program_address: CONFIG.e3_program_address.clone(),
        param_set: ckks_credit_program::PARAM_SET,
        model: round.model,
        fixed_point_model: round.fixed_point_model,
        issuer_root: round.issuer_root,
        applicant_addresses: round.snapshot.iter().map(|a| a.address.clone()).collect(),
        applications: round.applications,
        public_key_available,
        results: round.results,
        error: round.error,
        timings: round.timings.into_iter().collect(),
    })
}

async fn public_key(data: web::Data<AppData>, path: web::Path<String>) -> impl Responder {
    let id = path.into_inner();
    match data.e3(&id).interfold_e3().await {
        Ok(Some(e3)) if !e3.committee_public_key.is_empty() => HttpResponse::Ok()
            .json(json!({ "publicKeyHex": format!("0x{}", hex::encode(e3.committee_public_key)) })),
        Ok(_) => HttpResponse::NotFound()
            .json(json!({ "error": "committee public key not published yet" })),
        Err(e) => internal(e),
    }
}

async fn feature_proof(
    data: web::Data<AppData>,
    path: web::Path<(String, String)>,
) -> impl Responder {
    let (id, address) = path.into_inner();
    let round = match data.e3(&id).try_get().await {
        Ok(Some(r)) => r,
        Ok(None) => return HttpResponse::NotFound().json(json!({ "error": "no such round" })),
        Err(e) => return internal(e),
    };
    let tree = match build_tree(&round.snapshot, round.cap) {
        Ok(t) => t,
        Err(e) => return internal(e),
    };
    match tree.proof_for(&address) {
        Some(p) => HttpResponse::Ok().json(p),
        None => HttpResponse::NotFound().json(
            json!({ "error": format!("{address} is not in the issuer snapshot of round {id}") }),
        ),
    }
}

async fn evaluate_now(data: web::Data<AppData>, path: web::Path<String>) -> impl Responder {
    let id = path.into_inner();
    let mut repo = data.e3(&id);
    let round = match repo.try_get().await {
        Ok(Some(r)) => r,
        Ok(None) => return HttpResponse::NotFound().json(json!({ "error": "no such round" })),
        Err(e) => return internal(e),
    };
    if !matches!(round.status, RoundStatus::Active | RoundStatus::Evaluating) {
        return bad(format!(
            "round is {:?}; can only evaluate an active/evaluating round",
            round.status
        ));
    }
    if let Err(e) = repo.set_status(RoundStatus::Evaluating).await {
        return internal(e);
    }
    match evaluate_and_publish(data.store(), &id).await {
        Ok(()) => HttpResponse::Ok().json(json!({ "ok": true })),
        Err(e) => {
            let msg = format!("{e:#}");
            let _ = repo.update(|r| r.error = Some(msg.clone())).await;
            internal(msg)
        }
    }
}
