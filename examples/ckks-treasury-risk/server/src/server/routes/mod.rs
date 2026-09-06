// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! HTTP API (CRISP `routes/`):
//!
//! - `GET  /status`
//! - `GET  /rounds`                          round summaries
//! - `POST /rounds/request`                  open a round (admin; body = `{weights[4], daos[]}`)
//! - `GET  /rounds/{id}`                     round detail (weights, DAOs, submissions, results, timings)
//! - `GET  /rounds/{id}/public-key`          committee CKKS pk (hex) once published
//! - `GET  /rounds/{id}/slot/{address}`      the DAO's registered slot
//! - `POST /rounds/{id}/evaluate`            force evaluation now (admin / dev; needs ≥ MIN_DAOS)
//! - `GET  /rounds/{id}/result`              the opened risk once finished
//!
//! Nothing here accepts a submission: they go straight from the DAO's wallet to the
//! program contract. The server never sees an exposure vector or a mask.

use crate::config::CONFIG;
use crate::server::app_data::AppData;
use crate::server::evaluate::evaluate_and_publish;
use crate::server::models::{RoundDetail, RoundRequest, RoundStatus, RoundSummary, SlotResponse};
use crate::server::rounds::open_round;
use actix_web::{web, HttpResponse, Responder};
use alloy::providers::{Provider, ProviderBuilder};
use ckks_treasury_program::{ASSETS, MIN_DAOS};
use log::error;
use serde_json::json;

pub fn setup_routes(config: &mut web::ServiceConfig) {
    config.route("/status", web::get().to(status)).service(
        web::scope("/rounds")
            .route("", web::get().to(list_rounds))
            .route("/request", web::post().to(request_round))
            .route("/{id}", web::get().to(round_detail))
            .route("/{id}/public-key", web::get().to(public_key))
            .route("/{id}/slot/{address}", web::get().to(slot))
            .route("/{id}/evaluate", web::post().to(evaluate_now))
            .route("/{id}/result", web::get().to(result)),
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
        "paramSet": ckks_treasury_program::PARAM_SET,
        "assets": ASSETS,
        "minDaos": MIN_DAOS,
        "maskWidth": ckks_treasury_program::MASK_WIDTH,
        "maskBound": ckks_treasury_program::MASK_BOUND,
        "exposureBound": ckks_treasury_program::EXPOSURE_BOUND,
        "weightBound": ckks_treasury_program::WEIGHT_BOUND,
        "openingLevel": ckks_treasury_program::opening_level(),
        "ceremonyKeys": ckks_treasury_program::ceremony_key_files(),
        "outputCount": ckks_treasury_program::OUTPUT_COUNT,
        "outputDecimals": ckks_treasury_program::OUTPUT_DECIMALS,
    }))
}

fn summary(r: &crate::server::models::E3Treasury) -> RoundSummary {
    RoundSummary {
        e3_id: r.e3_id.clone(),
        status: r.status,
        input_window: r.input_window,
        weights: r.weights,
        dao_count: r.daos.len(),
        submission_count: r.submissions.len(),
        created_at: r.created_at,
    }
}

async fn list_rounds(data: web::Data<AppData>) -> impl Responder {
    let ids = match data.rounds().round_ids().await {
        Ok(ids) => ids,
        Err(e) => return internal(e),
    };
    let mut out = Vec::new();
    for id in ids.into_iter().rev() {
        if let Ok(Some(r)) = data.e3(&id).try_get().await {
            out.push(summary(&r));
        }
    }
    HttpResponse::Ok().json(out)
}

async fn request_round(data: web::Data<AppData>, body: web::Json<RoundRequest>) -> impl Responder {
    let req = body.into_inner();
    match open_round(data.store(), req.weights, req.daos, req.duration_secs).await {
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
        summary: summary(&round),
        program_address: CONFIG.e3_program_address.clone(),
        param_set: ckks_treasury_program::PARAM_SET,
        assets: ASSETS,
        min_daos: MIN_DAOS,
        weights_fixed: round.weights().fixed_point().0,
        daos: round.daos,
        submissions: round.submissions,
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

async fn slot(data: web::Data<AppData>, path: web::Path<(String, String)>) -> impl Responder {
    let (id, address) = path.into_inner();
    let round = match data.e3(&id).try_get().await {
        Ok(Some(r)) => r,
        Ok(None) => return HttpResponse::NotFound().json(json!({ "error": "no such round" })),
        Err(e) => return internal(e),
    };
    let wanted = address.trim_start_matches("0x").to_lowercase();
    match round
        .daos
        .iter()
        .position(|a| a.trim_start_matches("0x").to_lowercase() == wanted)
    {
        Some(index) => HttpResponse::Ok().json(SlotResponse {
            address: round.daos[index].clone(),
            index: index as u32,
        }),
        None => HttpResponse::NotFound()
            .json(json!({ "error": format!("{address} is not a registered DAO of round {id}") })),
    }
}

async fn result(data: web::Data<AppData>, path: web::Path<String>) -> impl Responder {
    let id = path.into_inner();
    match data.e3(&id).try_get().await {
        Ok(Some(r)) => match r.results {
            Some(res) => HttpResponse::Ok().json(res),
            None => HttpResponse::NotFound().json(json!({
                "error": format!("round {id} is {:?}; no result yet", r.status)
            })),
        },
        Ok(None) => HttpResponse::NotFound().json(json!({ "error": "no such round" })),
        Err(e) => internal(e),
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
    if round.submissions.len() < MIN_DAOS {
        return bad(format!(
            "{} submission(s); at least {MIN_DAOS} DAOs must submit before the aggregate risk is evaluated",
            round.submissions.len()
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
