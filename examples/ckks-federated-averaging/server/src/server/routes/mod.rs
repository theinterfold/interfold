// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! HTTP API (CRISP `routes/`):
//!
//! - `GET  /status`
//! - `GET  /rounds`                          round summaries
//! - `POST /rounds/request`                  open a round (admin; body = client list + d + norm bound + min clients)
//! - `GET  /rounds/{id}`                     round detail (params, clients, updates, results, timings)
//! - `GET  /rounds/{id}/public-key`          committee CKKS pk (hex) once published
//! - `GET  /rounds/{id}/slot/{address}`      the client's registered slot + the round's bound
//! - `POST /rounds/{id}/evaluate`            force evaluation now (admin / dev; still requires min clients)
//!
//! Nothing here accepts an update: they go straight from the client's wallet to the program
//! contract. The server never sees a model update or a sample count.

use crate::config::CONFIG;
use crate::server::app_data::AppData;
use crate::server::evaluate::evaluate_and_publish;
use crate::server::models::{RoundDetail, RoundRequest, RoundStatus, RoundSummary, SlotResponse};
use crate::server::rounds::open_round;
use actix_web::{web, HttpResponse, Responder};
use alloy::providers::{Provider, ProviderBuilder};
use ckks_fedavg_program::RoundParams;
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
        "paramSet": ckks_fedavg_program::PARAM_SET,
        "d": ckks_fedavg_program::D,
        "maxD": ckks_fedavg_program::MAX_D,
        "entryBound": ckks_fedavg_program::ENTRY_BOUND,
        "countBound": ckks_fedavg_program::COUNT_BOUND,
        "openingLevel": ckks_fedavg_program::opening_level(),
        "ceremonyKeys": ckks_fedavg_program::ceremony_key_files(),
    }))
}

fn summary(r: &crate::server::models::E3FedAvg) -> RoundSummary {
    RoundSummary {
        e3_id: r.e3_id.clone(),
        status: r.status,
        d: r.params.d,
        norm_bound: r.params.norm_bound,
        min_clients: r.params.min_clients,
        input_window: r.input_window,
        update_count: r.updates.len(),
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
    if req.clients.is_empty() {
        return bad("client list must not be empty");
    }
    let params = RoundParams {
        d: req.d,
        norm_bound: req.norm_bound,
        min_clients: req.min_clients,
    };
    if let Err(e) = params.validate() {
        return bad(format!("{e:#}"));
    }
    match open_round(data.store(), req.clients, params, req.duration_secs).await {
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
        param_set: ckks_fedavg_program::PARAM_SET,
        norm_bound_fixed_point: round.norm_bound_fixed_point,
        clients: round.clients,
        updates: round.updates,
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
        .clients
        .iter()
        .position(|a| a.trim_start_matches("0x").to_lowercase() == wanted)
    {
        Some(index) => HttpResponse::Ok().json(SlotResponse {
            address: round.clients[index].clone(),
            index: index as u32,
            d: round.params.d,
            norm_bound: round.params.norm_bound,
            norm_bound_fixed_point: round.norm_bound_fixed_point,
        }),
        None => HttpResponse::NotFound()
            .json(json!({ "error": format!("{address} is not a registered client of round {id}") })),
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
    if round.updates.len() < round.params.min_clients {
        return bad(format!(
            "only {} update(s) accepted; the round requires at least {} clients",
            round.updates.len(),
            round.params.min_clients
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
