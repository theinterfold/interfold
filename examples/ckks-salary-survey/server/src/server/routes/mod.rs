// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! HTTP API.
//!
//! ```text
//! GET  /health
//! GET  /rounds                       → [RoundSummary]
//! GET  /rounds/{id}                  → Round (status, pk, submissions, evaluation, results)
//! GET  /rounds/{id}/pubkey           → { e3_id, public_key_hex, param_set, salary_cap }
//! POST /rounds/{id}/submit           { submission } → relayed on-chain (server pays gas)
//! POST /rounds          (admin)      { duration_secs? } → request a round through the program
//! POST /rounds/{id}/evaluate (admin) → evaluate + publish ciphertext output
//! ```

use actix_web::{web, HttpRequest, HttpResponse, Responder};
use alloy::primitives::U256;
use log::{info, warn};
use serde::{Deserialize, Serialize};
use serde_json::json;

use super::app_data::AppData;
use super::chain::RelayError;
use super::evaluator;
use super::models::{now_secs, Round, RoundStatus, RoundSummary, Submission, SubmissionPayload};
use super::repo::list_round_ids;
use crate::config::CONFIG;

pub fn setup_routes(cfg: &mut web::ServiceConfig) {
    cfg.route("/health", web::get().to(health))
        .route("/rounds", web::get().to(list_rounds))
        .route("/rounds", web::post().to(create_round))
        .route("/rounds/{id}", web::get().to(get_round))
        .route("/rounds/{id}/pubkey", web::get().to(get_pubkey))
        .route("/rounds/{id}/submit", web::post().to(submit))
        .route("/rounds/{id}/evaluate", web::post().to(evaluate));
}

fn err(status: u16, message: impl ToString) -> HttpResponse {
    HttpResponse::build(actix_web::http::StatusCode::from_u16(status).unwrap_or_default())
        .json(json!({ "error": message.to_string() }))
}

fn admin_ok(req: &HttpRequest) -> bool {
    if CONFIG.admin_key.is_empty() {
        return true;
    }
    req.headers()
        .get("x-admin-key")
        .and_then(|v| v.to_str().ok())
        .map(|v| v == CONFIG.admin_key)
        .unwrap_or(false)
}

async fn health(data: web::Data<AppData>) -> impl Responder {
    let block = data.chain.block_timestamp().await.ok();
    HttpResponse::Ok().json(json!({
        "ok": true,
        "chain_id": CONFIG.chain_id,
        "chain_time": block,
        "program": CONFIG.e3_program_address,
        "relayer": format!("{:#x}", data.chain.wallet),
        "salary_cap": CONFIG.salary_cap,
        "param_set": ckks_salary_program::PARAM_SET,
        "output_scale": ckks_salary_program::OUTPUT_SCALE,
    }))
}

async fn list_rounds(data: web::Data<AppData>) -> impl Responder {
    let mut out: Vec<RoundSummary> = Vec::new();
    for id in list_round_ids(&data.db) {
        if let Ok(Some(r)) = data.round(&id).get().await {
            out.push(RoundSummary::from(&r));
        }
    }
    out.reverse();
    HttpResponse::Ok().json(out)
}

async fn get_round(data: web::Data<AppData>, path: web::Path<String>) -> impl Responder {
    match data.round(path.into_inner()).get().await {
        Ok(Some(r)) => HttpResponse::Ok().json(r),
        Ok(None) => err(404, "round not found"),
        Err(e) => err(500, e),
    }
}

async fn get_pubkey(data: web::Data<AppData>, path: web::Path<String>) -> impl Responder {
    let id = path.into_inner();
    match data.round(&id).get().await {
        Ok(Some(r)) => match r.public_key_hex {
            Some(pk) => HttpResponse::Ok().json(json!({
                "e3_id": id,
                "public_key_hex": pk,
                "param_set": r.param_set,
                "salary_cap": r.salary_cap,
                "input_window": r.input_window,
                "status": r.status,
            })),
            None => err(425, "committee public key not published yet"),
        },
        Ok(None) => err(404, "round not found"),
        Err(e) => err(500, e),
    }
}

#[derive(Deserialize)]
struct SubmitBody {
    submission: SubmissionPayload,
}

#[derive(Serialize)]
struct SubmitResponse {
    accepted: bool,
    e3_id: String,
    index: u64,
    tx_hash: String,
    block_number: u64,
    gas_used: u64,
    u_commitment: String,
    m_commitment: String,
    relay_millis: u64,
}

/// Validate the shape locally before spending gas: ParamSet, public-input
/// counts, cross-leg commitment binding and the cap.
fn validate_shape(s: &SubmissionPayload, round: &Round) -> Result<(), String> {
    if let Some(ps) = s.param_set {
        if ps != round.param_set {
            return Err(format!(
                "submission is for paramSet {ps}, round runs paramSet {}",
                round.param_set
            ));
        }
    }
    if s.ct0.public_inputs.len() != 4
        || s.ct1.public_inputs.len() != 3
        || s.app_leg.public_inputs.len() != 2
    {
        return Err("public-input counts must be ct0=4, ct1=3, app=2".into());
    }
    let u0 = &s.ct0.public_inputs[3];
    let u1 = &s.ct1.public_inputs[2];
    if !u0.eq_ignore_ascii_case(u1) {
        return Err("u_commitment mismatch between the ct0 and ct1 legs".into());
    }
    let m0 = &s.ct0.public_inputs[2];
    let ma = &s.app_leg.public_inputs[1];
    if !m0.eq_ignore_ascii_case(ma) {
        return Err("m_commitment mismatch between the ct0 and app legs".into());
    }
    let cap = U256::from_str_radix(s.app_leg.public_inputs[0].trim_start_matches("0x"), 16)
        .map_err(|e| format!("bad cap word: {e}"))?;
    if cap != U256::from(round.salary_cap) {
        return Err(format!(
            "app leg cap {cap} != round cap {}",
            round.salary_cap
        ));
    }
    if s.ciphertext_hex.trim_start_matches("0x").is_empty() {
        return Err("empty ciphertext".into());
    }
    for (name, leg) in [("ct0", &s.ct0), ("ct1", &s.ct1), ("app", &s.app_leg)] {
        if leg.proof_hex.trim_start_matches("0x").len() < 64 {
            return Err(format!("{name} proof too short"));
        }
    }
    Ok(())
}

async fn submit(
    data: web::Data<AppData>,
    path: web::Path<String>,
    body: web::Json<SubmitBody>,
) -> impl Responder {
    let id = path.into_inner();
    let round = match data.round(&id).get().await {
        Ok(Some(r)) => r,
        Ok(None) => return err(404, "round not found"),
        Err(e) => return err(500, e),
    };
    if round.public_key_hex.is_none() {
        return err(425, "committee public key not published yet");
    }
    if round.status != RoundStatus::Open {
        return err(
            409,
            format!("round is {:?}; submissions closed", round.status),
        );
    }
    let s = &body.submission;
    if let Err(m) = validate_shape(s, &round) {
        return err(400, m);
    }
    let u = s.ct0.public_inputs[3].to_lowercase();
    if round.has_u_commitment(&u) {
        // Already accepted on-chain for this round: same answer the chain
        // would give (DuplicateSubmission), without spending a preflight.
        return HttpResponse::Conflict().json(json!({
            "error": RelayError::Duplicate(u.clone()).to_string(),
            "duplicate": true,
            "u_commitment": u,
            "source": "server-index",
        }));
    }
    let ciphertext = match hex::decode(s.ciphertext_hex.trim_start_matches("0x")) {
        Ok(b) => b,
        Err(e) => return err(400, format!("ciphertext hex: {e}")),
    };
    info!(
        "[e3_id={id}] relaying submission u_commitment={u} ({} bytes ct)",
        ciphertext.len()
    );
    let t = std::time::Instant::now();
    let e3_id = match U256::from_str_radix(&id, 10) {
        Ok(v) => v,
        Err(e) => return err(400, e),
    };
    let receipt = match data.chain.relay_submission(e3_id, s).await {
        Ok(r) => r,
        Err(RelayError::Duplicate(u)) => {
            warn!("[e3_id={id}] REJECTED duplicate u_commitment {u}");
            return HttpResponse::Conflict().json(json!({
                "error": RelayError::Duplicate(u.clone()).to_string(),
                "duplicate": true,
                "u_commitment": u,
                "source": "on-chain",
            }));
        }
        Err(RelayError::Reverted(m)) => {
            warn!("[e3_id={id}] relay REVERTED: {m}");
            return err(422, m);
        }
        Err(RelayError::Provider(m)) => {
            warn!("[e3_id={id}] relay provider error: {m}");
            return err(502, m);
        }
    };
    let relay_millis = t.elapsed().as_millis() as u64;
    let tx_hash = format!("{:#x}", receipt.transaction_hash);
    let block_number = receipt.block_number.unwrap_or_default();
    let gas_used = receipt.gas_used;
    let submission = Submission {
        index: 0,
        publisher: format!("{:#x}", data.chain.wallet),
        tx_hash: tx_hash.clone(),
        block_number,
        ciphertext_hash: format!("{:#x}", alloy::primitives::keccak256(&ciphertext)),
        m_commitment: s.ct0.public_inputs[2].to_lowercase(),
        u_commitment: u.clone(),
        ciphertext_bytes: ciphertext.len(),
        // The indexer flips this on VerifiedInputPublished; a successful
        // receipt already implies it (the tx cannot succeed without
        // emitting the event), so record it now.
        verified: true,
        gas_used: Some(gas_used),
        submitted_at: now_secs(),
    };
    let index = match data
        .round(&id)
        .add_submission(submission, &ciphertext)
        .await
    {
        Ok(i) => i,
        Err(e) => {
            return err(
                500,
                format!("relayed (tx {tx_hash}) but storing failed: {e}"),
            )
        }
    };
    info!(
        "[e3_id={id}] ACCEPTED on-chain #{index} tx={tx_hash} gas={gas_used} in {relay_millis} ms"
    );
    HttpResponse::Ok().json(SubmitResponse {
        accepted: true,
        e3_id: id,
        index,
        tx_hash,
        block_number,
        gas_used,
        u_commitment: u,
        m_commitment: s.ct0.public_inputs[2].to_lowercase(),
        relay_millis,
    })
}

#[derive(Deserialize, Default)]
struct CreateRoundBody {
    duration_secs: Option<u64>,
}

async fn create_round(
    req: HttpRequest,
    data: web::Data<AppData>,
    body: Option<web::Json<CreateRoundBody>>,
) -> impl Responder {
    if !admin_ok(&req) {
        return err(401, "admin key required");
    }
    let duration = body
        .and_then(|b| b.duration_secs)
        .unwrap_or(CONFIG.e3_duration);
    // Compute-provider params: the mock decryption verifier address padded
    // to 32 bytes is what `committee:new` sends; the CKKS program ignores it
    // (`validate` is pure), so an empty payload is accepted too.
    let compute_params = alloy::primitives::Bytes::new();
    let program_cap = match data.chain.salary_cap().await {
        Ok(c) => c,
        Err(e) => return err(502, format!("reading salaryCap: {e}")),
    };
    if program_cap != CONFIG.salary_cap {
        return err(
            500,
            format!(
                "program salaryCap {program_cap} != configured {}",
                CONFIG.salary_cap
            ),
        );
    }
    let t = std::time::Instant::now();
    match data
        .chain
        .request_round(
            CONFIG.e3_committee_size,
            ckks_salary_program::PARAM_SET,
            duration,
            compute_params,
        )
        .await
    {
        Ok((e3_id, tx, window)) => {
            let id = e3_id.to_string();
            let round = Round {
                e3_id: id.clone(),
                chain_id: CONFIG.chain_id,
                status: RoundStatus::Requested,
                program_address: CONFIG.e3_program_address.clone(),
                requester: format!("{:#x}", data.chain.wallet),
                param_set: ckks_salary_program::PARAM_SET,
                salary_cap: CONFIG.salary_cap,
                input_window: window,
                requested_at: now_secs(),
                request_tx_hash: Some(format!("{tx:#x}")),
                request_block: 0,
                committee: vec![],
                public_key_hex: None,
                key_published_at: None,
                submissions: vec![],
                evaluation: None,
                results: None,
                failure_reason: None,
            };
            // The indexer may already have stored it from E3Requested;
            // keep whichever is richer.
            let mut repo = data.round(&id);
            let stored = match repo.get().await {
                Ok(Some(mut existing)) => {
                    existing.request_tx_hash = Some(format!("{tx:#x}"));
                    existing
                }
                _ => round,
            };
            if let Err(e) = repo.set(&stored).await {
                return err(500, e);
            }
            info!(
                "[e3_id={id}] round requested tx={tx:#x} window={window:?} in {} ms",
                t.elapsed().as_millis()
            );
            HttpResponse::Ok().json(json!({
                "e3_id": id,
                "tx_hash": format!("{tx:#x}"),
                "input_window": window,
                "program": CONFIG.e3_program_address,
            }))
        }
        Err(e) => err(502, format!("request_e3 failed: {e}")),
    }
}

async fn evaluate(
    req: HttpRequest,
    data: web::Data<AppData>,
    path: web::Path<String>,
) -> impl Responder {
    if !admin_ok(&req) {
        return err(401, "admin key required");
    }
    let id = path.into_inner();
    match evaluator::evaluate_and_publish(
        data.store.clone(),
        &data.chain,
        &CONFIG.relin_key_dir,
        &id,
    )
    .await
    {
        Ok(rec) => HttpResponse::Ok().json(rec),
        Err(e) => err(409, e),
    }
}
