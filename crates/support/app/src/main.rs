// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use actix_web::{middleware::Logger, web, App, HttpResponse, HttpServer, Result as ActixResult};
use e3_compute_provider::FHEInputs;
use e3_support_types::{ComputeRequest, WebhookPayload};
use serde::Serialize;

#[derive(Serialize, Debug)]
struct ProcessingResponse {
    status: String,
    e3_id: u64,
}

async fn call_webhook(callback_url: &str, payload: &WebhookPayload) -> anyhow::Result<()> {
    let (e3_id, status_label, ciphertext_len, proof_len) = match payload {
        WebhookPayload::Completed {
            e3_id,
            ciphertext,
            proof,
        } => (*e3_id, "completed", ciphertext.len(), proof.len()),
        WebhookPayload::Failed { e3_id, error } => {
            println!("call_webhook() - status: failed, error: {}", error);
            (*e3_id, "failed", 0, 0)
        }
    };

    println!(
        "call_webhook() - status: {}, ciphertext len: {}, proof len: {}",
        status_label, ciphertext_len, proof_len
    );

    println!("Sending webhook to: {}", callback_url);

    let response = reqwest::Client::new()
        .post(callback_url)
        .json(payload)
        .send()
        .await?;

    println!("Webhook response status: {}", response.status());
    if !response.status().is_success() {
        let error_body = response.text().await?;
        println!("Webhook error response: {}", error_body);
        return Err(anyhow::anyhow!(
            "Webhook failed with status and body: {}",
            error_body
        ));
    }

    response.error_for_status()?;
    println!("✓ Webhook called successfully for E3 {}", e3_id);
    Ok(())
}

async fn run_computation_async(fhe_inputs: FHEInputs) -> anyhow::Result<(Vec<u8>, Vec<u8>)> {
    println!("running computation...");
    let result =
        tokio::task::spawn_blocking(move || e3_support_host::run_compute(fhe_inputs)).await?;

    match result {
        Ok((boundless_output, ciphertext)) => match boundless_output {
            e3_support_host::BoundlessOutput::Success { seal, .. } => {
                println!(
                    "have result from computation! seal len: {}, ciphertext len: {}",
                    seal.len(),
                    ciphertext.len()
                );
                Ok((seal, ciphertext))
            }
            e3_support_host::BoundlessOutput::Error { error } => {
                Err(anyhow::anyhow!("Boundless request failed: {}", error))
            }
        },
        Err(e3_support_host::ComputeError::BoundlessFailed(msg)) => {
            Err(anyhow::anyhow!("Boundless request failed: {}", msg))
        }
        Err(e3_support_host::ComputeError::Other(msg)) => {
            Err(anyhow::anyhow!("Computation error: {}", msg))
        }
    }
}

async fn process_computation_background(
    e3_id: u64,
    callback_url: &str,
    fhe_inputs: FHEInputs,
) -> anyhow::Result<()> {
    match run_computation_async(fhe_inputs).await {
        Ok((proof, ciphertext)) => {
            println!("computation finished!");
            println!("handling webhook delivery...");
            let payload = WebhookPayload::Completed {
                e3_id,
                ciphertext,
                proof,
            };
            call_webhook(callback_url, &payload).await?;
            println!("Computation completed for E3 {}", e3_id);
            Ok(())
        }
        Err(e) => {
            let error_msg = e.to_string();
            eprintln!("Computation failed for E3 {}: {}", e3_id, error_msg);

            let payload = WebhookPayload::Failed {
                e3_id,
                error: format!("Compute failed: {}", error_msg),
            };
            call_webhook(callback_url, &payload).await?;

            Err(e)
        }
    }
}

async fn handle_compute(req: web::Json<ComputeRequest>) -> ActixResult<HttpResponse> {
    println!("Processing computation...");
    let e3_id = req
        .e3_id
        .ok_or_else(|| actix_web::error::ErrorBadRequest("e3_id is required"))?;
    let callback_url = req
        .callback_url
        .clone()
        .ok_or_else(|| actix_web::error::ErrorBadRequest("callback_url is required"))?;
    let fhe_inputs = FHEInputs {
        params: req.params.clone(),
        ciphertexts: req.ciphertext_inputs.clone(),
    };

    println!("fhe_inputs.params = {:?}", fhe_inputs.params);
    let callback_url = callback_url
        .replace("localhost", "host.local")
        .replace("127.0.0.1", "host.local");

    // Process computation in background
    tokio::spawn(async move {
        if let Err(e) = process_computation_background(e3_id, &callback_url, fhe_inputs).await {
            eprintln!("✗ Background computation failed for E3 {}: {:?}", e3_id, e);
        }
    });
    Ok(HttpResponse::Ok().json(ProcessingResponse {
        status: "processing".to_string(),
        e3_id,
    }))
}

async fn handle_health_check() -> ActixResult<HttpResponse> {
    Ok(HttpResponse::Ok().json(ProcessingResponse {
        status: "healthy".to_string(),
        e3_id: 0,
    }))
}

#[actix_web::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();
    let bind_addr = "0.0.0.0:13151";
    let server = HttpServer::new(move || {
        App::new()
            .wrap(Logger::default())
            .route("/run_compute", web::post().to(handle_compute))
            .route("/health", web::get().to(handle_health_check))
            .route("/health", web::head().to(handle_health_check))
    })
    .bind(bind_addr)?;
    println!("🚀 FHE Compute Service listening on http://{}", bind_addr);
    server.run().await.map_err(Into::into)
}
