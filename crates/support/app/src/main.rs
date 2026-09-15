// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use actix_web::{middleware::Logger, web, App, HttpResponse, HttpServer, Result as ActixResult};
use e3_compute_provider::FHEInputs;
use e3_compute_provider::PublishedData;
use e3_support_types::{ComputeDomain, ComputeRequest, WebhookPayload};
use serde::Serialize;
use std::sync::{Arc, OnceLock};
use std::time::Duration;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

#[derive(Serialize, Debug)]
struct ProcessingResponse {
    status: String,
    e3_id: String,
}

async fn call_webhook(callback_url: &str, payload: &WebhookPayload) -> anyhow::Result<()> {
    let (e3_id, status_label, ciphertext_len, commitment_len, proof_len) = match payload {
        WebhookPayload::Completed {
            e3_id,
            ciphertext,
            ciphertext_commitment,
            proof,
        } => (
            e3_id,
            "completed",
            ciphertext.len(),
            ciphertext_commitment.len(),
            proof.len(),
        ),
        WebhookPayload::Failed { e3_id, error } => {
            println!("call_webhook() - status: failed, error: {}", error);
            (e3_id, "failed", 0, 0, 0)
        }
    };

    println!(
        "call_webhook() - status: {}, ciphertext len: {}, commitment len: {}, proof len: {}",
        status_label, ciphertext_len, commitment_len, proof_len
    );

    println!("Sending webhook to: {}", callback_url);

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()?;
    let mut last_error = None;

    for attempt in 1_u32..=5 {
        match client.post(callback_url).json(payload).send().await {
            Ok(response) if response.status().is_success() => {
                println!("Webhook response status: {}", response.status());
                println!("✓ Webhook called successfully for E3 {}", e3_id);
                return Ok(());
            }
            Ok(response) => {
                let status = response.status();
                let retryable = status.is_server_error()
                    || status == reqwest::StatusCode::REQUEST_TIMEOUT
                    || status == reqwest::StatusCode::TOO_MANY_REQUESTS;
                let error_body = response
                    .text()
                    .await
                    .unwrap_or_else(|error| format!("could not read response body: {error}"));
                let error = anyhow::anyhow!("webhook returned {status}: {error_body}");
                if !retryable {
                    return Err(error);
                }
                last_error = Some(error);
            }
            Err(error) => last_error = Some(error.into()),
        }

        if attempt < 5 {
            let delay = Duration::from_secs(1_u64 << (attempt - 1));
            println!(
                "Webhook attempt {attempt} failed; retrying in {} seconds",
                delay.as_secs()
            );
            tokio::time::sleep(delay).await;
        }
    }

    Err(last_error.unwrap_or_else(|| anyhow::anyhow!("webhook delivery failed")))
}

async fn run_computation_async(
    fhe_inputs: FHEInputs,
    domain: ComputeDomain,
    published: Vec<PublishedData>,
) -> anyhow::Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    println!("running computation...");
    let result = tokio::task::spawn_blocking(move || {
        e3_support_host::run_compute(fhe_inputs, domain, published)
    })
    .await?;

    match result {
        Ok((boundless_output, ciphertext)) => match boundless_output {
            e3_support_host::BoundlessOutput::Success { result, seal, .. } => {
                anyhow::ensure!(
                    result.ciphertext_commitment.len() == 32,
                    "Boundless journal ciphertext commitment must be 32 bytes"
                );
                println!(
                    "have result from computation! seal len: {}, ciphertext len: {}, commitment len: {}",
                    seal.len(),
                    ciphertext.len(),
                    result.ciphertext_commitment.len()
                );
                let proof = e3_support_host::encode_compute_proof(&seal, &result)
                    .map_err(|error| anyhow::anyhow!("invalid compute proof: {error:?}"))?;
                Ok((proof, ciphertext, result.ciphertext_commitment))
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
    e3_id: String,
    callback_url: &str,
    fhe_inputs: FHEInputs,
    domain: ComputeDomain,
    published: Vec<PublishedData>,
    // Held for the whole computation and dropped with it, which is what frees the slot. Taking it
    // by value rather than borrowing is deliberate: the task is detached, so nothing else is alive
    // to own it.
    _permit: OwnedSemaphorePermit,
) -> anyhow::Result<()> {
    match run_computation_async(fhe_inputs, domain, published).await {
        Ok((proof, ciphertext, ciphertext_commitment)) => {
            println!("computation finished!");
            println!("handling webhook delivery...");
            let payload = WebhookPayload::Completed {
                e3_id: e3_id.clone(),
                ciphertext,
                ciphertext_commitment,
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
                e3_id: e3_id.clone(),
                error: format!("Compute failed: {}", error_msg),
            };
            call_webhook(callback_url, &payload).await?;

            Err(e)
        }
    }
}

/// Whether callbacks to addresses only reachable from inside the deployment are permitted.
///
/// Off by default. Local development legitimately posts to a host on the same machine, so there has
/// to be a way in, but it must be a deliberate one rather than the default.
fn allow_private_callbacks() -> bool {
    matches!(
        std::env::var("ALLOW_PRIVATE_CALLBACKS")
            .unwrap_or_default()
            .as_str(),
        "1" | "true" | "TRUE" | "yes" | "YES"
    )
}

/// Validates a caller-supplied callback URL before this server makes a request to it.
///
/// Without this, `callback_url` is a server-side request forgery primitive: the caller chooses a
/// destination and this server dials it, which reaches cloud metadata (169.254.169.254), loopback,
/// and anything else inside the network the server sits in.
///
/// Literal addresses are checked exhaustively. A hostname is checked by name only, so a name that
/// resolves to a private address still passes and DNS rebinding remains possible — closing that
/// needs resolution at connect time and a pinned socket.
fn validate_callback_url(raw: &str) -> ActixResult<()> {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    let url = reqwest::Url::parse(raw)
        .map_err(|e| actix_web::error::ErrorBadRequest(format!("invalid callback_url: {e}")))?;

    if !matches!(url.scheme(), "http" | "https") {
        return Err(actix_web::error::ErrorBadRequest(
            "callback_url must use http or https",
        ));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(actix_web::error::ErrorBadRequest(
            "callback_url must not contain credentials",
        ));
    }

    if allow_private_callbacks() {
        return Ok(());
    }

    // Loopback is deliberately NOT treated as internal. The escalation worth guarding is reaching
    // hosts the caller cannot reach itself — cloud metadata, RFC1918 services, .internal names.
    // Loopback is the machine this server already runs on, and it is how every local deployment
    // posts its webhook. Note this runs BEFORE the localhost -> host.local rewrite below, so that
    // rewrite is unaffected by `.local` remaining blocked.
    fn v4_is_internal(ip: Ipv4Addr) -> bool {
        if ip.is_loopback() {
            return false;
        }
        ip.is_private()
            || ip.is_link_local()
            || ip.is_broadcast()
            || ip.is_documentation()
            || ip.is_unspecified()
            || ip.octets()[0] == 0
            || (ip.octets()[0] == 100 && (64..128).contains(&ip.octets()[1]))
    }

    fn v6_is_internal(ip: Ipv6Addr) -> bool {
        if let Some(mapped) = ip.to_ipv4_mapped() {
            return v4_is_internal(mapped);
        }
        if ip.is_loopback() {
            return false;
        }
        ip.is_unspecified()
            || (ip.segments()[0] & 0xfe00) == 0xfc00
            || (ip.segments()[0] & 0xffc0) == 0xfe80
    }

    let internal = match url.host_str() {
        Some(host) => {
            let bare = host.trim_start_matches('[').trim_end_matches(']');
            match bare.parse::<IpAddr>() {
                Ok(IpAddr::V4(ip)) => v4_is_internal(ip),
                Ok(IpAddr::V6(ip)) => v6_is_internal(ip),
                Err(_) => {
                    // `localhost` resolves to loopback, and is allowed for the same reason.
                    let lowered = bare.to_ascii_lowercase();
                    lowered.ends_with(".local") || lowered.ends_with(".internal")
                }
            }
        }
        None => true,
    };

    if internal {
        return Err(actix_web::error::ErrorBadRequest(
            "callback_url must not point at a private, loopback or link-local address; \
             set ALLOW_PRIVATE_CALLBACKS=1 to permit it for local development",
        ));
    }

    Ok(())
}

/// How many computations may be in flight at once.
///
/// Proving is the most expensive thing this process does, and the handler previously spawned one
/// detached task per request with nothing bounding them: a caller could open as many as they liked
/// and exhaust CPU, memory, blocking workers and Boundless submissions together. One at a time by
/// default, because a single proof already saturates the machine.
fn max_concurrent_computations() -> usize {
    std::env::var("MAX_CONCURRENT_COMPUTATIONS")
        .ok()
        .and_then(|value| value.parse().ok())
        .filter(|value| *value > 0)
        .unwrap_or(1)
}

/// Permits for in-flight computations, sized once on first use.
static COMPUTE_SLOTS: OnceLock<Arc<Semaphore>> = OnceLock::new();

fn compute_slots() -> &'static Arc<Semaphore> {
    COMPUTE_SLOTS.get_or_init(|| Arc::new(Semaphore::new(max_concurrent_computations())))
}

/// Width of the slot an E3 program packs into its published metadata, in bytes.
///
/// Mirrors `abi.encodePacked(address, uint40)` — the convention the starter contract uses and the
/// one `crates/program-server` implements. Duplicated rather than shared because this workspace
/// builds standalone, outside the root workspace, so it cannot depend on that crate.
const SLOT_BYTES: usize = 20;
/// Width of the parent index in the same packing.
const PARENT_BYTES: usize = 5;
/// Largest parent index that fits `PARENT_BYTES`.
const MAX_PARENT: u64 = (1u64 << (8 * PARENT_BYTES as u64)) - 1;

/// Rebuilds what the E3 program published alongside each ciphertext.
///
/// Both widths are checked rather than coerced. This endpoint takes JSON from the network and the
/// packing is fixed-width: a slot of the wrong length shifts every byte after it, and a parent
/// above `uint40` would be truncated into a different, valid-looking index. Either produces
/// metadata the E3 program never published, and the only symptom is an input root the guest
/// derives and the contract rejects.
fn published_from(req: &ComputeRequest) -> ActixResult<Vec<PublishedData>> {
    if req.input_commitments.is_empty()
        && req.input_slots.is_empty()
        && req.input_parents.is_empty()
    {
        return Ok(Vec::new());
    }

    if req.input_commitments.len() != req.ciphertext_inputs.len() {
        return Err(actix_web::error::ErrorBadRequest(
            "input_commitments must have one entry per ciphertext input",
        ));
    }
    if !req.input_slots.is_empty() && req.input_slots.len() != req.input_commitments.len() {
        return Err(actix_web::error::ErrorBadRequest(
            "input_slots must have one entry per ciphertext input",
        ));
    }
    if req.input_slots.len() != req.input_parents.len() {
        return Err(actix_web::error::ErrorBadRequest(
            "input_slots and input_parents must have the same length",
        ));
    }

    req.input_commitments
        .iter()
        .enumerate()
        .map(|(index, hex_commitment)| {
            let bytes = hex::decode(hex_commitment.trim_start_matches("0x"))
                .map_err(|e| actix_web::error::ErrorBadRequest(format!("bad commitment: {e}")))?;
            let commitment: [u8; 32] = bytes.try_into().map_err(|_| {
                actix_web::error::ErrorBadRequest("each commitment must be 32 bytes")
            })?;

            let mut metadata = Vec::new();
            if let Some(hex_slot) = req.input_slots.get(index) {
                let slot = hex::decode(hex_slot.trim_start_matches("0x"))
                    .map_err(|e| actix_web::error::ErrorBadRequest(format!("bad slot: {e}")))?;
                if slot.len() != SLOT_BYTES {
                    return Err(actix_web::error::ErrorBadRequest(format!(
                        "each slot must be {SLOT_BYTES} bytes, got {}",
                        slot.len()
                    )));
                }
                metadata.extend_from_slice(&slot);

                let parent = req.input_parents.get(index).copied().unwrap_or_default();
                if parent > MAX_PARENT {
                    return Err(actix_web::error::ErrorBadRequest(format!(
                        "each parent must fit in {PARENT_BYTES} bytes (at most {MAX_PARENT}), got {parent}"
                    )));
                }
                metadata.extend_from_slice(&parent.to_be_bytes()[8 - PARENT_BYTES..]);
            }

            Ok(PublishedData {
                commitment: Some(commitment),
                metadata,
            })
        })
        .collect()
}

async fn handle_compute(req: web::Json<ComputeRequest>) -> ActixResult<HttpResponse> {
    println!("Processing computation...");
    let e3_id = req
        .e3_id
        .clone()
        .ok_or_else(|| actix_web::error::ErrorBadRequest("e3_id is required"))?;
    let callback_url = req
        .callback_url
        .clone()
        .ok_or_else(|| actix_web::error::ErrorBadRequest("callback_url is required"))?;
    validate_callback_url(&callback_url)?;

    // Admission control. Refused up front with 429 rather than queued, so a caller learns
    // immediately instead of holding a connection behind an unbounded backlog.
    let permit = Arc::clone(compute_slots())
        .try_acquire_owned()
        .map_err(|_| {
            actix_web::error::ErrorTooManyRequests(
                "a computation is already running; retry once it completes",
            )
        })?;
    let fhe_inputs = FHEInputs {
        params: req.params.clone(),
        ciphertexts: req.ciphertext_inputs.clone(),
    };
    let published = published_from(&req)?;
    let domain = ComputeDomain::new(
        req.chain_id,
        &req.interfold_address,
        &e3_id,
        &req.encryption_scheme_id,
        &req.committee_public_key_hash,
    )
    .map_err(actix_web::error::ErrorBadRequest)?;

    println!("fhe_inputs.params = {:?}", fhe_inputs.params);
    let callback_url = callback_url
        .replace("localhost", "host.local")
        .replace("127.0.0.1", "host.local");

    // Process computation in background
    let background_e3_id = e3_id.clone();
    tokio::spawn(async move {
        if let Err(e) = process_computation_background(
            background_e3_id.clone(),
            &callback_url,
            fhe_inputs,
            domain,
            published,
            permit,
        )
        .await
        {
            eprintln!(
                "✗ Background computation failed for E3 {}: {:?}",
                background_e3_id, e
            );
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
        e3_id: "0".to_string(),
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
