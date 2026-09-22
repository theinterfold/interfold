// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

mod types;

use actix_web::{middleware::Logger, web, App, HttpResponse, HttpServer, Result as ActixResult};
use alloy_primitives::U256;
use anyhow::{Context, Result};
use e3_bfv_client::compute_ct_commitment;
use e3_compute_provider::{FHEInputs, PublishedData};
use e3_fhe_params::decode_bfv_params_arc;
use serde::Serialize;
use std::{future::Future, pin::Pin, sync::Arc, time::Duration};
use tokio::sync::Semaphore;
use types::{ComputeRequest, WebhookPayload};

#[derive(Serialize, Debug)]
struct ProcessingResponse {
    status: String,
    e3_id: String,
}

type RunnerResult = Result<(Vec<u8>, Vec<u8>)>;
type Runner =
    dyn Fn(ComputeJob) -> Pin<Box<dyn Future<Output = RunnerResult> + Send>> + Send + Sync;

#[derive(Clone, Debug)]
pub struct ComputeDomain {
    pub chain_id: u64,
    pub verifying_contract: [u8; 20],
    pub e3_id: [u8; 32],
    pub encryption_scheme_id: [u8; 32],
    pub committee_public_key_hash: [u8; 32],
}

impl ComputeDomain {
    fn new(
        chain_id: u64,
        interfold_address: &str,
        e3_id: &str,
        encryption_scheme_id: &[u8],
        committee_public_key_hash: &[u8],
    ) -> Result<Self, String> {
        Ok(Self {
            chain_id,
            verifying_contract: fixed(
                &hex::decode(interfold_address.trim_start_matches("0x"))
                    .map_err(|error| format!("invalid Interfold address: {error}"))?,
                "Interfold address",
            )?,
            e3_id: e3_id
                .parse::<U256>()
                .map_err(|error| format!("invalid E3 ID: {error}"))?
                .to_be_bytes(),
            encryption_scheme_id: fixed(encryption_scheme_id, "encryption scheme ID")?,
            committee_public_key_hash: fixed(
                committee_public_key_hash,
                "committee public key hash",
            )?,
        })
    }
}

/// The width of one slot address in published metadata: a Solidity `address`.
const SLOT_BYTES: usize = 20;

/// The width of one parent index in published metadata: a Solidity `uint40`.
const PARENT_BYTES: usize = 5;

/// The largest parent index that fits in [`PARENT_BYTES`].
const MAX_PARENT: u64 = (1 << (8 * PARENT_BYTES as u64)) - 1;

fn fixed<const N: usize>(value: &[u8], name: &str) -> Result<[u8; N], String> {
    value
        .try_into()
        .map_err(|_| format!("{name} must be {N} bytes"))
}

pub struct ComputeJob {
    pub inputs: FHEInputs,
    /// What the E3 program published alongside each ciphertext, in the same order. Empty when the
    /// program publishes nothing beyond the ciphertexts.
    pub published: Vec<PublishedData>,
    pub domain: ComputeDomain,
}

#[derive(Clone)]
pub struct E3ProgramServerBuilder {
    runner: Arc<Runner>,
    port: Option<u16>,
    host: Option<String>,
    localhost_rewrite: Option<String>,
    max_concurrent_jobs: usize,
}

impl E3ProgramServerBuilder {
    /// Create a new builder with a computation callback
    pub fn new<F, Fut>(callback: F) -> Self
    where
        F: Fn(ComputeJob) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = RunnerResult> + Send + 'static,
    {
        Self {
            runner: Arc::new(move |inputs| Box::pin(callback(inputs))),
            port: None,
            host: None,
            localhost_rewrite: None,
            max_concurrent_jobs: 1,
        }
    }

    /// Set the port number (default: 13151)
    pub fn with_port(mut self, port: u16) -> Self {
        self.port = Some(port);
        self
    }

    /// Set the host address (default: "0.0.0.0")
    pub fn with_host<S: Into<String>>(mut self, host: S) -> Self {
        self.host = Some(host.into());
        self
    }

    /// Server will rewrite localhost callbacks to whatever is provided as an argument eg. "host.local". This is usefull when running in a Docker container which does not have direct access to the host
    pub fn with_localhost_rewrite(mut self, rewrite: &str) -> Self {
        self.localhost_rewrite = Some(rewrite.to_string());
        self
    }

    /// Bound the number of computations that may execute concurrently.
    pub fn with_max_concurrent_jobs(mut self, max_concurrent_jobs: usize) -> Self {
        self.max_concurrent_jobs = max_concurrent_jobs;
        self
    }

    /// Build the E3ProgramServer
    pub fn build(self) -> Result<E3ProgramServer> {
        anyhow::ensure!(
            self.max_concurrent_jobs > 0,
            "max concurrent jobs must be greater than zero"
        );
        let webhook_client = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(30))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .context("failed to build webhook client")?;
        Ok(E3ProgramServer {
            runner: self.runner,
            port: self.port.unwrap_or(13151),
            host: self.host.unwrap_or_else(|| "0.0.0.0".to_string()),
            localhost_rewrite: self.localhost_rewrite,
            webhook_client,
            jobs: Arc::new(Semaphore::new(self.max_concurrent_jobs)),
        })
    }
}

#[derive(Clone)]
pub struct E3ProgramServer {
    runner: Arc<Runner>,
    port: u16,
    host: String,
    localhost_rewrite: Option<String>,
    webhook_client: reqwest::Client,
    jobs: Arc<Semaphore>,
}

impl E3ProgramServer {
    /// Create a new builder for E3ProgramServer with a computation callback
    pub fn builder<F, Fut>(callback: F) -> E3ProgramServerBuilder
    where
        F: Fn(ComputeJob) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = RunnerResult> + Send + 'static,
    {
        E3ProgramServerBuilder::new(callback)
    }

    /// Get the configured port
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Get the configured host
    pub fn host(&self) -> &str {
        &self.host
    }

    /// Get the bind address as a string
    pub fn bind_address(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }

    /// Run the HTTP server
    pub async fn run(&self) -> Result<()> {
        let bind_addr = self.bind_address();
        let config = AppConfig {
            runner: Arc::clone(&self.runner),
            localhost_rewrite: self.localhost_rewrite.clone(),
            webhook_client: self.webhook_client.clone(),
            jobs: Arc::clone(&self.jobs),
        };
        let server = HttpServer::new(move || {
            App::new()
                .app_data(web::Data::new(config.clone()))
                .app_data(web::JsonConfig::default().limit(10 * 1024 * 1024)) // 10MB for prod params
                .wrap(Logger::default())
                .route("/run_compute", web::post().to(handle_compute))
                .route("/health", web::get().to(handle_health_check))
                .route("/health", web::head().to(handle_health_check))
        })
        .bind(&bind_addr)?;

        println!("🚀 E3 Program Server listening on http://{}", bind_addr);
        server.run().await.map_err(Into::into)
    }
}

#[derive(Clone)]
pub struct AppConfig {
    pub runner: Arc<Runner>,
    pub localhost_rewrite: Option<String>,
    webhook_client: reqwest::Client,
    jobs: Arc<Semaphore>,
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

/// Rejects a callback host that is not reachable from the public internet.
///
/// This endpoint takes a URL from the network and then makes a request to it, which is a
/// server-side request forgery primitive: without this, a caller can aim the callback at a cloud
/// metadata service (169.254.169.254), at loopback, or at anything inside the private network the
/// server sits in, and read the effect through the response or the side effects.
///
/// Literal addresses are checked exhaustively. A hostname is checked by name only — a name that
/// resolves to a private address still passes, and DNS rebinding remains possible. Closing that
/// needs resolution at connect time and a pinned socket; this guard is the cheap part, not the
/// whole answer.
fn ensure_public_callback_host(url: &reqwest::Url) -> Result<()> {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    if allow_private_callbacks() {
        return Ok(());
    }

    // Loopback is deliberately NOT treated as internal.
    //
    // The escalation that makes SSRF worth guarding is reaching hosts the caller cannot reach
    // itself: cloud metadata at 169.254.169.254, RFC1918 services on the deployment's LAN, names
    // under .internal. Loopback is the machine this server already runs on, and anyone who can post
    // to this endpoint can address that host directly, so bouncing a request off its own loopback
    // adds little reach. It is not zero risk — a localhost-only admin port is still a target — but
    // it is a different class from pivoting into a private network.
    //
    // It is also how every local and CI deployment works: the callback is a webhook on the same
    // host, and `with_localhost_rewrite` is unset by default. Rejecting it broke the CRISP
    // end-to-end run for no security gain that a caller could not already obtain.
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
            // 100.64.0.0/10, carrier-grade NAT.
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
            // fc00::/7 unique-local, fe80::/10 link-local.
            || (ip.segments()[0] & 0xfe00) == 0xfc00
            || (ip.segments()[0] & 0xffc0) == 0xfe80
    }

    let internal = match url.host_str() {
        Some(host) => {
            // `host_str` keeps the brackets on an IPv6 literal, which `IpAddr` will not parse.
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

    anyhow::ensure!(
        !internal,
        "callback URL must not point at a private, loopback or link-local address; \
         set ALLOW_PRIVATE_CALLBACKS=1 to permit it for local development"
    );

    Ok(())
}

fn parse_http_url(value: &str, label: &str) -> Result<reqwest::Url> {
    let url = reqwest::Url::parse(value).with_context(|| format!("invalid {label}"))?;
    anyhow::ensure!(
        matches!(url.scheme(), "http" | "https"),
        "{label} must use http or https"
    );
    anyhow::ensure!(url.host_str().is_some(), "{label} must contain a host");
    anyhow::ensure!(
        url.username().is_empty() && url.password().is_none(),
        "{label} must not contain credentials"
    );
    Ok(url)
}

fn validated_callback_url(
    callback_url: &str,
    localhost_rewrite: Option<&str>,
) -> Result<reqwest::Url> {
    let mut callback = parse_http_url(callback_url, "callback URL")?;
    let mut rewritten = false;
    if matches!(callback.host_str(), Some("localhost" | "127.0.0.1")) {
        if let Some(rewrite) = localhost_rewrite {
            callback
                .set_host(Some(rewrite))
                .map_err(|_| anyhow::anyhow!("invalid localhost rewrite host"))?;
            rewritten = true;
        }
    }
    anyhow::ensure!(
        callback.fragment().is_none(),
        "callback URL must not contain a fragment"
    );

    // The rewrite target is operator configuration rather than caller input, and it exists so a
    // local deployment can post to its own host. Exempting it keeps that path working without
    // opening the general case: a caller who did not name an exact local host is still checked.
    if !rewritten {
        ensure_public_callback_host(&callback)?;
    }

    Ok(callback)
}

async fn call_webhook(
    client: &reqwest::Client,
    callback_url: &reqwest::Url,
    payload: WebhookPayload,
) -> Result<()> {
    let e3_id = match &payload {
        WebhookPayload::Completed { e3_id, .. } => e3_id,
        WebhookPayload::Failed { e3_id, .. } => e3_id,
    };

    match &payload {
        WebhookPayload::Completed {
            ciphertext, proof, ..
        } => {
            println!(
                "call_webhook() - status: Completed, ciphertext len: {}, proof len: {}",
                ciphertext.len(),
                proof.len()
            );
        }
        WebhookPayload::Failed { error, .. } => {
            println!("call_webhook() - status: Failed, error: {}", error);
        }
    }

    let response = client
        .post(callback_url.clone())
        .json(&payload)
        .send()
        .await?;

    println!("Webhook response status: {}", response.status());
    if !response.status().is_success() {
        return Err(anyhow::anyhow!(
            "Webhook failed with status {}",
            response.status()
        ));
    }

    response.error_for_status()?;
    println!("✓ Webhook called successfully for E3 {}", e3_id);
    Ok(())
}

async fn handle_webhook_delivery(
    client: &reqwest::Client,
    callback_url: &reqwest::Url,
    payload: WebhookPayload,
) -> Result<()> {
    println!("handle_webhook_delivery()");
    call_webhook(client, callback_url, payload).await?;
    println!("✓ Webhook sent successfully");
    Ok(())
}

async fn process_computation_background(
    runner: Arc<Runner>,
    e3_id: String,
    webhook_client: reqwest::Client,
    callback_url: reqwest::Url,
    job: ComputeJob,
) -> Result<()> {
    let fhe_inputs = job.inputs.clone();
    match runner(job).await {
        Ok((proof, ciphertext)) => {
            println!("computation finished!");
            // Compute the SAFE commitment for the produced ciphertext so the
            // downstream template server can forward it to
            // `Interfold.publishCiphertextOutput`.
            let params = decode_bfv_params_arc(&fhe_inputs.params)
                .context("failed to decode BFV params for commitment")?;
            let ciphertext_commitment = compute_ct_commitment(
                ciphertext.clone(),
                params.degree(),
                params.plaintext(),
                params.moduli().to_vec(),
            )
            .context("failed to compute ciphertext commitment")?;
            println!("handling webhook delivery...");
            let payload = WebhookPayload::Completed {
                e3_id: e3_id.clone(),
                ciphertext,
                proof,
                ciphertext_commitment,
            };
            handle_webhook_delivery(&webhook_client, &callback_url, payload).await?;
            println!("✓ Computation completed for E3 {}", e3_id);
            Ok(())
        }
        Err(e) => {
            let error_msg = e.to_string();
            eprintln!("Computation failed for E3 {}: {}", e3_id, error_msg);

            let payload = WebhookPayload::Failed {
                e3_id: e3_id.clone(),
                error: format!("Compute failed: {}", error_msg),
            };
            handle_webhook_delivery(&webhook_client, &callback_url, payload).await?;

            Err(e)
        }
    }
}

async fn handle_compute(
    config: web::Data<AppConfig>,
    req: web::Json<ComputeRequest>,
) -> ActixResult<HttpResponse> {
    println!("Processing computation...");
    let e3_id = req
        .e3_id
        .clone()
        .ok_or_else(|| actix_web::error::ErrorBadRequest("e3_id is required"))?;

    let callback_url = req
        .callback_url
        .clone()
        .ok_or_else(|| actix_web::error::ErrorBadRequest("callback_url is required"))?;

    let published = req
        .input_commitments
        .iter()
        .enumerate()
        .map(|(index, hex_commitment)| {
            let raw = hex::decode(hex_commitment.trim_start_matches("0x"))
                .map_err(|e| actix_web::error::ErrorBadRequest(format!("bad commitment: {e}")))?;
            let commitment = <[u8; 32]>::try_from(raw.as_slice()).map_err(|_| {
                actix_web::error::ErrorBadRequest("each commitment must be 32 bytes")
            })?;

            // The metadata is opaque here — what a policy reads out of it is the E3 program's
            // business. It is assembled in the order the program packs it, which for CRISP is
            // `abi.encodePacked(address, uint40)`.
            //
            // Both widths are checked rather than coerced. This endpoint takes JSON from the
            // network, and the packing is fixed-width: a slot of the wrong length shifts every
            // byte after it, and a parent above `uint40` would be truncated into a different,
            // valid-looking index. Either produces metadata the E3 program never published, and
            // the only symptom is an input root the guest derives and the contract rejects.
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
        .collect::<ActixResult<Vec<PublishedData>>>()?;

    // One-sided metadata is a caller bug that would otherwise fall through to the default policy
    // and silently produce a root the E3 program rejects.
    if req.input_commitments.is_empty() != req.input_slots.is_empty() {
        return Err(actix_web::error::ErrorBadRequest(
            "input_commitments and input_slots must be supplied together",
        ));
    }
    if req.input_slots.len() != req.input_parents.len() {
        return Err(actix_web::error::ErrorBadRequest(
            "input_slots and input_parents must have the same length",
        ));
    }

    if !published.is_empty() && published.len() != req.ciphertext_inputs.len() {
        return Err(actix_web::error::ErrorBadRequest(
            "input_commitments must have one entry per ciphertext input",
        ));
    }
    if !req.input_slots.is_empty() && req.input_slots.len() != req.ciphertext_inputs.len() {
        return Err(actix_web::error::ErrorBadRequest(
            "input_slots must have one entry per ciphertext input",
        ));
    }

    let fhe_inputs = FHEInputs {
        params: req.params.clone(),
        ciphertexts: req.ciphertext_inputs.clone(),
        committee_key: req.committee_public_key.clone(),
    };
    let domain = ComputeDomain::new(
        req.chain_id,
        &req.interfold_address,
        &e3_id,
        &req.encryption_scheme_id,
        &req.committee_public_key_hash,
    )
    .map_err(actix_web::error::ErrorBadRequest)?;
    let job = ComputeJob {
        inputs: fhe_inputs,
        published,
        domain,
    };

    let callback_url = validated_callback_url(&callback_url, config.localhost_rewrite.as_deref())
        .map_err(actix_web::error::ErrorBadRequest)?;
    let permit = Arc::clone(&config.jobs)
        .try_acquire_owned()
        .map_err(|_| actix_web::error::ErrorTooManyRequests("compute capacity exhausted"))?;
    let runner = config.runner.clone();
    let webhook_client = config.webhook_client.clone();
    let background_e3_id = e3_id.clone();
    tokio::spawn(async move {
        let _permit = permit;
        if let Err(e) = process_computation_background(
            runner,
            background_e3_id.clone(),
            webhook_client,
            callback_url,
            job,
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

#[cfg(test)]
mod server_tests {
    use super::*;

    #[test]
    fn compute_domain_preserves_ids_larger_than_u64() {
        let domain = ComputeDomain::new(
            1,
            "0x1111111111111111111111111111111111111111",
            "18446744073709551616",
            &[0x22; 32],
            &[0x33; 32],
        )
        .unwrap();

        assert_eq!(domain.e3_id[23], 1);
        assert!(domain.e3_id[..23].iter().all(|byte| *byte == 0));
        assert!(domain.e3_id[24..].iter().all(|byte| *byte == 0));
    }

    #[test]
    fn callback_validation_accepts_http_origins_and_rejects_unsafe_urls() {
        assert!(validated_callback_url("https://callback.example:8443/results/1", None).is_ok());
        assert!(validated_callback_url("file:///etc/passwd", None).is_err());
        assert!(validated_callback_url("https://user:pass@example.com/result", None).is_err());
        assert!(validated_callback_url("https://example.com/result#fragment", None).is_err());

        // This endpoint dials whatever it is given, so a caller must not be able to aim it inside
        // the deployment. `metadata.internal` was previously accepted; it is the canonical target.
        assert!(validated_callback_url("https://metadata.internal:8443/latest", None).is_err());
        assert!(validated_callback_url("http://169.254.169.254/latest/meta-data", None).is_err());
        assert!(validated_callback_url("http://10.0.0.5/hook", None).is_err());
        assert!(validated_callback_url("http://192.168.1.10/hook", None).is_err());
        assert!(validated_callback_url("http://[fd00::1]/hook", None).is_err());
        assert!(validated_callback_url("http://100.64.0.1/hook", None).is_err());

        // Loopback is allowed: it reaches only the host this server already runs on, and it is how
        // every local and CI deployment delivers its webhook.
        assert!(validated_callback_url("http://127.0.0.1/hook", None).is_ok());
        assert!(validated_callback_url("http://[::1]/hook", None).is_ok());
        assert!(validated_callback_url("http://localhost:4000/hook", None).is_ok());
    }

    #[test]
    fn builder_rejects_zero_capacity_and_configures_the_job_limit() {
        let zero = E3ProgramServer::builder(|_| async { Ok((vec![], vec![])) })
            .with_max_concurrent_jobs(0)
            .build();
        assert!(zero.is_err());

        let server = E3ProgramServer::builder(|_| async { Ok((vec![], vec![])) })
            .with_max_concurrent_jobs(2)
            .build()
            .unwrap();
        assert_eq!(server.jobs.available_permits(), 2);
    }

    #[test]
    fn localhost_rewrite_changes_only_an_exact_local_host() {
        let rewritten =
            validated_callback_url("http://127.0.0.1:8080/result", Some("host.local")).unwrap();
        assert_eq!(rewritten.as_str(), "http://host.local:8080/result");
        let unchanged =
            validated_callback_url("http://localhost.attacker:8080/result", Some("host.local"))
                .unwrap();
        assert_eq!(unchanged.as_str(), "http://localhost.attacker:8080/result");
    }
}
