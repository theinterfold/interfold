// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use actix_web::{middleware::Logger, web, App, HttpResponse, HttpServer, Result as ActixResult};
use anyhow::Context;
use e3_compute_provider::FHEInputs;
use e3_support_types::{ComputeRequest, WebhookPayload};
use reqwest::header::HOST;
use serde::Serialize;
use std::net::IpAddr;
use std::sync::OnceLock;
use std::time::Duration;

#[derive(Serialize, Debug)]
struct ProcessingResponse {
    status: String,
    e3_id: u64,
}

#[derive(Clone, Debug)]
struct ValidatedCallback {
    url: reqwest::Url,
    host_header: Option<String>,
}

fn webhook_client() -> &'static reqwest::Client {
    static CLIENT: OnceLock<reqwest::Client> = OnceLock::new();
    CLIENT.get_or_init(|| {
        reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(30))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("failed to build webhook client")
    })
}

async fn call_webhook(callback: &ValidatedCallback, payload: &WebhookPayload) -> anyhow::Result<()> {
    let (e3_id, status_label, ciphertext_len, commitment_len, proof_len) = match payload {
        WebhookPayload::Completed {
            e3_id,
            ciphertext,
            ciphertext_commitment,
            proof,
        } => (
            *e3_id,
            "completed",
            ciphertext.len(),
            ciphertext_commitment.len(),
            proof.len(),
        ),
        WebhookPayload::Failed { e3_id, error } => {
            println!("call_webhook() - status: failed, error: {}", error);
            (*e3_id, "failed", 0, 0, 0)
        }
    };

    println!(
        "call_webhook() - status: {}, ciphertext len: {}, commitment len: {}, proof len: {}",
        status_label, ciphertext_len, commitment_len, proof_len
    );

    println!("Sending webhook to: {}", callback.url);

    let mut request = webhook_client()
        .post(callback.url.clone())
        .json(payload);
    if let Some(host) = &callback.host_header {
        request = request.header(HOST, host);
    }
    let response = request.send().await?;

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

fn parse_http_url(value: &str, label: &str) -> anyhow::Result<reqwest::Url> {
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

fn host_is_loopback(host: &str) -> bool {
    if host == "localhost" {
        return true;
    }
    host.parse::<IpAddr>()
        .map(|ip| ip.is_loopback())
        .unwrap_or(false)
}

fn ip_is_private_or_reserved(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_private()
                || v4.is_link_local()
                || v4.is_multicast()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || v4.octets() == [169, 254, 169, 254]
        }
        IpAddr::V6(v6) => {
            v6.is_unique_local()
                || v6.is_unicast_link_local()
                || v6.is_multicast()
                || v6.is_unspecified()
        }
    }
}

fn ip_is_safe_public_destination(ip: IpAddr) -> bool {
    !ip.is_loopback() && !ip_is_private_or_reserved(ip)
}

fn ip_is_safe_host_gateway_destination(ip: IpAddr) -> bool {
    ip.is_loopback() || ip_is_private_or_reserved(ip)
}

async fn resolve_host(host: &str, port: u16) -> anyhow::Result<Vec<IpAddr>> {
    let addrs: Vec<_> = tokio::net::lookup_host((host, port))
        .await
        .with_context(|| format!("failed to resolve callback host {host}"))?
        .map(|addr| addr.ip())
        .collect();
    anyhow::ensure!(
        !addrs.is_empty(),
        "callback URL host {host} did not resolve to any addresses"
    );
    Ok(addrs)
}

fn pin_callback_url(mut url: reqwest::Url, ip: IpAddr) -> anyhow::Result<reqwest::Url> {
    let pinned_host = match ip {
        IpAddr::V4(v4) => v4.to_string(),
        IpAddr::V6(v6) => format!("[{v6}]"),
    };
    url.set_host(Some(&pinned_host))
        .map_err(|_| anyhow::anyhow!("failed to pin callback URL to resolved address"))?;
    Ok(url)
}

async fn validated_callback_url(
    callback_url: &str,
    skip_localhost_rewrite: bool,
) -> anyhow::Result<ValidatedCallback> {
    let mut url = parse_http_url(callback_url, "callback URL")?;
    let host = url
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("callback URL must contain a host"))?;

    anyhow::ensure!(
        url.fragment().is_none(),
        "callback URL must not contain a fragment"
    );

    let port = url.port_or_known_default().unwrap_or(80);

    if skip_localhost_rewrite {
        anyhow::ensure!(
            host_is_loopback(host),
            "callback URL must target localhost in host networking mode"
        );

        let ips = if let Ok(ip) = host.parse::<IpAddr>() {
            vec![ip]
        } else {
            resolve_host(host, port).await?
        };
        anyhow::ensure!(
            ips.iter().all(|ip| ip.is_loopback()),
            "callback URL must resolve to loopback addresses in host networking mode"
        );

        let host_header = if host.parse::<IpAddr>().is_err() {
            Some(host.to_string())
        } else {
            None
        };
        return Ok(ValidatedCallback {
            url: pin_callback_url(url, ips[0])?,
            host_header,
        });
    }

    if host_is_loopback(host) {
        url.set_host(Some("host.local"))
            .map_err(|_| anyhow::anyhow!("invalid localhost rewrite host"))?;
        let ips = resolve_host("host.local", port).await?;
        anyhow::ensure!(
            ips.iter().all(|ip| ip_is_safe_host_gateway_destination(*ip)),
            "callback URL must resolve to a host-gateway address"
        );
        return Ok(ValidatedCallback {
            url: pin_callback_url(url, ips[0])?,
            host_header: Some("host.local".to_string()),
        });
    }

    if host == "host.local" {
        let ips = resolve_host(host, port).await?;
        anyhow::ensure!(
            ips.iter().all(|ip| ip_is_safe_host_gateway_destination(*ip)),
            "callback URL must resolve to a host-gateway address"
        );
        return Ok(ValidatedCallback {
            url: pin_callback_url(url, ips[0])?,
            host_header: Some("host.local".to_string()),
        });
    }

    if let Ok(ip) = host.parse::<IpAddr>() {
        anyhow::ensure!(
            ip_is_safe_public_destination(ip),
            "callback URL must not target private or reserved addresses"
        );
        return Ok(ValidatedCallback {
            url,
            host_header: None,
        });
    }

    let ips = resolve_host(host, port).await?;
    anyhow::ensure!(
        ips.iter().all(|ip| ip_is_safe_public_destination(*ip)),
        "callback URL must not resolve to private, loopback, or reserved addresses"
    );

    Ok(ValidatedCallback {
        url: pin_callback_url(url, ips[0])?,
        host_header: Some(host.to_string()),
    })
}

async fn run_computation_async(
    fhe_inputs: FHEInputs,
) -> anyhow::Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    println!("running computation...");
    let result =
        tokio::task::spawn_blocking(move || e3_support_host::run_compute(fhe_inputs)).await?;

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
                Ok((seal, ciphertext, result.ciphertext_commitment))
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
    callback: ValidatedCallback,
    fhe_inputs: FHEInputs,
) -> anyhow::Result<()> {
    match run_computation_async(fhe_inputs).await {
        Ok((proof, ciphertext, ciphertext_commitment)) => {
            println!("computation finished!");
            println!("handling webhook delivery...");
            let payload = WebhookPayload::Completed {
                e3_id,
                ciphertext,
                ciphertext_commitment,
                proof,
            };
            call_webhook(&callback, &payload).await?;
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
            call_webhook(&callback, &payload).await?;

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
    let skip_localhost_rewrite = std::env::var("INTERFOLD_SKIP_LOCALHOST_REWRITE")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    let callback = validated_callback_url(&callback_url, skip_localhost_rewrite)
        .await
        .map_err(|e| actix_web::error::ErrorBadRequest(e.to_string()))?;

    // Process computation in background
    tokio::spawn(async move {
        if let Err(e) = process_computation_background(e3_id, callback, fhe_inputs).await {
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

#[cfg(test)]
mod callback_tests {
    use super::*;

    #[test]
    fn private_ipv4_is_private_or_reserved() {
        assert!(ip_is_private_or_reserved("10.0.0.1".parse().unwrap()));
        assert!(ip_is_private_or_reserved("169.254.169.254".parse().unwrap()));
    }

    #[test]
    fn public_ipv4_is_safe_destination() {
        let ip: IpAddr = "8.8.8.8".parse().unwrap();
        assert!(ip_is_safe_public_destination(ip));
    }

    #[test]
    fn loopback_is_not_safe_public_destination() {
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        assert!(!ip_is_safe_public_destination(ip));
        assert!(ip_is_safe_host_gateway_destination(ip));
    }

    #[tokio::test]
    async fn rejects_private_literal_callback() {
        let err = validated_callback_url("http://10.0.0.1/callback", false)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("private or reserved"));
    }

    #[tokio::test]
    async fn host_mode_requires_loopback() {
        let err = validated_callback_url("http://example.com/callback", true)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("localhost"));
    }

    #[tokio::test]
    async fn host_mode_pins_localhost() {
        let callback = validated_callback_url("http://localhost:8080/callback", true)
            .await
            .unwrap();
        assert_eq!(callback.url.port(), Some(8080));
        assert!(callback.url.host().is_some());
        assert!(callback.url.host().unwrap().is_loopback());
        assert_eq!(callback.host_header.as_deref(), Some("localhost"));
    }
}
