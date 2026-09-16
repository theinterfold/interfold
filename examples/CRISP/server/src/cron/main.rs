// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use reqwest::{Client, Url};
use serde_json::json;
use std::error::Error;
use std::net::IpAddr;
use std::time::Duration;
use tokio::time::sleep;

const MAX_RETRIES: u8 = 5;

fn invalid_server_url(message: &str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidInput, message)
}

fn is_loopback_host(host: &str) -> bool {
    let host = host.trim_matches(['[', ']']);
    host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<IpAddr>()
            .is_ok_and(|address| address.is_loopback())
}

fn round_request_url(server_url: &str) -> Result<Url, std::io::Error> {
    let mut url = Url::parse(server_url.trim()).map_err(|_| {
        invalid_server_url("INTERFOLD_SERVER_URL must be an absolute HTTP or HTTPS URL")
    })?;

    if !url.username().is_empty() || url.password().is_some() {
        return Err(invalid_server_url(
            "INTERFOLD_SERVER_URL must not contain user information",
        ));
    }
    if url.query().is_some() || url.fragment().is_some() {
        return Err(invalid_server_url(
            "INTERFOLD_SERVER_URL must not contain a query or fragment",
        ));
    }

    let host = url
        .host_str()
        .ok_or_else(|| invalid_server_url("INTERFOLD_SERVER_URL must contain a host"))?;
    match url.scheme() {
        "https" => {}
        "http" if is_loopback_host(host) => {}
        "http" => {
            return Err(invalid_server_url(
                "INTERFOLD_SERVER_URL must use HTTPS unless its host is loopback",
            ));
        }
        _ => {
            return Err(invalid_server_url(
                "INTERFOLD_SERVER_URL must use HTTP or HTTPS",
            ));
        }
    }

    let path = format!("{}/rounds/request", url.path().trim_end_matches('/'));
    url.set_path(&path);
    Ok(url)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let cron_api_key = std::env::var("CRON_API_KEY").map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "CRON_API_KEY must be set")
    })?;
    if cron_api_key.trim().is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "CRON_API_KEY must not be empty",
        )
        .into());
    }
    let interfold_server_url = std::env::var("INTERFOLD_SERVER_URL")
        .unwrap_or_else(|_| "http://localhost:4000".to_string());
    let round_request_url = round_request_url(&interfold_server_url)?;
    let mut client_builder = Client::builder().redirect(reqwest::redirect::Policy::none());
    if round_request_url.scheme() == "http" {
        // Keep the loopback-only plaintext exception off environment-configured proxies.
        client_builder = client_builder.no_proxy();
    }
    let client = client_builder.build()?;

    loop {
        println!("Requesting new E3 round...");
        let mut retries = 0;
        let mut success = false;

        while retries < MAX_RETRIES {
            let response = client
                .post(round_request_url.clone())
                .json(&json!({
                    "cron_api_key": &cron_api_key
                }))
                .send()
                .await;

            match response {
                Ok(res) => {
                    if res.status().is_success() {
                        println!("Successfully requested new E3 round");
                        success = true;
                        break;
                    } else {
                        println!("Failed to request new E3 round: {:?}", res.text().await?);
                    }
                }
                Err(e) => {
                    println!("Error making request: {:?}", e);
                }
            }

            retries += 1;
            if retries < MAX_RETRIES {
                let backoff_time = Duration::from_secs(2u64.pow(retries.into()));
                println!("Retrying in {} seconds...", backoff_time.as_secs());
                sleep(backoff_time).await;
            }
        }

        if !success {
            println!(
                "Failed to request new E3 round after {} retries. Skipping for now.",
                MAX_RETRIES
            );
        }

        sleep(Duration::from_secs(24 * 60 * 60)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_https_servers() {
        let url = round_request_url("https://crisp.example/base/").unwrap();

        assert_eq!(url.as_str(), "https://crisp.example/base/rounds/request");
    }

    #[test]
    fn accepts_loopback_http_servers() {
        for server_url in [
            "http://localhost:4000",
            "http://127.0.0.2:4000",
            "http://[::1]:4000",
        ] {
            assert!(round_request_url(server_url).is_ok(), "{server_url}");
        }
    }

    #[test]
    fn rejects_remote_http_servers() {
        for server_url in [
            "http://crisp.example",
            "http://10.0.0.1",
            "http://0.0.0.0:4000",
        ] {
            let error = round_request_url(server_url).unwrap_err();
            assert!(error.to_string().contains("must use HTTPS"), "{server_url}");
        }
    }

    #[test]
    fn rejects_urls_with_user_information() {
        let error = round_request_url("http://localhost@crisp.example").unwrap_err();

        assert!(error
            .to_string()
            .contains("must not contain user information"));
    }

    #[test]
    fn rejects_invalid_schemes_queries_and_fragments() {
        for server_url in [
            "/relative",
            "ftp://crisp.example",
            "https://crisp.example?mode=cron",
            "https://crisp.example?",
            "https://crisp.example#cron",
            "https://crisp.example#",
        ] {
            assert!(round_request_url(server_url).is_err(), "{server_url}");
        }
    }
}
