// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use reqwest::Client;
use serde_json::json;
use std::error::Error;
use std::time::Duration;
use tokio::time::sleep;

const MAX_RETRIES: u8 = 5;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let client = Client::new();
    let cron_api_key = std::env::var("CRON_API_KEY").unwrap_or_else(|_| "1234567890".to_string());
    let interfold_server_url = std::env::var("INTERFOLD_SERVER_URL")
        .unwrap_or_else(|_| "http://localhost:4000".to_string());

    loop {
        println!("Requesting new E3 round...");
        let mut retries = 0;
        let mut success = false;

        while retries < MAX_RETRIES {
            let response = client
                .post(format!("{}/rounds/request", interfold_server_url))
                .json(&json!({
                    "cron_api_key": cron_api_key
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
