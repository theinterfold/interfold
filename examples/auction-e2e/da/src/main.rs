// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Avail helper of the auction server.
//!
//! `auction-da submit --file <bytes>` publishes a file to Avail and prints the pending publication
//! as JSON once Avail has finalized it. `auction-da proof --pending <json>` asks the VectorX bridge
//! API for the Ethereum proof of that publication. The proof can take hours, so the caller polls.
//! Both commands print one JSON document to stdout and report failures on stderr with exit code 1.
//!
//! Environment: `AVAIL_RPC_URL`, `AVAIL_APP_ID`, `AVAIL_SEED` (secret URI, `submit` only),
//! `AVAIL_BRIDGE_API_URL` and `DESTINATION_CHAIN_ID`.

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use e3_data_availability::{
    AvailPublisher, DataAvailabilityPublisher, PendingPublication, ProofStatus, VectorXBridgeApi,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{fs, path::PathBuf};

#[derive(Parser)]
#[command(name = "auction-da", about = "Avail publication helper of the auction server")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Publish a file to Avail and print the finalized publication as JSON.
    Submit {
        /// File whose bytes to publish. The limit is 1 MiB.
        #[arg(long)]
        file: PathBuf,
    },
    /// Print the Ethereum proof status of a publication as JSON.
    Proof {
        /// The JSON that `submit` printed, or the path of a file that holds it.
        #[arg(long)]
        pending: String,
    },
}

/// The publication in the camelCase JSON form that the server stores.
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PendingJson {
    content_hash: String,
    block_hash: String,
    block_number: u32,
    extrinsic_index: u32,
}

impl From<&PendingPublication> for PendingJson {
    fn from(pending: &PendingPublication) -> Self {
        Self {
            content_hash: format!("0x{}", hex::encode(pending.content_hash)),
            block_hash: pending.block_hash.clone(),
            block_number: pending.block_number,
            extrinsic_index: pending.extrinsic_index,
        }
    }
}

impl TryFrom<PendingJson> for PendingPublication {
    type Error = anyhow::Error;

    fn try_from(json: PendingJson) -> Result<Self> {
        let content_hash: [u8; 32] = hex::decode(json.content_hash.trim_start_matches("0x"))
            .context("contentHash is not hex")?
            .try_into()
            .map_err(|_| anyhow::anyhow!("contentHash must be 32 bytes"))?;
        Ok(Self {
            content_hash,
            block_hash: json.block_hash,
            block_number: json.block_number,
            extrinsic_index: json.extrinsic_index,
        })
    }
}

/// Read the `--pending` argument: JSON text, or the path of a file that holds the JSON.
fn parse_pending(argument: &str) -> Result<PendingPublication> {
    let text = if argument.trim_start().starts_with('{') {
        argument.to_owned()
    } else {
        fs::read_to_string(argument).with_context(|| format!("cannot read {argument}"))?
    };
    let json: PendingJson = serde_json::from_str(&text).context("pending publication is not valid JSON")?;
    json.try_into()
}

fn env(name: &str) -> Result<String> {
    match std::env::var(name) {
        Ok(value) if !value.trim().is_empty() => Ok(value.trim().to_owned()),
        _ => bail!("{name} is required"),
    }
}

fn destination_chain_id() -> Result<u64> {
    env("DESTINATION_CHAIN_ID")?
        .parse()
        .context("DESTINATION_CHAIN_ID must be an integer")
}

async fn submit(file: PathBuf) -> Result<serde_json::Value> {
    let bytes = fs::read(&file).with_context(|| format!("cannot read {}", file.display()))?;
    let app_id = env("AVAIL_APP_ID")?
        .parse()
        .context("AVAIL_APP_ID must be an integer")?;
    let publisher = AvailPublisher::new(
        env("AVAIL_RPC_URL")?,
        app_id,
        &env("AVAIL_SEED")?,
        env("AVAIL_BRIDGE_API_URL")?,
        destination_chain_id()?,
    )?;
    let pending = publisher.publish(&bytes).await?;
    Ok(serde_json::to_value(PendingJson::from(&pending))?)
}

async fn proof(pending: &str) -> Result<serde_json::Value> {
    let pending = parse_pending(pending)?;
    let bridge = VectorXBridgeApi::new(env("AVAIL_BRIDGE_API_URL")?, destination_chain_id()?)?;
    Ok(match bridge.proof(&pending).await? {
        ProofStatus::Pending => json!({ "status": "pending" }),
        ProofStatus::Ready { reference, abi_proof } => json!({
            "status": "ready",
            "contentHash": format!("0x{}", hex::encode(reference.content_hash)),
            "blockNumber": reference.block_number,
            // A decimal string: the leaf index is a uint128, which a JSON number cannot hold.
            "leafIndex": reference.leaf_index.to_string(),
            "abiProof": format!("0x{}", hex::encode(abi_proof)),
        }),
    })
}

#[tokio::main]
async fn main() {
    let result = match Cli::parse().command {
        Command::Submit { file } => submit(file).await,
        Command::Proof { pending } => proof(&pending).await,
    };
    match result {
        Ok(value) => println!("{value}"),
        Err(error) => {
            eprintln!("auction-da: {error:#}");
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> PendingPublication {
        PendingPublication {
            content_hash: [0xab; 32],
            block_hash: "0x01".to_owned(),
            block_number: 7,
            extrinsic_index: 3,
        }
    }

    #[test]
    fn pending_json_round_trips() {
        let json = serde_json::to_string(&PendingJson::from(&sample())).unwrap();
        assert!(json.contains("\"contentHash\":\"0xabab"));
        assert!(json.contains("\"extrinsicIndex\":3"));
        assert_eq!(parse_pending(&json).unwrap(), sample());
    }

    #[test]
    fn pending_rejects_a_short_content_hash() {
        let json = r#"{"contentHash":"0xabab","blockHash":"0x01","blockNumber":1,"extrinsicIndex":0}"#;
        assert!(parse_pending(json).is_err());
    }
}
