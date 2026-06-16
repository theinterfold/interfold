// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::server::CONFIG;

use anyhow::Result;
use serde::{Deserialize, Serialize, Serializer};

#[derive(Debug, Serialize)]
pub struct ComputeRequest {
    pub e3_id: Option<u64>,
    #[serde(serialize_with = "serialize_as_hex")]
    pub params: Vec<u8>,
    #[serde(serialize_with = "serialize_hex_tuple")]
    pub ciphertext_inputs: Vec<(Vec<u8>, u64)>,
    pub callback_url: Option<String>,
}

fn serialize_as_hex<S>(bytes: &Vec<u8>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let hex_string = format!("0x{}", hex::encode(bytes));
    serializer.serialize_str(&hex_string)
}

fn serialize_hex_tuple<S>(tuples: &[(Vec<u8>, u64)], serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let hex_tuples: Vec<(String, u64)> = tuples
        .iter()
        .map(|(bytes, num)| (format!("0x{}", hex::encode(bytes)), *num))
        .collect();
    hex_tuples.serialize(serializer)
}

#[derive(Deserialize, Serialize)]
pub struct ProcessingResponse {
    pub status: String,
    pub e3_id: u64,
}

pub async fn run_compute(
    e3_id: u64,
    params: Vec<u8>,
    ciphertext_inputs: Vec<(Vec<u8>, u64)>,
    webhook_url: String,
) -> Result<(u64, String)> {
    let request = ComputeRequest {
        e3_id: Some(e3_id),
        callback_url: Some(webhook_url),
        params,
        ciphertext_inputs,
    };

    println!("Sending request");

    let response: ProcessingResponse = reqwest::Client::new()
        .post(format!("{}/{}", CONFIG.program_server_url, "run_compute"))
        .json(&request)
        .send()
        .await?
        .json()
        .await?;

    Ok((response.e3_id, response.status))
}
