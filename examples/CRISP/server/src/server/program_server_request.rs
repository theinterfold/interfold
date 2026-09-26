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
    pub e3_id: Option<String>,
    pub chain_id: u64,
    pub interfold_address: String,
    #[serde(serialize_with = "serialize_as_hex")]
    pub encryption_scheme_id: Vec<u8>,
    #[serde(serialize_with = "serialize_as_hex")]
    pub committee_public_key_hash: Vec<u8>,
    #[serde(serialize_with = "serialize_as_hex")]
    pub committee_public_key: Vec<u8>,
    #[serde(serialize_with = "serialize_as_hex")]
    pub params: Vec<u8>,
    #[serde(serialize_with = "serialize_hex_tuple")]
    pub ciphertext_inputs: Vec<(Vec<u8>, u64)>,
    /// One commitment per input, in the same order. Lets the Secure Process reject an input whose
    /// published bytes are not the ciphertext that was proven, instead of losing the round.
    #[serde(serialize_with = "serialize_hex_list")]
    pub input_commitments: Vec<[u8; 32]>,
    /// The slot each input was published to, in the same order.
    #[serde(serialize_with = "serialize_hex_slots")]
    pub input_slots: Vec<[u8; 20]>,
    /// The entry each input names as the one it extends, plus one, in the same order. Zero means it
    /// extends nothing. The Secure Process walks each slot's chain by this.
    pub input_parents: Vec<u64>,
    pub callback_url: Option<String>,
}

fn serialize_as_hex<S>(bytes: &Vec<u8>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let hex_string = format!("0x{}", hex::encode(bytes));
    serializer.serialize_str(&hex_string)
}

fn serialize_hex_list<S>(items: &[[u8; 32]], serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let hex_items: Vec<String> = items
        .iter()
        .map(|bytes| format!("0x{}", hex::encode(bytes)))
        .collect();
    hex_items.serialize(serializer)
}

fn serialize_hex_slots<S>(items: &[[u8; 20]], serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let hex_items: Vec<String> = items
        .iter()
        .map(|bytes| format!("0x{}", hex::encode(bytes)))
        .collect();
    hex_items.serialize(serializer)
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
    pub e3_id: String,
}

fn build_compute_request(
    client: &reqwest::Client,
    program_server_url: &str,
    request: &ComputeRequest,
) -> reqwest::RequestBuilder {
    client
        .post(format!("{program_server_url}/run_compute"))
        .json(request)
}

/// The published inputs for a round, in on-chain index order.
///
/// Grouped because the four vectors are only meaningful together: entry `i` of each describes the
/// same input, and a length mismatch mis-pairs ciphertexts with the commitments that prove them.
pub struct RoundInputs {
    pub ciphertexts: Vec<(Vec<u8>, u64)>,
    pub commitments: Vec<[u8; 32]>,
    pub slots: Vec<[u8; 20]>,
    /// The entry each input names as the one it extends, plus one; zero for none.
    pub parents: Vec<u64>,
}

pub async fn run_compute(
    e3_id: &str,
    chain_id: u64,
    interfold_address: String,
    encryption_scheme_id: Vec<u8>,
    committee_public_key_hash: Vec<u8>,
    committee_public_key: Vec<u8>,
    params: Vec<u8>,
    inputs: RoundInputs,
    webhook_url: String,
) -> Result<(String, String)> {
    let request = ComputeRequest {
        e3_id: Some(e3_id.to_string()),
        chain_id,
        interfold_address,
        encryption_scheme_id,
        committee_public_key_hash,
        committee_public_key,
        callback_url: Some(webhook_url),
        params,
        ciphertext_inputs: inputs.ciphertexts,
        input_commitments: inputs.commitments,
        input_slots: inputs.slots,
        input_parents: inputs.parents,
    };

    println!("Sending request");

    let response = build_compute_request(
        &reqwest::Client::new(),
        &CONFIG.program_server_url,
        &request,
    )
    .send()
    .await?;

    // `error_for_status()` reports the code and drops the body, but the program server puts the
    // actual reason there (actix returns the handler's message as the payload): a missing field,
    // a params blob over the size limit, an address that is not 20 bytes. Without the body a
    // schema mismatch between this server and the program server is indistinguishable from a
    // malformed E3 record, and both read as a bare "400 Bad Request".
    let status = response.status();
    if !status.is_success() {
        let body = response.text().await.unwrap_or_default();
        anyhow::bail!("program server rejected the compute request ({status}): {body}");
    }

    let response: ProcessingResponse = response.json().await?;

    Ok((response.e3_id, response.status))
}

#[cfg(test)]
mod tests {
    use reqwest::header::AUTHORIZATION;

    use super::{build_compute_request, ComputeRequest};

    #[test]
    fn compute_request_does_not_require_authorization() {
        let request = ComputeRequest {
            e3_id: Some("7".to_string()),
            chain_id: 31_337,
            interfold_address: "0x1111111111111111111111111111111111111111".to_string(),
            encryption_scheme_id: vec![0x22; 32],
            committee_public_key_hash: vec![0x33; 32],
            committee_public_key: vec![0x44; 32],
            params: vec![1, 2, 3],
            ciphertext_inputs: vec![],
            input_commitments: vec![],
            input_slots: vec![],
            input_parents: vec![],
            callback_url: Some("http://127.0.0.1:4000/state/add-result".to_string()),
        };

        let request =
            build_compute_request(&reqwest::Client::new(), "http://127.0.0.1:13151", &request)
                .build()
                .expect("request should build");

        assert_eq!(request.url().as_str(), "http://127.0.0.1:13151/run_compute");
        assert!(!request.headers().contains_key(AUTHORIZATION));
    }

    /// The Secure Process can only reject an input whose bytes contradict its commitment if the
    /// commitments actually reach it, in the same order as the inputs.
    #[test]
    fn compute_request_carries_commitments_in_input_order() {
        let request = ComputeRequest {
            e3_id: Some("7".to_string()),
            chain_id: 31_337,
            interfold_address: "0x1111111111111111111111111111111111111111".to_string(),
            encryption_scheme_id: vec![0x22; 32],
            committee_public_key_hash: vec![0x33; 32],
            committee_public_key: vec![0x44; 32],
            params: vec![1, 2, 3],
            ciphertext_inputs: vec![(vec![0xaa], 0), (vec![0xbb], 1)],
            input_commitments: vec![[0x11; 32], [0x22; 32]],
            input_slots: vec![[0x01; 20], [0x02; 20]],
            input_parents: vec![0, 1],
            callback_url: None,
        };

        let json = serde_json::to_value(&request).expect("request should serialize");
        let commitments = json["input_commitments"]
            .as_array()
            .expect("input_commitments must serialize as an array");

        assert_eq!(commitments.len(), 2);
        assert_eq!(commitments[0], format!("0x{}", "11".repeat(32)));
        assert_eq!(commitments[1], format!("0x{}", "22".repeat(32)));
    }
}
