// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use super::{repo::InputSnapshot, rpc, CONFIG};

use alloy::hex::encode_prefixed;
use e3_sdk::indexer::models::E3;
use eyre::{bail, Context, Result};
use serde::{Deserialize, Serialize, Serializer};
use std::time::Duration;

/// The program server answers as soon as it has read the request body, and it allows that body
/// 120 s to arrive. The client deadline covers the upload too, so it matches that allowance.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(120);

#[derive(Serialize)]
struct ComputeRequest {
    e3_id: Option<String>,
    chain_id: u64,
    interfold_address: String,
    #[serde(serialize_with = "serialize_hex")]
    encryption_scheme_id: Vec<u8>,
    #[serde(serialize_with = "serialize_hex")]
    committee_public_key_hash: Vec<u8>,
    #[serde(serialize_with = "serialize_hex")]
    params: Vec<u8>,
    #[serde(serialize_with = "serialize_hex_tuple")]
    ciphertext_inputs: Vec<(Vec<u8>, u64)>,
    /// One commitment per input, in the same order. Lets the Secure Process reject an input whose
    /// published bytes are not the ciphertext that was proven, instead of losing the round.
    #[serde(serialize_with = "serialize_hex_list")]
    input_commitments: Vec<[u8; 32]>,
    /// The slot each input was published to, in the same order.
    #[serde(serialize_with = "serialize_hex_list")]
    input_slots: Vec<[u8; 20]>,
    /// The entry each input names as the one it extends, plus one, in the same order. Zero means it
    /// extends nothing. The Secure Process walks each slot's chain by this.
    input_parents: Vec<u64>,
    callback_url: Option<String>,
}

fn serialize_hex<S: Serializer>(
    bytes: &impl AsRef<[u8]>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(&encode_prefixed(bytes))
}

fn serialize_hex_list<S: Serializer, T: AsRef<[u8]>>(
    items: &[T],
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serializer.collect_seq(items.iter().map(encode_prefixed))
}

fn serialize_hex_tuple<S: Serializer>(
    tuples: &[(Vec<u8>, u64)],
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serializer.collect_seq(
        tuples
            .iter()
            .map(|(bytes, index)| (encode_prefixed(bytes), index)),
    )
}

#[derive(Deserialize)]
struct ProcessingResponse {
    status: String,
    e3_id: String,
}

/// Ask the program server to compute round `e3_id` from its indexed inputs. The server answers
/// "processing" and posts the result to `/state/add-result`; any other answer is an error.
pub async fn run_compute(e3_id: &str, e3: E3, inputs: InputSnapshot) -> Result<()> {
    let request = ComputeRequest {
        e3_id: Some(e3_id.to_string()),
        chain_id: e3.chain_id,
        interfold_address: e3.interfold_address,
        encryption_scheme_id: e3.encryption_scheme_id,
        committee_public_key_hash: e3.committee_public_key_hash,
        params: e3.e3_params,
        ciphertext_inputs: inputs.ciphertexts,
        input_commitments: inputs.commitments,
        input_slots: inputs.slots,
        input_parents: inputs.parents,
        callback_url: Some(format!(
            "{}/state/add-result",
            CONFIG.interfold_server_url_for_clients()
        )),
    };

    let response = rpc::HTTP
        .post(format!("{}/run_compute", CONFIG.program_server_url))
        .timeout(REQUEST_TIMEOUT)
        .json(&request)
        .send()
        .await
        .context("Error sending run compute request")?;

    // The program server puts the reason for a refusal in the body: a missing field, a params blob
    // over the size limit, an address that is not 20 bytes. Without it a schema mismatch reads as
    // a bare "400 Bad Request".
    let status = response.status();
    if !status.is_success() {
        let body = response.text().await.unwrap_or_default();
        bail!("program server rejected the compute request ({status}): {body}");
    }

    let response: ProcessingResponse = response
        .json()
        .await
        .context("Error reading the run compute response")?;
    if response.e3_id != e3_id {
        bail!(
            "Computation request returned unexpected E3 ID: expected {e3_id}, got {}",
            response.e3_id
        );
    }
    if response.status != "processing" {
        bail!(
            "Computation request failed with status: {}",
            response.status
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::ComputeRequest;
    use serde_json::json;

    /// The Secure Process can only reject an input whose bytes contradict its commitment if the
    /// commitments, slots, and parents reach it as hex strings and integers, one per input, in the
    /// order of the inputs.
    #[test]
    fn compute_request_carries_commitments_in_input_order() {
        let request = ComputeRequest {
            e3_id: Some("7".to_string()),
            chain_id: 31_337,
            interfold_address: "0x1111111111111111111111111111111111111111".to_string(),
            encryption_scheme_id: vec![0x22; 32],
            committee_public_key_hash: vec![0x33; 32],
            params: vec![1, 2, 3],
            ciphertext_inputs: vec![(vec![0xaa], 0), (vec![0xbb], 1)],
            input_commitments: vec![[0x11; 32], [0x22; 32]],
            input_slots: vec![[0x01; 20], [0x02; 20]],
            input_parents: vec![0, 1],
            callback_url: None,
        };

        let json = serde_json::to_value(&request).expect("request should serialize");

        assert_eq!(json["params"], "0x010203");
        assert_eq!(json["ciphertext_inputs"], json!([["0xaa", 0], ["0xbb", 1]]));
        assert_eq!(
            json["input_commitments"],
            json!([
                format!("0x{}", "11".repeat(32)),
                format!("0x{}", "22".repeat(32))
            ])
        );
        assert_eq!(
            json["input_slots"],
            json!([
                format!("0x{}", "01".repeat(20)),
                format!("0x{}", "02".repeat(20))
            ])
        );
        assert_eq!(json["input_parents"], json!([0, 1]));
    }
}
