// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use anyhow::Result;
use derivative::Derivative;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

#[allow(dead_code)]
#[derive(Serialize, Deserialize, Debug)]
pub struct ComputeResponse {
    pub ciphertext: Vec<u8>,
    pub proof: Vec<u8>,
}

#[derive(Debug, Deserialize)]
pub struct ComputeRequest {
    pub e3_id: Option<String>,
    pub chain_id: u64,
    pub interfold_address: String,
    #[serde(deserialize_with = "deserialize_hex_string")]
    pub encryption_scheme_id: Vec<u8>,
    #[serde(deserialize_with = "deserialize_hex_string")]
    pub committee_public_key_hash: Vec<u8>,
    #[serde(default, deserialize_with = "deserialize_hex_string")]
    pub committee_public_key: Vec<u8>,
    #[serde(deserialize_with = "deserialize_hex_string")]
    pub params: Vec<u8>,
    #[serde(deserialize_with = "deserialize_hex_tuple")]
    pub ciphertext_inputs: Vec<(Vec<u8>, u64)>,
    /// The commitment the E3 program stored for each input, hex encoded, in the same order as
    /// `ciphertext_inputs`.
    ///
    /// Optional so an older caller still deserializes. Omitting it means the Secure Process cannot
    /// check a published ciphertext against the commitment that was actually proven, so a single
    /// unusable input costs the whole round.
    #[serde(default)]
    pub input_commitments: Vec<String>,
    /// The slot each input was published to, hex encoded, in the same order. Required alongside
    /// `input_commitments`: the tree is append-only, so the Secure Process groups by slot.
    #[serde(default)]
    pub input_slots: Vec<String>,
    /// The entry each input names as the one it extends, plus one, in the same order; zero means it
    /// extends nothing. Required alongside `input_slots`, because a policy that groups by slot may
    /// also order within one, and CRISP's does.
    ///
    /// Carried as `u64` because JSON has no narrower integer, but the published width is a Solidity
    /// `uint40`. The handler refuses anything wider rather than truncating it.
    #[serde(default)]
    pub input_parents: Vec<u64>,
    pub callback_url: Option<String>,
}

#[derive(Derivative, Serialize, Deserialize)]
#[derivative(Debug)]
#[serde(tag = "status", rename_all = "lowercase")]
pub enum WebhookPayload {
    Completed {
        e3_id: String,
        #[serde(serialize_with = "serialize_as_hex")]
        #[serde(deserialize_with = "deserialize_hex_string")]
        #[derivative(Debug = "ignore")]
        ciphertext: Vec<u8>,
        #[serde(serialize_with = "serialize_as_hex")]
        #[serde(deserialize_with = "deserialize_hex_string")]
        #[derivative(Debug = "ignore")]
        proof: Vec<u8>,
        /// Circuit-compatible SAFE commitment to the decrypted ciphertext.
        /// Required by `Interfold.publishCiphertextOutput` since the
        /// ciphertext-binding remediation. Serialized as a 0x-prefixed
        /// hex string for direct forwarding to the template server.
        #[serde(serialize_with = "serialize_bytes32_as_hex")]
        ciphertext_commitment: [u8; 32],
    },
    Failed {
        e3_id: String,
        error: String,
    },
}

fn serialize_as_hex<S>(bytes: &Vec<u8>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let hex_string = format!("0x{}", hex::encode(bytes));
    serializer.serialize_str(&hex_string)
}

fn serialize_bytes32_as_hex<S>(bytes: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let hex_string = format!("0x{}", hex::encode(bytes));
    serializer.serialize_str(&hex_string)
}

pub fn deserialize_hex_string<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    let s: String = Deserialize::deserialize(deserializer)?;
    let hex_str = s.strip_prefix("0x").unwrap_or(&s);
    hex::decode(hex_str).map_err(serde::de::Error::custom)
}

pub fn deserialize_hex_tuple<'de, D>(deserializer: D) -> Result<Vec<(Vec<u8>, u64)>, D::Error>
where
    D: Deserializer<'de>,
{
    let tuples: Vec<(String, u64)> = Deserialize::deserialize(deserializer)?;
    tuples
        .into_iter()
        .map(|(hex_str, num)| {
            let stripped = hex_str.strip_prefix("0x").unwrap_or(&hex_str);
            hex::decode(stripped)
                .map(|bytes| (bytes, num))
                .map_err(serde::de::Error::custom)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use crate::{ComputeRequest, WebhookPayload};

    #[test]
    fn test_deserialize_compute_request() {
        let json = r#"
        {
            "e3_id": "12345",
            "chain_id": 31337,
            "interfold_address": "0x1111111111111111111111111111111111111111",
            "encryption_scheme_id": "0x2222222222222222222222222222222222222222222222222222222222222222",
            "committee_public_key_hash": "0x3333333333333333333333333333333333333333333333333333333333333333",
            "params": "0x12345ffa",
            "ciphertext_inputs": [
                ["0xffabc123", 100],
                ["0xaa6de432", 200]
            ],
            "callback_url": "https://example.com/callback"
        }
        "#;

        let payload: ComputeRequest = serde_json::from_str(json).unwrap();

        assert_eq!(payload.e3_id, Some("12345".to_string()));
        assert_eq!(payload.chain_id, 31337);
        assert_eq!(
            payload.interfold_address,
            "0x1111111111111111111111111111111111111111"
        );
        assert_eq!(payload.encryption_scheme_id, vec![0x22; 32]);
        assert_eq!(payload.committee_public_key_hash, vec![0x33; 32]);
        assert_eq!(payload.params, hex::decode("12345ffa").unwrap());
        assert_eq!(payload.ciphertext_inputs.len(), 2);
        assert_eq!(
            payload.ciphertext_inputs[0],
            (hex::decode("ffabc123").unwrap(), 100)
        );
        assert_eq!(
            payload.ciphertext_inputs[1],
            (hex::decode("aa6de432").unwrap(), 200)
        );
        assert_eq!(
            payload.callback_url,
            Some("https://example.com/callback".to_string())
        );
    }

    #[test]
    fn test_deserialize_compute_request_no_prefix() {
        let json = r#"
        {
            "e3_id": "12345",
            "chain_id": 31337,
            "interfold_address": "0x1111111111111111111111111111111111111111",
            "encryption_scheme_id": "2222222222222222222222222222222222222222222222222222222222222222",
            "committee_public_key_hash": "3333333333333333333333333333333333333333333333333333333333333333",
            "params": "12345ffa",
            "ciphertext_inputs": [
                ["ffabc123", 100],
                ["aa6de432", 200]
            ],
            "callback_url": "https://example.com/callback"
        }
        "#;

        let payload: ComputeRequest = serde_json::from_str(json).unwrap();

        assert_eq!(payload.e3_id, Some("12345".to_string()));
        assert_eq!(payload.encryption_scheme_id, vec![0x22; 32]);
        assert_eq!(payload.committee_public_key_hash, vec![0x33; 32]);
        assert_eq!(payload.params, hex::decode("12345ffa").unwrap());
        assert_eq!(payload.ciphertext_inputs.len(), 2);
        assert_eq!(
            payload.ciphertext_inputs[0],
            (hex::decode("ffabc123").unwrap(), 100)
        );
        assert_eq!(
            payload.ciphertext_inputs[1],
            (hex::decode("aa6de432").unwrap(), 200)
        );
        assert_eq!(
            payload.callback_url,
            Some("https://example.com/callback".to_string())
        );
    }

    #[test]
    fn test_webhook_payload_serialization_completed() {
        let commitment = [0x11u8; 32];
        let payload = WebhookPayload::Completed {
            e3_id: "12345".to_string(),
            ciphertext: vec![0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef],
            proof: vec![0xde, 0xad, 0xbe, 0xef],
            ciphertext_commitment: commitment,
        };

        let json = serde_json::to_string(&payload).expect("Failed to serialize");
        let expected = format!(
            r#"{{"status":"completed","e3_id":"12345","ciphertext":"0x0123456789abcdef","proof":"0xdeadbeef","ciphertext_commitment":"0x{}"}}"#,
            hex::encode(commitment),
        );

        assert_eq!(json, expected);
    }

    #[test]
    fn test_webhook_payload_serialization_failed() {
        let payload = WebhookPayload::Failed {
            e3_id: "12345".to_string(),
            error: "Computation failed".to_string(),
        };

        let json = serde_json::to_string(&payload).expect("Failed to serialize");
        let expected = r#"{"status":"failed","e3_id":"12345","error":"Computation failed"}"#;

        assert_eq!(json, expected);
    }
}
