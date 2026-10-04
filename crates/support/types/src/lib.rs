// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use alloy_primitives::U256;
use anyhow::Result;
use derivative::Derivative;
use e3_compute_provider::{ComputeInput, ComputeResult};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ComputeDomain {
    pub chain_id: u64,
    pub verifying_contract: [u8; 20],
    pub e3_id: [u8; 32],
    pub encryption_scheme_id: [u8; 32],
    pub committee_public_key_hash: [u8; 32],
}

impl ComputeDomain {
    pub fn new(
        chain_id: u64,
        interfold_address: &str,
        e3_id: &str,
        encryption_scheme_id: &[u8],
        committee_public_key_hash: &[u8],
    ) -> std::result::Result<Self, String> {
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

fn fixed<const N: usize>(value: &[u8], name: &str) -> std::result::Result<[u8; N], String> {
    value
        .try_into()
        .map_err(|_| format!("{name} must be {N} bytes"))
}

fn uint_word(value: u64) -> Vec<u8> {
    let mut word = vec![0_u8; 32];
    word[24..].copy_from_slice(&value.to_be_bytes());
    word
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ComputeGuestInput {
    pub domain: ComputeDomain,
    pub input: ComputeInput,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ComputeJournal {
    pub chain_id: Vec<u8>,
    pub verifying_contract: Vec<u8>,
    pub e3_id: Vec<u8>,
    pub encryption_scheme_id: Vec<u8>,
    pub committee_public_key_hash: Vec<u8>,
    pub ciphertext_hash: Vec<u8>,
    pub ciphertext_commitment: Vec<u8>,
    pub params_hash: Vec<u8>,
    pub merkle_root: Vec<u8>,
}

impl ComputeJournal {
    pub fn new(domain: ComputeDomain, result: ComputeResult) -> std::result::Result<Self, String> {
        for (name, value) in [
            ("ciphertext hash", &result.ciphertext_hash),
            ("ciphertext commitment", &result.ciphertext_commitment),
            ("parameter hash", &result.params_hash),
            ("input root", &result.merkle_root),
        ] {
            if value.len() != 32 {
                return Err(format!("{name} must be 32 bytes"));
            }
        }

        Ok(Self {
            chain_id: uint_word(domain.chain_id),
            verifying_contract: [vec![0_u8; 12], domain.verifying_contract.to_vec()].concat(),
            e3_id: domain.e3_id.to_vec(),
            encryption_scheme_id: domain.encryption_scheme_id.to_vec(),
            committee_public_key_hash: domain.committee_public_key_hash.to_vec(),
            ciphertext_hash: result.ciphertext_hash,
            ciphertext_commitment: result.ciphertext_commitment,
            params_hash: result.params_hash,
            merkle_root: result.merkle_root,
        })
    }
}

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
    #[serde(deserialize_with = "deserialize_hex_string")]
    pub params: Vec<u8>,
    #[serde(deserialize_with = "deserialize_hex_tuple")]
    pub ciphertext_inputs: Vec<(Vec<u8>, u64)>,
    pub callback_url: Option<String>,

    // What the E3 program published alongside each ciphertext. A program whose contract folds more
    // than the ciphertext into its input-tree leaf needs these to rebuild the same leaf; without
    // them the guest derives a different root and the proof cannot be published. Optional, because
    // a program using the default policy publishes none of it — but silently dropping them when
    // they *are* sent is the failure this exists to prevent, so the handler rejects a partial set
    // rather than computing a root the contract will reject.
    #[serde(default)]
    pub input_commitments: Vec<String>,
    #[serde(default)]
    pub input_slots: Vec<String>,
    #[serde(default)]
    pub input_parents: Vec<u64>,
}

/// Webhook payload for CRISP and `E3ProgramServer`.
/// A completed payload includes the ciphertext, its journal-bound commitment, and the proof.
/// A failed payload includes the E3 ID and an error message.
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
        ciphertext_commitment: Vec<u8>,
        #[serde(serialize_with = "serialize_as_hex")]
        #[serde(deserialize_with = "deserialize_hex_string")]
        #[derivative(Debug = "ignore")]
        proof: Vec<u8>,
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
    use crate::{ComputeDomain, ComputeRequest, WebhookPayload};

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
        let payload = WebhookPayload::Completed {
            e3_id: "12345".to_string(),
            ciphertext: vec![0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef],
            ciphertext_commitment: vec![0x11; 32],
            proof: vec![0xde, 0xad, 0xbe, 0xef],
        };

        let json = serde_json::to_string(&payload).expect("Failed to serialize");
        let expected = format!(
            r#"{{"status":"completed","e3_id":"12345","ciphertext":"0x0123456789abcdef","ciphertext_commitment":"0x{}","proof":"0xdeadbeef"}}"#,
            "11".repeat(32)
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

    #[test]
    fn test_webhook_deserialize_roundtrip() {
        let json = format!(
            r#"{{"status":"completed","e3_id":"12345","ciphertext":"0xabcdef","ciphertext_commitment":"0x{}","proof":"0x123456"}}"#,
            "22".repeat(32)
        );
        let payload: WebhookPayload = serde_json::from_str(&json).unwrap();
        match payload {
            WebhookPayload::Completed {
                e3_id,
                ciphertext,
                ciphertext_commitment,
                proof,
            } => {
                assert_eq!(e3_id, "12345");
                assert_eq!(ciphertext, vec![0xab, 0xcd, 0xef]);
                assert_eq!(ciphertext_commitment, vec![0x22; 32]);
                assert_eq!(proof, vec![0x12, 0x34, 0x56]);
            }
            _ => panic!("Expected Completed"),
        }
    }
}
