// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Server-side records and API shapes (mirrors the types in `packages/ckks-matching-sdk`).

use alloy::primitives::U256;
use anyhow::Result;
use ckks_matching_program::Role;
use serde::{Deserialize, Serialize};

pub fn e3_id_to_u256(e3_id: &str) -> Result<U256> {
    U256::from_str_radix(e3_id, 10).map_err(|e| anyhow::anyhow!("Invalid E3 ID '{}': {}", e3_id, e))
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum RoundStatus {
    /// E3 requested; committee DKG + level-0 relin ceremony in progress.
    Requested,
    /// Committee key published; submission window open.
    Active,
    /// Input window closed; evaluating.
    Evaluating,
    /// Ciphertext output published; committee threshold-decrypting.
    Published,
    /// Plaintext on-chain; the score is available.
    Finished,
    Failed,
}

/// A submission accepted by the on-chain gate (`SubmissionPublished`): five Honk
/// proofs verified, slot `index` = the party's position in the registered pair
/// (0 = A / forward, 1 = B / reversed).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IndexedSubmission {
    /// The party's SLOT (0 = A, 1 = B) — also its role.
    pub index: u64,
    pub role: Role,
    pub publisher: String,
    pub transaction_hash: String,
    pub block: u64,
    pub vector_ciphertext_hash: String,
    pub mask_ciphertext_hash: String,
    pub m_commitment_vec: String,
    pub m_commitment_mask: String,
    /// Whether both ciphertexts were recovered from the transaction and hash-checked.
    pub ciphertext_available: bool,
}

/// The opened output: 64 coefficients at 4 decimals; `score = −opened[0]`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct RoundResults {
    /// The compatibility score `⟨a, b⟩` of the two private profile vectors.
    pub score: f64,
    /// The raw opened coefficients (`opened[0] = −score`; `1..` are masked cross terms).
    pub opened: Vec<f64>,
    /// The raw on-chain plaintext bytes (hex), for clients that want to decode themselves.
    pub plaintext_hex: String,
}

/// The per-round record.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct E3Matching {
    pub e3_id: String,
    pub status: RoundStatus,
    pub created_at: u64,
    pub input_window: [u64; 2],
    /// The two registered parties in SLOT order: `[A, B]`.
    pub parties: Vec<String>,
    pub submissions: Vec<IndexedSubmission>,
    /// `(slot index, vector ct, mask ct)` — only those recovered from calldata.
    #[serde(default)]
    pub ciphertexts: Vec<(u64, Vec<u8>, Vec<u8>)>,
    pub results: Option<RoundResults>,
    pub error: Option<String>,
    /// Stage → wall-clock ms, for the timings table.
    #[serde(default)]
    pub timings: Vec<(String, u64)>,
    /// Unix timestamps of stage boundaries (`requested`, `active`, ...).
    #[serde(default)]
    pub stage_at: Vec<(String, u64)>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RoundSummary {
    pub e3_id: String,
    pub status: RoundStatus,
    pub input_window: [u64; 2],
    pub party_a: String,
    pub party_b: String,
    pub submission_count: usize,
    pub created_at: u64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RoundDetail {
    #[serde(flatten)]
    pub summary: RoundSummary,
    pub program_address: String,
    pub param_set: u8,
    /// Vector length each party packs.
    pub k: usize,
    /// The two registered parties in SLOT order: `[A, B]`.
    pub parties: Vec<String>,
    pub submissions: Vec<IndexedSubmission>,
    pub public_key_available: bool,
    pub results: Option<RoundResults>,
    pub error: Option<String>,
    pub timings: std::collections::BTreeMap<String, u64>,
}

/// `GET /rounds/{id}/slot/{address}`: the party's registered slot + role.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SlotResponse {
    pub address: String,
    /// The party's slot index (0 = A, 1 = B).
    pub index: u32,
    pub role: Role,
    /// `forward` (A) or `reversed` (B): the coefficient layout the party must encode.
    pub layout: &'static str,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RoundRequest {
    /// Party A (slot 0, forward layout).
    pub party_a: String,
    /// Party B (slot 1, reversed layout).
    pub party_b: String,
    #[serde(default)]
    pub duration_secs: Option<u64>,
}
