// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Server-side records and API shapes (mirrors the types in `packages/ckks-credit-sdk`).

use alloy::primitives::U256;
use anyhow::Result;
use ckks_credit_program::{FixedPointModel, Model, FEATURES};
use serde::{Deserialize, Serialize};

pub fn e3_id_to_u256(e3_id: &str) -> Result<U256> {
    U256::from_str_radix(e3_id, 10).map_err(|e| anyhow::anyhow!("Invalid E3 ID '{}': {}", e3_id, e))
}

/// One issuer-snapshot entry: the features the issuer attests for an address (integer
/// numerators over the round's `cap`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Applicant {
    pub address: String,
    pub features: [u32; FEATURES],
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum RoundStatus {
    /// E3 requested; committee DKG + two per-level relin ceremonies in progress.
    Requested,
    /// Committee key published; application window open.
    Active,
    /// Input window closed; evaluating.
    Evaluating,
    /// Ciphertext output published; committee threshold-decrypting.
    Published,
    /// Plaintext on-chain; masked scores available.
    Finished,
    Failed,
}

/// An application accepted by the on-chain gate (`ApplicationPublished`): five Honk
/// proofs verified, slot `index` = the applicant's position in the registered list.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IndexedApplication {
    /// The applicant's SLOT (its position in the registered applicant list).
    pub index: u64,
    pub publisher: String,
    pub transaction_hash: String,
    pub block: u64,
    pub logit_ciphertext_hash: String,
    pub mask_ciphertext_hash: String,
    pub m_commitment_z: String,
    pub m_commitment_m: String,
    /// Whether both ciphertexts were recovered from the transaction and hash-checked.
    pub ciphertext_available: bool,
}

/// The opened output: one MASKED probability per SLOT (`σ_cubic(z_i) + m_i`; 0.5 for an
/// empty slot). Meaningless to anyone but the applicant holding `m_i`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct RoundResults {
    /// `opened[i] = σ_cubic(z_i) + m_i` for slot `i` (one per registered applicant).
    pub opened: Vec<f64>,
    /// The raw on-chain plaintext bytes (hex), for clients that want to decode themselves.
    pub plaintext_hex: String,
}

/// The per-round record.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct E3Credit {
    pub e3_id: String,
    pub status: RoundStatus,
    pub created_at: u64,
    pub input_window: [u64; 2],
    pub cap: u64,
    pub model: Model,
    /// The model as registered on-chain (`×2^16`).
    #[serde(default)]
    pub fixed_point_model: Option<FixedPointModel>,
    pub snapshot: Vec<Applicant>,
    /// Hex leaf hashes in snapshot order (what the tree was built from).
    pub leaf_hashes: Vec<String>,
    pub issuer_root: Option<String>,
    pub applications: Vec<IndexedApplication>,
    /// `(slot index, logit ct, mask ct)` — only those recovered from calldata.
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
    pub cap: u64,
    pub input_window: [u64; 2],
    pub application_count: usize,
    pub created_at: u64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RoundDetail {
    #[serde(flatten)]
    pub summary: RoundSummary,
    pub program_address: String,
    pub param_set: u8,
    pub model: Model,
    pub fixed_point_model: Option<FixedPointModel>,
    pub issuer_root: Option<String>,
    /// Addresses in the snapshot, in SLOT order (features are NOT served here — only to the
    /// applicant via the feature-proof route, which the client then keeps in the browser).
    pub applicant_addresses: Vec<String>,
    pub applications: Vec<IndexedApplication>,
    pub public_key_available: bool,
    pub results: Option<RoundResults>,
    pub error: Option<String>,
    pub timings: std::collections::BTreeMap<String, u64>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FeatureProofResponse {
    pub address: String,
    /// The applicant's slot index (its position in the registered list).
    pub index: u32,
    pub features: [u32; FEATURES],
    pub cap: u64,
    pub merkle_root: String,
    pub depth: u32,
    pub indices: Vec<bool>,
    pub siblings: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RoundRequest {
    pub snapshot: Vec<Applicant>,
    pub model: Model,
    #[serde(default)]
    pub duration_secs: Option<u64>,
}
