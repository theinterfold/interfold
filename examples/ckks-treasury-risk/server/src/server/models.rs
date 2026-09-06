// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Server-side records and API shapes (mirrors the types in `packages/ckks-treasury-sdk`).

use alloy::primitives::U256;
use anyhow::Result;
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
    /// Input window closed (or enough DAOs in); evaluating.
    Evaluating,
    /// Ciphertext output published; committee threshold-decrypting.
    Published,
    /// Plaintext on-chain; the risk is available.
    Finished,
    Failed,
}

/// A submission accepted by the on-chain gate (`SubmissionPublished`): seven Honk
/// proofs verified, slot `index` = the DAO's position in the registered list.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IndexedSubmission {
    /// The DAO's SLOT (position in the registered list).
    pub index: u64,
    pub publisher: String,
    pub transaction_hash: String,
    pub block: u64,
    pub forward_ciphertext_hash: String,
    pub reversed_ciphertext_hash: String,
    pub mask_ciphertext_hash: String,
    pub m_commitment_fwd: String,
    pub m_commitment_rev: String,
    pub m_commitment_mask: String,
    /// Whether all three ciphertexts were recovered from the transaction and hash-checked.
    pub ciphertext_available: bool,
}

/// The opened output: 64 coefficients at 4 decimals; `risk = −opened[0]`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct RoundResults {
    /// The weighted concentration risk `Σ_a w_a (Σ_i x_{i,a})²` of the combined book.
    pub risk: f64,
    /// The raw opened coefficients (`opened[0] = −risk`; `1..` are masked cross terms).
    pub opened: Vec<f64>,
    /// The raw on-chain plaintext bytes (hex), for clients that want to decode themselves.
    pub plaintext_hex: String,
}

/// `(slot index, forward ct, reversed ct, mask ct)` as recovered from calldata.
pub type IndexedCiphertexts = (u64, Vec<u8>, Vec<u8>, Vec<u8>);

/// The per-round record.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct E3Treasury {
    pub e3_id: String,
    pub status: RoundStatus,
    pub created_at: u64,
    pub input_window: [u64; 2],
    /// The round's public risk weights (real values, `|w| ≤ 1`).
    pub weights: [f64; ckks_treasury_program::ASSETS],
    /// The registered DAOs in SLOT order.
    pub daos: Vec<String>,
    pub submissions: Vec<IndexedSubmission>,
    /// `(slot index, forward ct, reversed ct, mask ct)` — only those recovered from calldata.
    #[serde(default)]
    pub ciphertexts: Vec<IndexedCiphertexts>,
    pub results: Option<RoundResults>,
    pub error: Option<String>,
    /// Stage → wall-clock ms, for the timings table.
    #[serde(default)]
    pub timings: Vec<(String, u64)>,
    /// Unix timestamps of stage boundaries (`requested`, `active`, ...).
    #[serde(default)]
    pub stage_at: Vec<(String, u64)>,
}

impl E3Treasury {
    pub fn weights(&self) -> ckks_treasury_program::Weights {
        ckks_treasury_program::Weights(self.weights)
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RoundSummary {
    pub e3_id: String,
    pub status: RoundStatus,
    pub input_window: [u64; 2],
    pub weights: [f64; ckks_treasury_program::ASSETS],
    pub dao_count: usize,
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
    pub assets: usize,
    pub min_daos: usize,
    /// The weights in fixed point (`× 2^16`, signed) exactly as registered on-chain.
    pub weights_fixed: [i32; ckks_treasury_program::ASSETS],
    /// The registered DAOs in SLOT order.
    pub daos: Vec<String>,
    pub submissions: Vec<IndexedSubmission>,
    pub public_key_available: bool,
    pub results: Option<RoundResults>,
    pub error: Option<String>,
    pub timings: std::collections::BTreeMap<String, u64>,
}

/// `GET /rounds/{id}/slot/{address}`: the DAO's registered slot.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SlotResponse {
    pub address: String,
    /// The DAO's slot index (position in the registered list).
    pub index: u32,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RoundRequest {
    /// The round's public risk weights (real values, `|w| ≤ 1`).
    pub weights: Vec<f64>,
    /// The DAOs allowed to submit (slot = position).
    pub daos: Vec<String>,
    #[serde(default)]
    pub duration_secs: Option<u64>,
}
