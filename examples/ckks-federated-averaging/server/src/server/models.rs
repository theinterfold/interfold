// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Server-side records and API shapes (mirrors the types in `packages/ckks-fedavg-sdk`).

use alloy::primitives::U256;
use anyhow::Result;
use ckks_fedavg_program::RoundParams;
use serde::{Deserialize, Serialize};

pub fn e3_id_to_u256(e3_id: &str) -> Result<U256> {
    U256::from_str_radix(e3_id, 10).map_err(|e| anyhow::anyhow!("Invalid E3 ID '{}': {}", e3_id, e))
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum RoundStatus {
    /// E3 requested; committee DKG + level-0 relin ceremony in progress.
    Requested,
    /// Committee key published; update window open.
    Active,
    /// Input window closed; evaluating.
    Evaluating,
    /// Ciphertext output published; committee threshold-decrypting.
    Published,
    /// Plaintext on-chain; weighted mean available.
    Finished,
    Failed,
}

/// An update accepted by the on-chain gate (`UpdatePublished`): five Honk
/// proofs verified, slot `index` = the client's position in the registered list.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IndexedUpdate {
    /// The client's SLOT (its position in the registered client list).
    pub index: u64,
    pub publisher: String,
    pub transaction_hash: String,
    pub block: u64,
    pub gradient_ciphertext_hash: String,
    pub count_ciphertext_hash: String,
    pub m_commitment_grad: String,
    pub m_commitment_count: String,
    /// Whether both ciphertexts were recovered from the transaction and hash-checked.
    pub ciphertext_available: bool,
}

/// The opened output: the sample-weighted mean update and the total sample count.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct RoundResults {
    /// `opened[k]` for the first 64 coefficients (`opened[j+1] = Σ n_i g_{i,j}`, `opened[d+1] = Σ n_i`).
    pub opened: Vec<f64>,
    /// `opened[j+1] / opened[d+1]` for `j < d`.
    pub mean: Vec<f64>,
    /// `opened[d+1]` — the total number of samples across all clients.
    pub total_count: f64,
    /// The raw on-chain plaintext bytes (hex), for clients that want to decode themselves.
    pub plaintext_hex: String,
}

/// The per-round record.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct E3FedAvg {
    pub e3_id: String,
    pub status: RoundStatus,
    pub created_at: u64,
    pub input_window: [u64; 2],
    pub params: RoundParams,
    /// The norm bound as registered on-chain (`× 2^32`).
    pub norm_bound_fixed_point: u64,
    /// Registered client addresses in SLOT order.
    pub clients: Vec<String>,
    pub updates: Vec<IndexedUpdate>,
    /// `(slot index, gradient ct, count ct)` — only those recovered from calldata.
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
    pub d: usize,
    pub norm_bound: f64,
    pub min_clients: usize,
    pub input_window: [u64; 2],
    pub update_count: usize,
    pub created_at: u64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RoundDetail {
    #[serde(flatten)]
    pub summary: RoundSummary,
    pub program_address: String,
    pub param_set: u8,
    pub norm_bound_fixed_point: u64,
    /// Registered client addresses in SLOT order.
    pub clients: Vec<String>,
    pub updates: Vec<IndexedUpdate>,
    pub public_key_available: bool,
    pub results: Option<RoundResults>,
    pub error: Option<String>,
    pub timings: std::collections::BTreeMap<String, u64>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SlotResponse {
    pub address: String,
    /// The client's slot index (its position in the registered list).
    pub index: u32,
    pub d: usize,
    pub norm_bound: f64,
    /// The norm bound as the circuit takes it (`× 2^32`).
    pub norm_bound_fixed_point: u64,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RoundRequest {
    /// Registered client addresses (slot = position).
    pub clients: Vec<String>,
    pub d: usize,
    pub norm_bound: f64,
    pub min_clients: usize,
    #[serde(default)]
    pub duration_secs: Option<u64>,
}
