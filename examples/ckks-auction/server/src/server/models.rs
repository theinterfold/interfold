// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Server-side records and API shapes (mirrors `crisp-sdk` types in `packages/ckks-auction-sdk`).

use alloy::primitives::U256;
use anyhow::Result;
use serde::{Deserialize, Serialize};

pub fn e3_id_to_u256(e3_id: &str) -> Result<U256> {
    U256::from_str_radix(e3_id, 10).map_err(|e| anyhow::anyhow!("Invalid E3 ID '{}': {}", e3_id, e))
}

/// One snapshot entry (CRISP `TokenHolder`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct TokenHolder {
    pub address: String,
    /// Raw integer balance, decimal string.
    pub balance: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum RoundStatus {
    /// E3 requested; committee DKG + relin ceremony in progress.
    Requested,
    /// Committee key published; bidding window open.
    Active,
    /// Input window closed; evaluating / waiting for the ceremony keys.
    Evaluating,
    /// Ciphertext output published; committee threshold-decrypting.
    Published,
    /// Plaintext on-chain; results decoded.
    Finished,
    Failed,
}

/// A bid accepted by the on-chain gate (`VerifiedInputPublished`).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IndexedBid {
    pub index: u64,
    pub publisher: String,
    pub transaction_hash: String,
    pub block: u64,
    pub ciphertext_hash: String,
    pub m_commitment: String,
    pub u_commitment: String,
    /// Whether the ciphertext bytes were recovered from the transaction and hash-checked.
    pub ciphertext_available: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct RoundResults {
    pub pairs: Vec<(usize, usize)>,
    pub values: Vec<f64>,
    pub signs: Vec<i8>,
    pub binarized: bool,
    pub wins: Vec<usize>,
    pub winner: usize,
    pub winner_address: Option<String>,
}

/// The per-round record (CRISP `E3Crisp`).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct E3Auction {
    pub e3_id: String,
    pub status: RoundStatus,
    pub created_at: u64,
    pub input_window: [u64; 2],
    pub bid_cap: u64,
    pub snapshot: Vec<TokenHolder>,
    /// Hex leaf hashes in snapshot order (what the tree was built from).
    pub token_holder_hashes: Vec<String>,
    pub balance_root: Option<String>,
    pub bids: Vec<IndexedBid>,
    /// Ciphertext bytes keyed by bid index (only those recovered from calldata).
    #[serde(default)]
    pub ciphertexts: Vec<(u64, Vec<u8>)>,
    pub results: Option<RoundResults>,
    pub error: Option<String>,
    /// Stage → wall-clock ms, for the timings table.
    #[serde(default)]
    pub timings: Vec<(String, u64)>,
    /// Unix timestamps of stage boundaries (`requested`, `key_published`, ...).
    #[serde(default)]
    pub stage_at: Vec<(String, u64)>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RoundSummary {
    pub e3_id: String,
    pub status: RoundStatus,
    pub bid_cap: u64,
    pub input_window: [u64; 2],
    pub bid_count: usize,
    pub created_at: u64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RoundDetail {
    #[serde(flatten)]
    pub summary: RoundSummary,
    pub program_address: String,
    pub balance_root: Option<String>,
    pub snapshot: Vec<TokenHolder>,
    pub bids: Vec<IndexedBid>,
    pub public_key_available: bool,
    pub ceremony_keys: usize,
    pub ceremony_keys_expected: usize,
    pub results: Option<RoundResults>,
    pub error: Option<String>,
    pub timings: std::collections::BTreeMap<String, u64>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BalanceProofResponse {
    pub address: String,
    pub balance: String,
    pub merkle_root: String,
    pub depth: u32,
    pub indices: Vec<bool>,
    pub siblings: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RoundRequest {
    pub snapshot: Vec<TokenHolder>,
    #[serde(default)]
    pub duration_secs: Option<u64>,
}
