// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Round / submission / result records served by the API and stored in sled.

use serde::{Deserialize, Serialize};

/// Lifecycle of a survey round, in on-chain order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RoundStatus {
    /// `E3Requested` seen; committee DKG + relin ceremony running.
    Requested,
    /// `CommitteePublished` seen: the joint CKKS pk is on-chain; submissions
    /// are accepted until `input_window[1]`.
    Open,
    /// The input window closed; evaluation not yet published.
    Closed,
    /// The evaluated ciphertext is on-chain; committee threshold-decrypting.
    Evaluating,
    /// `PlaintextOutputPublished` seen; statistics decoded.
    Complete,
    /// The E3 failed on-chain.
    Failed,
}

/// One submission accepted by the three-leg on-chain gate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Submission {
    /// Position in `VerifiedInputPublished` order (0-based).
    pub index: u64,
    pub publisher: String,
    pub tx_hash: String,
    pub block_number: u64,
    pub ciphertext_hash: String,
    pub m_commitment: String,
    pub u_commitment: String,
    /// Size of the stored ciphertext in bytes.
    pub ciphertext_bytes: usize,
    /// True once the indexer saw `VerifiedInputPublished` for this
    /// `u_commitment` (a relayed submission is stored optimistically with
    /// its receipt and confirmed by the event).
    pub verified: bool,
    /// Gas used by the relayed `publishInput` transaction.
    pub gas_used: Option<u64>,
    pub submitted_at: u64,
}

/// The evaluated (encrypted) output.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvaluationRecord {
    pub input_count: u64,
    pub ciphertext_bytes: usize,
    pub commitment: String,
    pub publish_tx_hash: Option<String>,
    pub evaluated_at: u64,
    pub eval_millis: u64,
}

/// The decoded statistics (the ONLY numbers ever decrypted, plus derived).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Results {
    pub count: u64,
    pub sum: f64,
    pub sum_of_squares: f64,
    pub mean: f64,
    pub variance: f64,
    pub stddev: f64,
    /// Raw opened slots (`S*sum/cap`, `S*sumsq/cap^2`).
    pub opened_slots: Vec<f64>,
    pub plaintext_hex: String,
    pub plaintext_tx_hash: Option<String>,
    pub decrypted_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Round {
    pub e3_id: String,
    pub chain_id: u64,
    pub status: RoundStatus,
    pub program_address: String,
    pub requester: String,
    pub param_set: u8,
    pub salary_cap: u64,
    pub input_window: [u64; 2],
    pub requested_at: u64,
    pub request_tx_hash: Option<String>,
    pub request_block: u64,
    /// Committee node addresses (from `CommitteePublished`).
    #[serde(default)]
    pub committee: Vec<String>,
    /// Joint CKKS public key (`0x` hex) once published.
    pub public_key_hex: Option<String>,
    pub key_published_at: Option<u64>,
    #[serde(default)]
    pub submissions: Vec<Submission>,
    pub evaluation: Option<EvaluationRecord>,
    pub results: Option<Results>,
    pub failure_reason: Option<String>,
}

impl Round {
    pub fn submission_count(&self) -> usize {
        self.submissions.len()
    }

    pub fn has_u_commitment(&self, u: &str) -> bool {
        self.submissions
            .iter()
            .any(|s| s.u_commitment.eq_ignore_ascii_case(u))
    }
}

/// Summary served by `GET /rounds`.
#[derive(Debug, Clone, Serialize)]
pub struct RoundSummary {
    pub e3_id: String,
    pub status: RoundStatus,
    pub salary_cap: u64,
    pub input_window: [u64; 2],
    pub requested_at: u64,
    pub submission_count: usize,
    pub has_public_key: bool,
    pub has_results: bool,
}

impl From<&Round> for RoundSummary {
    fn from(r: &Round) -> Self {
        Self {
            e3_id: r.e3_id.clone(),
            status: r.status,
            salary_cap: r.salary_cap,
            input_window: r.input_window,
            requested_at: r.requested_at,
            submission_count: r.submission_count(),
            has_public_key: r.public_key_hex.is_some(),
            has_results: r.results.is_some(),
        }
    }
}

/// A participant's `submission.json` (the exact shape `ckks_participant` /
/// the browser SDK produce and `program:publish-app-input` consumes).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofLeg {
    #[serde(rename = "proofHex")]
    pub proof_hex: String,
    #[serde(rename = "publicInputs")]
    pub public_inputs: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubmissionPayload {
    #[serde(default)]
    pub app: Option<String>,
    #[serde(default, rename = "paramSet")]
    pub param_set: Option<u8>,
    #[serde(rename = "ciphertextHex")]
    pub ciphertext_hex: String,
    pub ct0: ProofLeg,
    pub ct1: ProofLeg,
    #[serde(rename = "appLeg")]
    pub app_leg: ProofLeg,
}

pub fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_default()
}
