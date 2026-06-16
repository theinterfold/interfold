// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use anyhow::Result;
use derivative::Derivative;
use serde::{Deserialize, Deserializer, Serialize};
use serde_repr::{Deserialize_repr, Serialize_repr};

#[derive(Derivative, Deserialize, Serialize)]
#[derivative(Debug)]
#[serde(tag = "status", rename_all = "lowercase")]
pub enum WebhookPayload {
    Completed {
        e3_id: u64,
        #[serde(deserialize_with = "deserialize_hex_string")]
        #[derivative(Debug = "ignore")]
        ciphertext: Vec<u8>,
        #[serde(deserialize_with = "deserialize_hex_string")]
        #[derivative(Debug = "ignore")]
        proof: Vec<u8>,
    },
    Failed {
        e3_id: u64,
        error: String,
    },
}

pub fn deserialize_hex_string<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    let s: String = Deserialize::deserialize(deserializer)?;
    let hex_str = s.strip_prefix("0x").unwrap_or(&s);
    hex::decode(hex_str).map_err(serde::de::Error::custom)
}

#[derive(Debug, Deserialize, Serialize)]
pub struct JsonResponse {
    pub response: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VoteResponseStatus {
    Success,
    UserAlreadyVoted,
    FailedBroadcast,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct VoteResponse {
    pub status: VoteResponseStatus,
    pub tx_hash: Option<String>,
    pub message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_vote_update: Option<bool>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct VoteStatusRequest {
    pub round_id: u64,
    pub address: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct VoteStatusResponse {
    pub round_id: u64,
    pub address: String,
    pub has_voted: bool,
    pub round_status: Option<String>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize, Serialize)]
pub struct RoundCount {
    pub round_count: u64,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct CurrentRound {
    pub id: u64,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct PKRequest {
    pub round_id: u64,
    pub pk_bytes: Vec<u8>,
}
#[derive(Debug, Deserialize, Serialize)]
pub struct CTRequest {
    pub round_id: u64,
    pub ct_bytes: Vec<u8>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct VoteRequest {
    pub round_id: u64,
    pub encoded_proof: String,
    pub address: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct GetRoundRequest {
    pub round_id: u64,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct RoundRequestWithRequester {
    pub requesters: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct PreviousCiphertextRequest {
    pub round_id: u64,
    pub address: String,
}

#[derive(Serialize)]
pub struct PreviousCiphertextResponse {
    pub ciphertext: Vec<u8>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ComputeProviderParams {
    pub name: String,
    pub parallel: bool,
    pub batch_size: u32,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct CustomParams {
    pub token_address: String,
    pub balance_threshold: String,
    pub num_options: String,
    pub credit_mode: CreditMode,
    pub credits: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct RoundRequest {
    pub cron_api_key: String,
    pub token_address: String,
    pub balance_threshold: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct WebResultRequest {
    pub round_id: u64,
    pub tally: Vec<String>,
    pub option_1_emoji: String,
    pub option_2_emoji: String,
    pub total_votes: u64,
    pub end_time: u64,
    pub requester: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct E3StateLite {
    pub id: u64,
    pub chain_id: u64,
    pub interfold_address: String,

    pub status: String,
    pub vote_count: u64,

    pub start_time: u64,
    pub end_time: u64,
    pub start_block: u64,

    pub committee_public_key: Vec<u8>,
    pub emojis: [String; 2],

    pub token_address: String,
    pub balance_threshold: String,
    pub num_options: String,

    pub requester: String,

    pub credit_mode: CreditMode,
    pub credits: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct E3 {
    // Identifiers
    pub id: u64,
    pub chain_id: u64,
    pub interfold_address: String,

    // Status-related
    pub status: String,
    pub has_voted: Vec<String>,
    pub vote_count: u64,
    pub tally: Vec<String>,

    // Timing-related
    pub start_time: u64,
    pub block_start: u64,
    pub end_time: u64,

    // Parameters
    pub e3_params: Vec<u8>,
    pub committee_public_key: Vec<u8>,

    // Outputs
    pub ciphertext_output: Vec<u8>,
    pub plaintext_output: Vec<u8>,

    // Emojis
    pub emojis: [String; 2],

    // Custom Parameters
    pub custom_params: CustomParams,

    // The address that requested the E3
    pub requester: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct E3Crisp {
    pub emojis: [String; 2],
    pub has_voted: Vec<String>,
    pub start_time: u64,
    pub end_time: u64,
    pub status: String,
    pub tally: Vec<String>,
    pub token_holder_hashes: Vec<String>,
    pub eligible_addresses: Vec<TokenHolder>,
    pub token_address: String,
    pub balance_threshold: String,
    pub ciphertext_inputs: Vec<(Vec<u8>, u64)>,
    pub requester: String,
    pub num_options: String,
    pub credit_mode: CreditMode,
    pub credits: Option<String>,
}

impl From<E3> for WebResultRequest {
    fn from(e3: E3) -> Self {
        WebResultRequest {
            round_id: e3.id,
            tally: e3.tally,
            option_1_emoji: e3.emojis[0].clone(),
            option_2_emoji: e3.emojis[1].clone(),
            total_votes: e3.vote_count,
            end_time: e3.end_time,
            requester: e3.requester,
        }
    }
}

/// Represents a token holder with their address and balance.
/// Balance is stored as a string to preserve precision for large numbers.
#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub struct TokenHolder {
    pub address: String,
    pub balance: String,
}

/// Defines the mode of credit assignment for voters.
/// - `Constant`: All voters receive the same credit regardless of their token balance.
/// - `Custom`: Voters receive credit proportional to their token balance, with a specified threshold.
#[derive(Debug, PartialEq, Clone, Copy, Serialize_repr, Deserialize_repr)]
#[repr(u8)]
pub enum CreditMode {
    Constant = 0,
    Custom = 1,
}

impl TryFrom<u64> for CreditMode {
    type Error = eyre::Error;

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(CreditMode::Constant),
            1 => Ok(CreditMode::Custom),
            _ => Err(eyre::eyre!("Unknown credit mode: {}", value)),
        }
    }
}
