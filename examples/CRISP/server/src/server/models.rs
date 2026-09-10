// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use alloy::primitives::U256;
use anyhow::Result;
use derivative::Derivative;
use serde::{Deserialize, Deserializer, Serialize};
use serde_repr::{Deserialize_repr, Serialize_repr};

pub fn e3_id_to_u256(e3_id: &str) -> Result<U256> {
    U256::from_str_radix(e3_id, 10).map_err(|e| anyhow::anyhow!("Invalid E3 ID '{}': {}", e3_id, e))
}

pub fn canonical_e3_id(e3_id: &str) -> Result<String> {
    Ok(e3_id_to_u256(e3_id)?.to_string())
}

#[derive(Derivative, Deserialize, Serialize)]
#[derivative(Debug)]
#[serde(tag = "status", rename_all = "lowercase")]
pub enum WebhookPayload {
    Completed {
        e3_id: String,
        #[serde(deserialize_with = "deserialize_hex_string")]
        #[derivative(Debug = "ignore")]
        ciphertext: Vec<u8>,
        #[serde(deserialize_with = "deserialize_hex_string")]
        #[derivative(Debug = "ignore")]
        ciphertext_commitment: Vec<u8>,
        #[serde(deserialize_with = "deserialize_hex_string")]
        #[derivative(Debug = "ignore")]
        proof: Vec<u8>,
    },
    Failed {
        e3_id: String,
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
    PendingCommitment,
    PendingAvailability,
    ReadyForCommitment,
    FailedBroadcast,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct VoteResponse {
    pub status: VoteResponseStatus,
    pub tx_hash: Option<String>,
    pub job_id: Option<String>,
    pub encoded_proof: Option<String>,
    pub message: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct VoteStatusRequest {
    pub round_id: String,
    pub address: String,
}

/// Whether a slot holds any published entry, not whether its owner voted.
///
/// The server cannot answer "has this address voted": a mask is indistinguishable from a vote by
/// design, and both write an entry to the slot. Any per-address answer the server could give is
/// slot activity, so the field says exactly that. A client that wants "did *I* vote" must remember
/// its own submissions.
#[derive(Debug, Deserialize, Serialize)]
pub struct VoteStatusResponse {
    pub round_id: String,
    pub address: String,
    pub slot_active: bool,
    pub round_status: Option<String>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize, Serialize)]
pub struct RoundCount {
    pub round_count: u64,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct CurrentRound {
    pub id: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct PKRequest {
    pub round_id: String,
    pub pk_bytes: Vec<u8>,
}
#[derive(Debug, Deserialize, Serialize)]
pub struct CTRequest {
    pub round_id: String,
    pub ct_bytes: Vec<u8>,
}

#[derive(Debug, Deserialize, Serialize)]
/// A relay request: the round and the encoded input, nothing else.
///
/// Deliberately no address field. The slot is already inside the encoded proof, and the relay has
/// no use for a caller-supplied copy — every byte the relay does not receive is a byte it cannot
/// log, so a masker's session leaves nothing linking it to the slot it masked beyond the proof
/// itself. Old clients that still send one are tolerated: serde ignores unknown fields.
pub struct VoteRequest {
    pub round_id: String,
    pub encoded_proof: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct GetRoundRequest {
    pub round_id: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct RoundRequestWithRequester {
    pub requesters: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct PreviousCiphertextRequest {
    pub round_id: String,
    pub address: String,
}

#[derive(Serialize)]
pub struct PreviousCiphertextResponse {
    pub ciphertext: Vec<u8>,
    /// The tree index of that entry, which a client names as the parent of the input it builds.
    pub index: u64,
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
    pub census_mode: CensusMode,
    /// Divides raw token power into ballot units for a `CensusMode::Onchain` round. `"0"` means
    /// the contract derives it from the token's decimals. Recorded because a round may name its
    /// own: scaling by the decimals then puts every served balance in different units from the
    /// ones `publishInput` will enforce.
    pub voting_power_divisor: String,
}

#[derive(Debug, Deserialize)]
pub struct RoundRequest {
    pub cron_api_key: String,
    pub token_address: String,
    pub balance_threshold: String,
    /// The census source for the round, as a `CRISPProgram.CensusMode` discriminant. Optional:
    /// normal token rounds default to 0 (TOKEN), and a known `SelfRegistry` defaults to
    /// 2 (ONCHAIN). A `SelfRegistry` cannot use 0, because token-holder discovery would find no
    /// voters and the server would have no CRISP record to show clients.
    #[serde(default)]
    pub census_mode: Option<u64>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct WebResultRequest {
    pub round_id: String,
    pub tally: Vec<String>,
    pub option_1_emoji: String,
    pub option_2_emoji: String,
    pub total_votes: u64,
    pub end_time: u64,
    pub requester: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct E3StateLite {
    pub id: String,
    pub chain_id: u64,
    pub interfold_address: String,

    pub status: String,
    pub vote_count: u64,

    pub start_time: u64,
    pub end_time: u64,
    /// The EIP-6372 timepoint (timestamp) the E3 was requested at
    pub start_block: u64,
    /// The EIP-6372 timepoint (timestamp) the census was built at. Named for a block
    /// height for backwards compatibility with stored rounds and the web API.
    pub snapshot_block: u64,

    pub committee_public_key: Vec<u8>,
    pub emojis: [String; 2],

    pub token_address: String,
    pub balance_threshold: String,
    pub num_options: String,

    pub requester: String,

    pub credit_mode: CreditMode,
    pub credits: Option<String>,
    /// Served so a client can tell which ballot circuit a round needs. Without it a client
    /// cannot distinguish an ONCHAIN round and would build a Merkle witness for it, which no
    /// verifier accepts.
    pub census_mode: CensusMode,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct E3 {
    // Identifiers
    pub id: String,
    pub chain_id: u64,
    pub interfold_address: String,

    // Status-related
    pub status: String,
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

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct E3Crisp {
    pub emojis: [String; 2],
    pub start_time: u64,
    /// Last timestamp at which a voter can commit a new proof. The protocol input window ends
    /// later so the availability service can finalize already committed ciphertexts.
    #[serde(default)]
    pub voting_end_time: u64,
    pub end_time: u64,
    pub status: String,
    pub tally: Vec<String>,
    pub token_holder_hashes: Vec<String>,
    pub eligible_addresses: Vec<TokenHolder>,
    pub token_address: String,
    pub balance_threshold: String,
    pub ciphertext_inputs: Vec<(Vec<u8>, u64)>,
    /// The commitment the contract stored for each input, keyed by the same on-chain index.
    ///
    /// The Secure Process needs it to check that the published bytes are the ciphertext that was
    /// actually proven. Defaulted so rounds recorded before the event carried it still load.
    #[serde(default)]
    pub input_commitments: Vec<(u64, [u8; 32])>,
    /// The slot each input was published to, keyed by the same on-chain index. The tree is
    /// append-only, so the Secure Process groups entries by slot.
    #[serde(default)]
    pub input_slots: Vec<(u64, [u8; 20])>,
    /// Whether each input's published bytes reproduce the commitment stored with it, keyed by the
    /// same on-chain index.
    ///
    /// Recomputing this costs a BFV commitment — about 5ms per entry — and the answer never changes,
    /// because the tree is append-only and an entry's bytes are fixed once published. Deciding it
    /// once here keeps it off the read path, where `state/previous-ciphertext` is called by every
    /// voter before every ballot.
    ///
    /// A hint, not an authority. The Secure Process recomputes it from the ciphertexts it consumed
    /// and never reads this, so a wrong value here can only send a client to the wrong parent — the
    /// same outcome as a stale read, and the guest drops such an input either way.
    #[serde(default)]
    pub input_usable: Vec<(u64, bool)>,
    /// The entry each input names as the one it extends, plus one, keyed by the same on-chain
    /// index. Zero means it extends nothing.
    ///
    /// The Secure Process walks each slot's chain by this, taking an entry only when the one it
    /// names is the slot's current head. That is what keeps a slot writable after someone publishes
    /// bytes nobody can open: such an entry is never the head, so it is never a valid parent, and
    /// the next honest input names the same parent it did.
    #[serde(default)]
    pub input_parents: Vec<(u64, u64)>,
    pub requester: String,
    pub num_options: String,
    pub credit_mode: CreditMode,
    pub credits: Option<String>,
    /// The EIP-6372 timepoint (timestamp) the census was built at. Defaults to 0 for
    /// rounds stored before this field existed, which is resolved when the round state
    /// is read. Named for a block height for backwards compatibility.
    #[serde(default)]
    pub snapshot_block: u64,
    /// Defaults to `Token` for rounds stored before this field existed, which is what they
    /// were: `Onchain` did not exist when they were written.
    #[serde(default)]
    pub census_mode: CensusMode,
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

/// Where a round's eligible voter set comes from. Mirrors `CRISPProgram.CensusMode`.
///
/// `Token` reconstructs holders from transfer logs. `ByRequester` asks the requesting contract,
/// which already knows its own membership.
///
/// Required in the params and never inferred: a round that omits it fails to decode rather than
/// quietly becoming a token vote over the wrong people.
#[derive(Debug, Default, PartialEq, Clone, Copy, Serialize_repr, Deserialize_repr)]
#[repr(u8)]
pub enum CensusMode {
    #[default]
    Token = 0,
    ByRequester = 1,
    /// No census at all. `CRISPProgram` reads voting power from the token per input, so the
    /// coordinator enumerates nothing and posts no root.
    Onchain = 2,
}

impl TryFrom<u64> for CensusMode {
    type Error = eyre::Error;

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(CensusMode::Token),
            1 => Ok(CensusMode::ByRequester),
            2 => Ok(CensusMode::Onchain),
            _ => Err(eyre::eyre!("Unknown census mode: {}", value)),
        }
    }
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

#[cfg(test)]
mod persisted_round_tests {
    use super::{CensusMode, CreditMode, E3Crisp};

    /// A round written before `census_mode` existed. Kept verbatim rather than generated, so a
    /// change to the struct cannot quietly change what "legacy" means. It still carries
    /// `has_voted`, which the struct no longer has — stored rounds do too, and decoding must
    /// ignore it rather than refuse the round.
    const LEGACY_ROUND: &str = r#"{
        "emojis": ["a", "b"],
        "has_voted": [],
        "start_time": 1,
        "end_time": 2,
        "status": "Active",
        "tally": [],
        "token_holder_hashes": [],
        "eligible_addresses": [],
        "token_address": "0x0",
        "balance_threshold": "0",
        "ciphertext_inputs": [],
        "requester": "0x0",
        "num_options": "2",
        "credit_mode": 1,
        "credits": null
    }"#;

    /// `E3Crisp` carries no schema version, and `census_mode` was added with `#[serde(default)]`
    /// alongside `snapshot_block`, which was added the same way. The default is sound for the only
    /// population that can lack the field: every stored round predates `Onchain`, so it was a
    /// token census by construction. This pins that, so a future variant reordering — which would
    /// silently move the default — fails here instead of at a vote.
    #[test]
    fn a_round_stored_before_census_mode_reads_as_token() {
        let round: E3Crisp =
            serde_json::from_str(LEGACY_ROUND).expect("legacy round must still decode");

        assert_eq!(round.census_mode, CensusMode::Token);
        assert_eq!(round.snapshot_block, 0);
        assert_eq!(round.credit_mode, CreditMode::Custom);
    }

    #[test]
    fn every_census_mode_round_trips_through_storage() {
        for mode in [
            CensusMode::Token,
            CensusMode::ByRequester,
            CensusMode::Onchain,
        ] {
            let mut round: E3Crisp = serde_json::from_str(LEGACY_ROUND).unwrap();
            round.census_mode = mode;

            let encoded = serde_json::to_string(&round).unwrap();
            let decoded: E3Crisp = serde_json::from_str(&encoded).unwrap();

            assert_eq!(decoded.census_mode, mode, "mode did not survive storage");
        }
    }
}

#[cfg(test)]
mod census_mode_tests {
    use super::CensusMode;

    #[test]
    fn unknown_values_are_rejected_rather_than_defaulted() {
        // A mode the coordinator does not understand must stop the round, not quietly become a
        // token vote — which is the failure this enum exists to prevent.
        assert!(CensusMode::try_from(3u64).is_err());
        assert!(CensusMode::try_from(u64::MAX).is_err());
    }

    #[test]
    fn known_values_round_trip() {
        // Values must match `CRISPProgram.CensusMode`, which the contract range-checks against
        // `type(CensusMode).max`. A discriminant that drifts from Solidity would route a round
        // down the wrong census path rather than failing.
        assert_eq!(CensusMode::try_from(0u64).unwrap(), CensusMode::Token);
        assert_eq!(CensusMode::try_from(1u64).unwrap(), CensusMode::ByRequester);
        assert_eq!(CensusMode::try_from(2u64).unwrap(), CensusMode::Onchain);
    }
}

#[cfg(test)]
mod e3_id_tests {
    use super::{canonical_e3_id, e3_id_to_u256};

    #[test]
    fn accepts_full_width_decimal_ids() {
        let id: alloy::primitives::U256 =
            (alloy::primitives::U256::from(1) << 200) + alloy::primitives::U256::from(7);
        assert_eq!(e3_id_to_u256(&id.to_string()).unwrap(), id);
    }

    #[test]
    fn rejects_non_decimal_ids() {
        assert!(e3_id_to_u256("not-an-id").is_err());
    }

    #[test]
    fn canonicalizes_padded_decimal_ids() {
        assert_eq!(canonical_e3_id("00042").unwrap(), "42");
    }
}
