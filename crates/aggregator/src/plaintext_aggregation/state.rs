// SPDX-License-Identifier: LGPL-3.0-only

//! Persisted threshold-plaintext state schema.

use super::*;
use e3_events::{EventContext, Sequenced};

pub const THRESHOLD_PLAINTEXT_RECOVERY_SCHEMA_VERSION: u32 = 2;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct QueuedDecryptionShare {
    pub share: Vec<ArcBytes>,
    pub proofs: Vec<SignedProofPayload>,
}

/// Restart-only inputs for re-creating interrupted plaintext aggregation effects.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ThresholdPlaintextAggregatorRecoveryState {
    pub schema_version: u32,
    pub honest_c6_proofs: Vec<(u64, Vec<Proof>)>,
    pub c7_proofs: Option<Vec<Proof>>,
    pub decryption_aggregator_proofs: Option<Vec<Proof>>,
    pub last_ec: Option<EventContext<Sequenced>>,
    /// Retained so v0.12 snapshots remain decodable. Canonical chain deadlines
    /// now own timeout failure, so the actor does not use this value.
    pub collection_deadline_unix_secs: Option<u64>,
    /// Local results keyed by the exact verification request, including replayed results.
    pub c6_outcomes: BTreeMap<[u8; 32], BTreeSet<u64>>,
}

impl Default for ThresholdPlaintextAggregatorRecoveryState {
    fn default() -> Self {
        Self {
            schema_version: THRESHOLD_PLAINTEXT_RECOVERY_SCHEMA_VERSION,
            honest_c6_proofs: Vec::new(),
            c7_proofs: None,
            decryption_aggregator_proofs: None,
            last_ec: None,
            collection_deadline_unix_secs: None,
            c6_outcomes: BTreeMap::new(),
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Collecting {
    pub(crate) threshold_m: u64,
    pub(crate) threshold_n: u64,
    pub(crate) shares: BTreeMap<u64, Vec<ArcBytes>>,
    /// Signed raw C6 proofs for ShareVerification.
    pub(crate) c6_proofs: BTreeMap<u64, Vec<SignedProofPayload>>,
    pub(crate) seed: Seed,
    pub(crate) ciphertext_output: Vec<ArcBytes>,
    pub(crate) params: ArcBytes,
    pub(crate) rejected_parties: BTreeSet<u64>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct VerifyingC6 {
    pub(crate) threshold_m: u64,
    pub(crate) threshold_n: u64,
    pub(crate) shares: BTreeMap<u64, Vec<ArcBytes>>,
    pub(crate) c6_proofs: BTreeMap<u64, Vec<SignedProofPayload>>,
    pub(crate) ciphertext_output: Vec<ArcBytes>,
    pub(crate) params: ArcBytes,
    pub(crate) seed: Seed,
    pub(crate) rejected_parties: BTreeSet<u64>,
    /// Backups must not change the batch whose verification result is pending.
    pub(crate) queued_shares: BTreeMap<u64, QueuedDecryptionShare>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Computing {
    pub(crate) threshold_m: u64,
    pub(crate) threshold_n: u64,
    pub(crate) shares: Vec<(u64, Vec<ArcBytes>)>,
    pub(crate) ciphertext_output: Vec<ArcBytes>,
    pub(crate) params: ArcBytes,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct GeneratingC7Proof {
    pub(crate) threshold_m: u64,
    pub(crate) threshold_n: u64,
    pub(crate) shares: Vec<(u64, Vec<ArcBytes>)>,
    pub(crate) plaintext: Vec<ArcBytes>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Complete {
    pub(crate) decrypted: Vec<ArcBytes>,
    pub(crate) shares: Vec<(u64, Vec<ArcBytes>)>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum ThresholdPlaintextAggregatorState {
    Collecting(Collecting),
    VerifyingC6(VerifyingC6),
    Computing(Computing),
    GeneratingC7Proof(GeneratingC7Proof),
    Complete(Complete),
}

impl TryFrom<ThresholdPlaintextAggregatorState> for Collecting {
    type Error = anyhow::Error;
    fn try_from(
        value: ThresholdPlaintextAggregatorState,
    ) -> std::result::Result<Self, Self::Error> {
        match value {
            ThresholdPlaintextAggregatorState::Collecting(s) => Ok(s),
            _ => bail!("PlaintextState was expected to be Collecting but it was not."),
        }
    }
}

impl TryFrom<ThresholdPlaintextAggregatorState> for VerifyingC6 {
    type Error = anyhow::Error;
    fn try_from(
        value: ThresholdPlaintextAggregatorState,
    ) -> std::result::Result<Self, Self::Error> {
        match value {
            ThresholdPlaintextAggregatorState::VerifyingC6(s) => Ok(s),
            _ => bail!("Inconsistent state: expected VerifyingC6"),
        }
    }
}

impl TryFrom<ThresholdPlaintextAggregatorState> for Computing {
    type Error = anyhow::Error;
    fn try_from(
        value: ThresholdPlaintextAggregatorState,
    ) -> std::result::Result<Self, Self::Error> {
        match value {
            ThresholdPlaintextAggregatorState::Computing(s) => Ok(s),
            _ => bail!("Inconsistent state: expected Computing"),
        }
    }
}

impl TryFrom<ThresholdPlaintextAggregatorState> for GeneratingC7Proof {
    type Error = anyhow::Error;
    fn try_from(
        value: ThresholdPlaintextAggregatorState,
    ) -> std::result::Result<Self, Self::Error> {
        match value {
            ThresholdPlaintextAggregatorState::GeneratingC7Proof(s) => Ok(s),
            _ => bail!("Inconsistent state: expected GeneratingC7Proof"),
        }
    }
}

impl TryFrom<ThresholdPlaintextAggregatorState> for Complete {
    type Error = anyhow::Error;
    fn try_from(
        value: ThresholdPlaintextAggregatorState,
    ) -> std::result::Result<Self, Self::Error> {
        match value {
            ThresholdPlaintextAggregatorState::Complete(s) => Ok(s),
            _ => bail!("Inconsistent state: expected Complete"),
        }
    }
}

impl ThresholdPlaintextAggregatorState {
    pub fn init(
        threshold_m: u64,
        threshold_n: u64,
        seed: Seed,
        ciphertext_output: Vec<ArcBytes>,
        params: ArcBytes,
    ) -> Self {
        ThresholdPlaintextAggregatorState::Collecting(Collecting {
            threshold_m,
            threshold_n,
            shares: BTreeMap::new(),
            c6_proofs: BTreeMap::new(),
            seed,
            ciphertext_output,
            params,
            rejected_parties: BTreeSet::new(),
        })
    }
}
