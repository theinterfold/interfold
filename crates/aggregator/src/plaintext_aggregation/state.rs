// SPDX-License-Identifier: LGPL-3.0-only

//! Persisted threshold-plaintext state schema.

use super::*;

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
    /// Absolute wall-clock deadline. Hydration schedules only the remaining collection window.
    pub(crate) deadline_unix_ms: u64,
    /// Causal parent captured from the ciphertext event that opened plaintext aggregation.
    pub(crate) timeout_context: EventContext<Sequenced>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct VerifyingC6 {
    pub(crate) threshold_m: u64,
    pub(crate) threshold_n: u64,
    pub(crate) shares: BTreeMap<u64, Vec<ArcBytes>>,
    pub(crate) c6_proofs: BTreeMap<u64, Vec<SignedProofPayload>>,
    pub(crate) ciphertext_output: Vec<ArcBytes>,
    pub(crate) params: ArcBytes,
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
        deadline_unix_ms: u64,
        timeout_context: EventContext<Sequenced>,
    ) -> Self {
        ThresholdPlaintextAggregatorState::Collecting(Collecting {
            threshold_m,
            threshold_n,
            shares: BTreeMap::new(),
            c6_proofs: BTreeMap::new(),
            seed,
            ciphertext_output,
            params,
            deadline_unix_ms,
            timeout_context,
        })
    }
}
