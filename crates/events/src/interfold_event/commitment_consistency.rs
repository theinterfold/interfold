// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Events for cross-circuit commitment consistency checking.
//!
//! The [`ShareVerificationActor`] publishes [`CommitmentConsistencyCheckRequested`]
//! after ECDSA validation but **before** ZK proof verification, carrying each
//! party's public signals. The per-E3 [`CommitmentConsistencyChecker`] caches
//! the signals, evaluates all registered commitment links, and responds with
//! [`CommitmentConsistencyCheckComplete`]. Only parties that pass the consistency
//! check proceed to ZK verification.

use crate::{CorrelationId, E3id, ProofType, VerificationKind};
use alloy::primitives::{Address, Bytes};
use e3_utils::utility_types::ArcBytes;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// Per-party proof data for commitment consistency checking.
///
/// Contains the public signals extracted from the party's ECDSA-validated
/// (but not yet ZK-verified) signed proofs.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PartyProofData {
    pub party_id: u64,
    pub address: Address,
    /// Each entry is a `(proof_type, public_signals, data_hash, proof_data)` tuple
    /// from a signed proof. The `data_hash` is `keccak256(abi.encode(proof.data,
    /// public_signals))` — used for the accusation protocol if a consistency
    /// violation is detected. The `proof_data` (raw `proof.data` bytes) is forwarded
    /// alongside so the on-chain slashing contract can recompute the dataHash from
    /// the evidence preimage `abi.encode(proof_data, public_signals)`.
    pub proofs: Vec<(ProofType, ArcBytes, [u8; 32], ArcBytes)>,
}

/// Published by [`ShareVerificationActor`] after ECDSA validation, before ZK.
///
/// Tells the [`CommitmentConsistencyChecker`] to cache proof data and evaluate
/// all registered commitment links. The checker responds with
/// [`CommitmentConsistencyCheckComplete`] on the same `correlation_id`.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CommitmentConsistencyCheckRequested {
    pub e3_id: E3id,
    pub kind: VerificationKind,
    pub correlation_id: CorrelationId,
    pub party_proofs: Vec<PartyProofData>,
}

/// Response from [`CommitmentConsistencyChecker`].
///
/// If `inconsistent_parties` is empty, all parties' commitments are consistent
/// with previously cached proofs and the verification pipeline may proceed to
/// ZK verification. Otherwise, the listed parties should be treated as
/// dishonest and excluded from ZK verification.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CommitmentConsistencyCheckComplete {
    pub e3_id: E3id,
    pub kind: VerificationKind,
    pub correlation_id: CorrelationId,
    /// Parties whose commitments are inconsistent with previously cached proofs.
    pub inconsistent_parties: BTreeSet<u64>,
}

/// Emitted by [`CommitmentConsistencyChecker`] when a party's commitment
/// values are inconsistent across circuit proofs.
///
/// Consumed by [`AccusationManager`] to initiate the off-chain accusation
/// quorum protocol — the same flow as [`ProofVerificationFailed`] but for
/// cross-circuit commitment mismatches rather than ZK proof failures.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CommitmentConsistencyViolation {
    pub e3_id: E3id,
    /// Party whose commitment is inconsistent.
    pub accused_party_id: u64,
    /// Recovered Ethereum address of the accused party.
    pub accused_address: Address,
    /// The proof type (source side) whose commitment value doesn't match.
    pub proof_type: ProofType,
    /// `keccak256(abi.encode(proof.data, public_signals))` of the accused party's
    /// proof — matches the data_hash used by the accusation protocol.
    pub data_hash: [u8; 32],
    /// Raw `abi.encode(proof.data, public_signals)` — preimage of `data_hash`.
    /// Forwarded to `SlashingManager.proposeSlash` so the on-chain contract can
    /// verify `keccak256(evidence) == dataHash` bound in voter signatures.
    pub evidence: Bytes,
}
