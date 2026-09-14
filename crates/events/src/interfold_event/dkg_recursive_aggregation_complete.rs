// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Event published by [`NodeProofAggregator`] when all inner proofs for a
//! DKG node have been incrementally folded into a single aggregated proof.
//!
//! [`PublicKeyAggregator`] collects these from all honest nodes for the
//! cross-node aggregation phase.

use crate::{E3id, Proof, SignedDkgFoldAttestation};
use serde::{Deserialize, Serialize};

/// NodeProofAggregator -> PublicKeyAggregator: fully aggregated DKG node proof.
/// The test/CI node-level skip path reports `None`; the public-key aggregator
/// converts that internal state into a non-empty mock-verifier placeholder.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DKGRecursiveAggregationComplete {
    pub e3_id: E3id,
    pub party_id: u64,
    pub aggregated_proof: Option<Proof>,
    /// Binds the fold to the operator's registered address via `sk_agg` / `esm_agg` commits.
    pub fold_attestation: Option<SignedDkgFoldAttestation>,
    /// Hash of the DKG roster the folded C4 proofs were built over. Zero for a legacy sender.
    #[serde(default)]
    pub roster_hash: [u8; 32],
}

impl DKGRecursiveAggregationComplete {
    pub fn with_attestation(
        e3_id: E3id,
        party_id: u64,
        aggregated_proof: Option<Proof>,
        fold_attestation: Option<SignedDkgFoldAttestation>,
        roster_hash: [u8; 32],
    ) -> Self {
        Self {
            e3_id,
            party_id,
            aggregated_proof,
            fold_attestation,
            roster_hash,
        }
    }
}
