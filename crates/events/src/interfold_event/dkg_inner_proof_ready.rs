// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Event emitted by [`ProofRequestActor`] for each inner DKG proof as it completes.
//!
//! [`NodeProofAggregator`] consumes these events and folds them incrementally
//! in strict `seq` order into a single aggregated proof.

use crate::{E3id, Proof};
use serde::{Deserialize, Serialize};

/// A single inner DKG proof ready for incremental aggregation (`NodeFold` input chain).
///
/// Emitted for every inner circuit (C0–C4) when available. `seq` gives the deterministic ordering.
///
/// The total count of expected proofs is communicated separately via
/// [`ThresholdSharePending`]. The normal flow publishes that event first, but
/// [`NodeProofAggregator`] also tolerates earlier `DKGInnerProofReady` arrivals
/// by prebuffering them until collection state exists.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DKGInnerProofReady {
    pub e3_id: E3id,
    pub party_id: u64,
    pub proof: Proof,
    /// Deterministic sequence index for ordered folding.
    pub seq: usize,
}
