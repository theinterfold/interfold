// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Event for C5 proof generation through ProofRequestActor.
//!
//! `PkAggregationProofPending` is published by [`PublicKeyAggregator`] after
//! C1 verification succeeds and synchronous aggregation completes.
//! `ProofRequestActor` generates the C5 proof, signs it, and publishes
//! `PkAggregationProofSigned`.

use crate::{E3id, OrderedSet, PkAggregationProofRequest};
use e3_utils::ArcBytes;
use serde::{Deserialize, Serialize};

/// PublicKeyAggregator -> ProofRequestActor: generate and sign C5 proof.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PkAggregationProofPending {
    pub e3_id: E3id,
    pub proof_request: PkAggregationProofRequest,
    pub public_key: ArcBytes,
    pub nodes: OrderedSet<String>,
}
