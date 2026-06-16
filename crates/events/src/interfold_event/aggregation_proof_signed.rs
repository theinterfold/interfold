// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Event for C7 proof signing completion.
//!
//! `AggregationProofSigned` is published by [`ProofRequestActor`] after
//! generating and ECDSA-signing the C7 proofs. [`ThresholdPlaintextAggregator`]
//! consumes this to transition to Complete and publish `PlaintextAggregated`.

use crate::{E3id, SignedProofPayload};
use serde::{Deserialize, Serialize};

/// ProofRequestActor -> ThresholdPlaintextAggregator: signed C7 proofs.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AggregationProofSigned {
    pub e3_id: E3id,
    pub signed_proofs: Vec<SignedProofPayload>,
}
