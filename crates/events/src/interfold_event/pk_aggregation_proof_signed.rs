// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Event for C5 proof signing completion.
//!
//! `PkAggregationProofSigned` is published by [`ProofRequestActor`] after
//! generating and ECDSA-signing the C5 proof. [`PublicKeyAggregator`]
//! consumes this to transition to Complete and publish `PublicKeyAggregated`.

use crate::{E3id, SignedProofPayload};
use serde::{Deserialize, Serialize};

/// ProofRequestActor -> PublicKeyAggregator: signed C5 proof.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PkAggregationProofSigned {
    pub e3_id: E3id,
    pub signed_proof: SignedProofPayload,
}
