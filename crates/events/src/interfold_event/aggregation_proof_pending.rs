// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Event for C7 proof generation through ProofRequestActor.
//!
//! `AggregationProofPending` is published by [`ThresholdPlaintextAggregator`]
//! after TrBFV threshold decryption completes.
//! `ProofRequestActor` generates the C7 proof(s), signs them, and publishes
//! `AggregationProofSigned`.

use crate::{DecryptedSharesAggregationProofRequest, E3id};
use e3_utils::utility_types::ArcBytes;
use serde::{Deserialize, Serialize};

/// ThresholdPlaintextAggregator -> ProofRequestActor: generate and sign C7 proofs.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AggregationProofPending {
    pub e3_id: E3id,
    pub proof_request: DecryptedSharesAggregationProofRequest,
    pub plaintext: Vec<ArcBytes>,
    pub shares: Vec<(u64, Vec<ArcBytes>)>,
}
