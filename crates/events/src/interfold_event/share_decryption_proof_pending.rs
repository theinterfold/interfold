// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Event for C6 proof generation through ProofRequestActor.
//!
//! `ShareDecryptionProofPending` is published by [`ThresholdKeyshare`] when it
//! has computed the decryption share and needs C6 proofs generated and signed.
//! `ProofRequestActor` generates the proofs, signs them, and publishes
//! `DecryptionshareCreated` with signed proofs.

use crate::{E3id, ThresholdShareDecryptionProofRequest};
use e3_utils::utility_types::ArcBytes;
use serde::{Deserialize, Serialize};

/// ThresholdKeyshare -> ProofRequestActor: generate and sign C6 proofs.
///
/// Carries the proof generation inputs and the protocol data so that
/// ProofRequestActor can publish `DecryptionshareCreated` directly.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ShareDecryptionProofPending {
    pub e3_id: E3id,
    pub party_id: u64,
    pub node: String,
    /// Computed decryption shares, one per ciphertext index.
    pub decryption_share: Vec<ArcBytes>,
    /// C6 proof generation request.
    pub proof_request: ThresholdShareDecryptionProofRequest,
}
