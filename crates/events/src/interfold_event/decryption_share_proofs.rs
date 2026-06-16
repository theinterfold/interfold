// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Events for C4 proof generation and signing flow.
//!
//! `DecryptionShareProofsPending` is published by [`ThresholdKeyshare`] when it
//! has computed the decryption data and needs C4 proofs generated and signed.
//! `ProofRequestActor` generates the proofs, signs them, and publishes
//! `DecryptionKeyShared` (Exchange #3) directly.

use crate::{DkgShareDecryptionProofRequest, E3id};
use serde::{Deserialize, Serialize};

/// ThresholdKeyshare → ProofRequestActor: generate and sign C4 proofs.
///
/// Carries the proof generation inputs (sk_request, esm_requests) and node
/// info so that ProofRequestActor can publish `DecryptionKeyShared` directly.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DecryptionShareProofsPending {
    pub e3_id: E3id,
    pub party_id: u64,
    pub node: String,
    /// C4a proof request (SecretKey decryption).
    pub sk_request: DkgShareDecryptionProofRequest,
    /// C4b proof requests (SmudgingNoise decryption), one per ESI index.
    pub esm_requests: Vec<DkgShareDecryptionProofRequest>,
}
