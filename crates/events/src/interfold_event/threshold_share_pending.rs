// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::{
    E3id, PkGenerationProofRequest, ShareComputationProofRequest, ShareEncryptionProofRequest,
    ThresholdShare,
};
use actix::Message;
use serde::{Deserialize, Serialize};
use std::fmt::{self, Display};
use std::sync::Arc;

#[derive(Message, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[rtype(result = "()")]
pub struct ThresholdSharePending {
    pub e3_id: E3id,
    /// Full threshold share containing all encrypted shares for all parties
    pub full_share: Arc<ThresholdShare>,
    /// The proof request data for C1 (PkGeneration)
    pub proof_request: PkGenerationProofRequest,
    /// The proof request for C2a (SkShareComputation)
    pub sk_share_computation_request: ShareComputationProofRequest,
    /// The proof request for C2b (ESmShareComputation)
    pub e_sm_share_computation_request: ShareComputationProofRequest,
    /// C3a: SK share encryption proof requests (one per recipient per modulus row)
    pub sk_share_encryption_requests: Vec<ShareEncryptionProofRequest>,
    /// C3b: E_SM share encryption proof requests (per ESI, per recipient, per modulus row)
    pub e_sm_share_encryption_requests: Vec<ShareEncryptionProofRequest>,
    /// Party IDs with collected C0 keys. Shares are sent only to these parties.
    /// `full_share` retains N-wide recipient slots for C3 proofs.
    /// Placeholder ciphertexts for absent recipients are not delivered.
    pub recipient_party_ids: Vec<u64>,
}

impl Display for ThresholdSharePending {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}
