// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::{E3id, SignedProofPayload};
use actix::Message;
use derivative::Derivative;
use serde::{Deserialize, Serialize};
use std::fmt::{self, Display};

/// Exchange #3: Each honest node shares its aggregated trBFV partial key shares
/// with all other honest nodes, together with C4 proofs of correct BFV decryption.
#[derive(Message, Derivative, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[rtype(result = "()")]
#[derivative(Debug)]
pub struct DecryptionKeyShared {
    pub e3_id: E3id,
    /// The sender's party_id.
    pub party_id: u64,
    /// The sender's node address.
    pub node: String,
    /// ECDSA-signed C4a proof (SecretKey decryption) for verification and fault attribution.
    pub signed_sk_decryption_proof: SignedProofPayload,
    /// ECDSA-signed C4b proofs (SmudgingNoise decryption), one per smudging noise index.
    pub signed_e_sm_decryption_proofs: Vec<SignedProofPayload>,
    /// Whether this was received from the network.
    pub external: bool,
}

impl Display for DecryptionKeyShared {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "DecryptionKeyShared {{ e3_id: {}, party_id: {} }}",
            self.e3_id, self.party_id
        )
    }
}
