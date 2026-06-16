// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::{E3id, Proof, SignedProofPayload};
use actix::Message;
use derivative::Derivative;
use e3_utils::utility_types::ArcBytes;
use serde::{Deserialize, Serialize};
use std::{
    fmt::{self, Display},
    sync::Arc,
};

/// BFV encryption key with optional proof of correct generation.
#[derive(Derivative, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[derivative(Debug)]
pub struct EncryptionKey {
    pub party_id: u64,
    #[derivative(Debug(format_with = "e3_utils::formatters::hexf"))]
    pub pk_bfv: ArcBytes,
    /// Proof of correct BFV public key generation (C0 proof).
    pub proof: Option<Proof>,
    /// ECDSA-signed payload for fault attribution.
    /// Present when the node signs its proof before broadcasting.
    pub signed_payload: Option<SignedProofPayload>,
}

impl EncryptionKey {
    pub fn new(party_id: u64, pk_bfv: impl Into<ArcBytes>) -> Self {
        Self {
            party_id,
            pk_bfv: pk_bfv.into(),
            proof: None,
            signed_payload: None,
        }
    }

    pub fn with_proof(mut self, proof: Proof) -> Self {
        self.proof = Some(proof);
        self
    }

    pub fn with_signed_payload(mut self, signed: SignedProofPayload) -> Self {
        self.signed_payload = Some(signed);
        self
    }
}

#[derive(Message, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[rtype(result = "()")]
pub struct EncryptionKeyCreated {
    pub e3_id: E3id,
    pub key: Arc<EncryptionKey>,
    pub external: bool,
}

impl Display for EncryptionKeyCreated {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}
