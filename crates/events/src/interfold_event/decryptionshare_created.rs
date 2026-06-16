// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::{E3id, SignedProofPayload};
use actix::Message;
use e3_utils::utility_types::ArcBytes;
use serde::{Deserialize, Serialize};
use std::fmt::{self, Display};

#[derive(Message, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[rtype(result = "()")]
pub struct DecryptionshareCreated {
    pub party_id: u64,
    pub decryption_share: Vec<ArcBytes>, // per index depending on what is required for the
    // ciphertext
    pub e3_id: E3id,
    pub node: String,
    /// C6 raw proofs (signed): one per ciphertext index, used for ShareVerification.
    pub signed_decryption_proofs: Vec<SignedProofPayload>,
}

impl Display for DecryptionshareCreated {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}
