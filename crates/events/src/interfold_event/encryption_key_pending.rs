// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::{E3id, EncryptionKey};
use actix::Message;
use e3_committee::CiphernodesCommitteeSize;
use e3_fhe_params::BfvProfile;
use serde::{Deserialize, Serialize};
use std::fmt::{self, Display};
use std::sync::Arc;

/// Encryption key pending proof generation and verification.
///
/// This event is emitted by local key generation and consumed by ProofRequestActor.
#[derive(Message, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[rtype(result = "()")]
pub struct EncryptionKeyPending {
    pub e3_id: E3id,
    pub key: Arc<EncryptionKey>,
    pub params_profile: BfvProfile,
    pub committee_size: CiphernodesCommitteeSize,
}

impl Display for EncryptionKeyPending {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}
