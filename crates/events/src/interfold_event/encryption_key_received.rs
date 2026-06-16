// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::{E3id, EncryptionKey};
use actix::Message;
use serde::{Deserialize, Serialize};
use std::fmt::{self, Display};
use std::sync::Arc;

/// Encryption key received from external sources (network).
///
/// This event is consumed by ZkActor for verification before publishing
/// `EncryptionKeyCreated`.
#[derive(Message, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[rtype(result = "()")]
pub struct EncryptionKeyReceived {
    pub e3_id: E3id,
    pub key: Arc<EncryptionKey>,
}

impl Display for EncryptionKeyReceived {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}
