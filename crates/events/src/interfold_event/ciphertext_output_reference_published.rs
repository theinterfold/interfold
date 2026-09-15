// SPDX-License-Identifier: LGPL-3.0-only

use crate::E3id;
use actix::Message;
use serde::{Deserialize, Serialize};
use std::fmt::{self, Display};

/// Ethereum-verified reference to an aggregate ciphertext stored on a DA layer.
#[derive(Message, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[rtype(result = "()")]
pub struct CiphertextOutputReferencePublished {
    pub e3_id: E3id,
    pub content_hash: [u8; 32],
    pub ciphertext_commitment: [u8; 32],
    pub availability_block: u32,
    pub availability_leaf_index: u128,
}

impl Display for CiphertextOutputReferencePublished {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "e3_id: {}, content_hash: 0x{}, availability_block: {}, availability_leaf_index: {}",
            self.e3_id,
            hex::encode(self.content_hash),
            self.availability_block,
            self.availability_leaf_index
        )
    }
}
