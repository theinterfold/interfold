// SPDX-License-Identifier: LGPL-3.0-only

use crate::E3id;
use actix::Message;
use e3_utils::ArcBytes;
use serde::{Deserialize, Serialize};
use std::fmt::{self, Display};

/// One Ethereum-backed transport chunk of a committee public-key candidate.
#[derive(Message, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[rtype(result = "()")]
pub struct CommitteePublicKeyChunkPublished {
    pub e3_id: E3id,
    pub publisher: String,
    pub candidate_hash: [u8; 32],
    pub nodes: Vec<String>,
    pub pk_commitment: [u8; 32],
    pub chunk_index: u16,
    pub chunk_count: u16,
    pub total_length: u32,
    pub chunk: ArcBytes,
}

impl Display for CommitteePublicKeyChunkPublished {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "e3_id: {}, publisher: {}, chunk: {}/{}, bytes: {}",
            self.e3_id,
            self.publisher,
            self.chunk_index + 1,
            self.chunk_count,
            self.chunk.len()
        )
    }
}
