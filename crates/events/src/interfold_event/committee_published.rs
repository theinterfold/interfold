// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::E3id;
use actix::Message;
use e3_utils::ArcBytes;
use serde::{Deserialize, Serialize};
use std::fmt::{self, Display};

#[derive(Message, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[rtype(result = "()")]
pub struct CommitteePublished {
    pub e3_id: E3id,
    pub nodes: Vec<String>,
    pub public_key: ArcBytes,
    pub proof: ArcBytes,
}

impl Display for CommitteePublished {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "e3_id: {}, nodes: {:?}, public_key_len: {}, proof_len: {}",
            self.e3_id,
            self.nodes,
            self.public_key.len(),
            self.proof.len()
        )
    }
}
