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
pub struct PlaintextOutputPublished {
    pub e3_id: E3id,
    pub plaintext_output: ArcBytes,
    pub proof: ArcBytes,
}

impl Display for PlaintextOutputPublished {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "e3_id: {}, plaintext_output_len: {}, proof_len: {}",
            self.e3_id,
            self.plaintext_output.len(),
            self.proof.len()
        )
    }
}
