// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use actix::Message;
use serde::{Deserialize, Serialize};
use std::fmt::{self, Display};

#[derive(Message, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[rtype(result = "()")]
pub struct CiphernodeDeregistrationRequested {
    pub operator: String,
    pub unlock_at: u64,
    pub chain_id: u64,
}

impl Display for CiphernodeDeregistrationRequested {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "CiphernodeDeregistrationRequested {{ operator: {}, unlock_at: {}, chain_id: {} }}",
            self.operator, self.unlock_at, self.chain_id
        )
    }
}
