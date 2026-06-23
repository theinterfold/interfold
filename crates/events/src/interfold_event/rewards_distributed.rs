// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::E3id;
use actix::Message;
use serde::{Deserialize, Serialize};
use std::fmt::{self, Display};

#[derive(Message, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[rtype(result = "()")]
pub struct RewardsDistributed {
    pub e3_id: E3id,
    pub nodes: Vec<String>,
    pub amounts: Vec<String>,
}

impl Display for RewardsDistributed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "RewardsDistributed {{ e3_id: {}, recipients: {} }}",
            self.e3_id,
            self.nodes.len()
        )
    }
}
