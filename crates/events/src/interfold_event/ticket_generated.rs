// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::E3id;
use actix::Message;
use serde::{Deserialize, Serialize};
use std::fmt::{self, Display};

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TicketId {
    Score(u64),
}

#[derive(Message, Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[rtype(result = "()")]
pub struct TicketGenerated {
    pub e3_id: E3id,
    pub ticket_id: TicketId,
    pub node: String,
    pub party_index: Option<u64>,
}

impl Display for TicketGenerated {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "e3_id: {}, ticket_id: {:?}, node: {}, party_index: {:?}",
            self.e3_id, self.ticket_id, self.node, self.party_index
        )
    }
}
