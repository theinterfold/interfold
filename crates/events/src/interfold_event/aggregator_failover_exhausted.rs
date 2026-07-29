// SPDX-License-Identifier: LGPL-3.0-only

use crate::{AggregatorPhase, E3id};
use actix::Message;
use serde::{Deserialize, Serialize};
use std::fmt::{self, Display};

/// Every deterministic aggregator candidate has consumed its stage lease.
/// The Interfold writer consumes this durable event through its EVM outbox and
/// invokes the permissionless `markE3Failed` path when the chain permits it.
#[derive(Message, Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[rtype(result = "()")]
pub struct AggregatorFailoverExhausted {
    pub e3_id: E3id,
    pub phase: AggregatorPhase,
    pub stage_deadline: u64,
}

impl Display for AggregatorFailoverExhausted {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "AggregatorFailoverExhausted {{ e3_id: {}, phase: {:?}, stage_deadline: {} }}",
            self.e3_id, self.phase, self.stage_deadline
        )
    }
}
