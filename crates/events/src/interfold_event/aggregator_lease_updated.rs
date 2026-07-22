// SPDX-License-Identifier: LGPL-3.0-only

use crate::E3id;
use actix::Message;
use serde::{Deserialize, Serialize};
use std::fmt::{self, Display};

/// Aggregation phase whose on-chain deadline is being shared with the selector.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AggregatorPhase {
    AwaitingPublicKey,
    AwaitingPlaintext,
}

/// Durable, locally-derived view of an authoritative Interfold stage deadline.
///
/// This event is emitted only after a confirmed chain progress event and a matching
/// `Interfold.getE3Stage/getDeadlines` read. It is intentionally not gossip-admissible.
#[derive(Message, Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[rtype(result = "()")]
pub struct AggregatorLeaseUpdated {
    pub e3_id: E3id,
    pub phase: AggregatorPhase,
    pub stage_deadline: u64,
}

impl Display for AggregatorLeaseUpdated {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "AggregatorLeaseUpdated {{ e3_id: {}, phase: {:?}, stage_deadline: {} }}",
            self.e3_id, self.phase, self.stage_deadline
        )
    }
}
