// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::CorrelationId;
use actix::Message;
use serde::{Deserialize, Serialize};
use std::fmt::{self, Display};

/// Dispatched once the sync process is complete and live listening should continue
#[derive(Message, Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[rtype(result = "()")]
pub struct SyncEnded {
    correlation_id: CorrelationId,
}

impl Default for SyncEnded {
    fn default() -> Self {
        Self::new()
    }
}

impl SyncEnded {
    pub fn new() -> Self {
        Self {
            correlation_id: CorrelationId::new(),
        }
    }
}

impl Display for SyncEnded {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}
