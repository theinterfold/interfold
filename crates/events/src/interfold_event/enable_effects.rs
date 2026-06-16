// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::CorrelationId;
use actix::Message;
use serde::{Deserialize, Serialize};
use std::fmt::{self, Display};

/// Dispatched once effects (side-effects) should be activated after a sync pass
#[derive(Message, Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[rtype(result = "()")]
pub struct EffectsEnabled {
    correlation_id: CorrelationId,
}

impl Default for EffectsEnabled {
    fn default() -> Self {
        Self::new()
    }
}

impl EffectsEnabled {
    pub fn new() -> Self {
        Self {
            correlation_id: CorrelationId::new(),
        }
    }
}

impl Display for EffectsEnabled {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}
