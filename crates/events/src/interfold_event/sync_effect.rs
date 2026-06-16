// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use actix::Message;
use serde::{Deserialize, Serialize};
use std::fmt::{self, Display};

/// Dispatched from the Sync actor once the effect events are to be run but before buffered events are to
/// be dispatched
#[derive(Message, Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[rtype(result = "()")]
pub struct SyncEffect;

impl Default for SyncEffect {
    fn default() -> Self {
        Self::new()
    }
}

impl SyncEffect {
    pub fn new() -> Self {
        Self {}
    }
}

impl Display for SyncEffect {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}
