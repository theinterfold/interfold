// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::E3id;
use actix::Message;
use serde::{Deserialize, Serialize};
use std::fmt::{self, Display};

// Re-export E3Stage from e3_failed to avoid duplication
pub use super::e3_failed::E3Stage;

#[derive(Message, Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[rtype(result = "()")]
pub struct E3StageChanged {
    pub e3_id: E3id,
    pub previous_stage: E3Stage,
    pub new_stage: E3Stage,
}

impl Display for E3StageChanged {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "E3StageChanged {{ e3_id: {}, {:?} -> {:?} }}",
            self.e3_id, self.previous_stage, self.new_stage
        )
    }
}
