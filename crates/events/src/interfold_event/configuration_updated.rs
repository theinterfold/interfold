// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use actix::Message;
use alloy::primitives::U256;
use serde::{Deserialize, Serialize};
use std::fmt::{self, Display};

#[derive(Message, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[rtype(result = "()")]
pub struct ConfigurationUpdated {
    pub parameter: String,
    pub old_value: U256,
    pub new_value: U256,
    pub chain_id: u64,
}

impl Display for ConfigurationUpdated {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "parameter: {}, old_value: {}, new_value: {}, chain_id: {}",
            self.parameter, self.old_value, self.new_value, self.chain_id
        )
    }
}
