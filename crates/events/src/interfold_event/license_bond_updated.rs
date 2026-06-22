// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use actix::Message;
use alloy::primitives::{I256, U256};
use serde::{Deserialize, Serialize};
use std::fmt::{self, Display};

#[derive(Message, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[rtype(result = "()")]
pub struct LicenseBondUpdated {
    pub operator: String,
    pub delta: I256,
    pub new_bond: U256,
    pub reason: [u8; 32],
    pub chain_id: u64,
}

impl Display for LicenseBondUpdated {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "LicenseBondUpdated {{ operator: {}, new_bond: {}, chain_id: {} }}",
            self.operator, self.new_bond, self.chain_id
        )
    }
}
