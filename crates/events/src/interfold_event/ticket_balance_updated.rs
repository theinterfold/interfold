// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use actix::Message;
use alloy::primitives::{FixedBytes, I256, U256};
use serde::{Deserialize, Serialize};
use std::fmt::{self, Display};

#[derive(Message, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[rtype(result = "()")]
pub struct TicketBalanceUpdated {
    pub operator: String,
    pub delta: I256,
    pub new_balance: U256,
    pub reason: FixedBytes<32>,
    pub chain_id: u64,
}

impl Display for TicketBalanceUpdated {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "operator: {}, delta: {}, new_balance: {}, chain_id: {}",
            self.operator, self.delta, self.new_balance, self.chain_id
        )
    }
}
