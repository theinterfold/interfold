// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::E3id;
use actix::Message;
use serde::{Deserialize, Serialize};
use std::fmt::{self, Display};

#[derive(Message, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[rtype(result = "()")]
pub struct RewardClaimed {
    pub e3_id: E3id,
    pub account: String,
    pub token: String,
    pub amount: String,
}

impl Display for RewardClaimed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "RewardClaimed {{ e3_id: {}, account: {}, amount: {} }}",
            self.e3_id, self.account, self.amount
        )
    }
}
