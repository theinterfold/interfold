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
pub struct CommitteeViabilityUpdated {
    pub e3_id: E3id,
    pub active_count: String,
    pub threshold_m: String,
    pub viable: bool,
}

impl Display for CommitteeViabilityUpdated {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "CommitteeViabilityUpdated {{ e3_id: {}, active_count: {}, threshold_m: {}, viable: {} }}",
            self.e3_id, self.active_count, self.threshold_m, self.viable
        )
    }
}
