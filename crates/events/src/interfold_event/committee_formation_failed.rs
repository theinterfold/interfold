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
pub struct CommitteeFormationFailed {
    pub e3_id: E3id,
    pub nodes_submitted: String,
    pub threshold_required: String,
}

impl Display for CommitteeFormationFailed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "CommitteeFormationFailed {{ e3_id: {}, submitted: {}, required: {} }}",
            self.e3_id, self.nodes_submitted, self.threshold_required
        )
    }
}
