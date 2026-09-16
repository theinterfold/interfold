// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::E3id;
use actix::Message;
use serde::{Deserialize, Serialize};

/// Local fact emitted after an authenticated DKG roster is accepted.
#[derive(Message, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[rtype(result = "()")]
pub struct CommitmentRosterSelected {
    pub e3_id: E3id,
    /// Selected full-committee party IDs in C4 row order.
    pub party_ids: Vec<u64>,
}
