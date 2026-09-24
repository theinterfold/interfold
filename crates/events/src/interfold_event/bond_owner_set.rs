// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use actix::Message;
use serde::{Deserialize, Serialize};
use std::fmt::{self, Display};

#[derive(Message, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[rtype(result = "()")]
pub struct BondOwnerSet {
    pub operator: String,
    pub bond_owner: String,
    pub chain_id: u64,
}

impl Display for BondOwnerSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "BondOwnerSet {{ operator: {}, bond_owner: {}, chain_id: {} }}",
            self.operator, self.bond_owner, self.chain_id
        )
    }
}

/// A chain ownership update with its original block timestamp in seconds.
/// The event clock records ingestion time and must not define the ownership snapshot.
#[derive(Message, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[rtype(result = "()")]
pub struct BondOwnerSetAt {
    pub owner: BondOwnerSet,
    pub timepoint: u64,
}

impl Display for BondOwnerSetAt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "BondOwnerSetAt {{ owner: {}, timepoint: {} }}",
            self.owner, self.timepoint
        )
    }
}
