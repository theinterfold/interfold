// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::{E3id, Seed};
use actix::Message;
use serde::{Deserialize, Serialize};
use std::fmt::{self, Display};

#[derive(Message, Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[rtype(result = "()")]
pub struct CommitteeRequested {
    pub e3_id: E3id,
    pub seed: Seed,
    pub threshold: [usize; 2],
    pub request_block: u64,
    pub committee_deadline: u64,
    pub chain_id: u64,
}

impl Display for CommitteeRequested {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "e3_id: {}, seed: {:?}, threshold: [{}, {}], request_block: {}, committee_deadline: {}, chain_id: {}",
            self.e3_id, self.seed, self.threshold[0], self.threshold[1], self.request_block, self.committee_deadline, self.chain_id
        )
    }
}
