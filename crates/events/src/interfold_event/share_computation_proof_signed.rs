// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::{E3id, SignedProofPayload};
use actix::Message;
use serde::{Deserialize, Serialize};
use std::fmt::{self, Display};

#[derive(Message, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[rtype(result = "()")]
pub struct DkgProofSigned {
    pub e3_id: E3id,
    pub party_id: u64,
    pub signed_proof: SignedProofPayload,
}

impl Display for DkgProofSigned {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}
