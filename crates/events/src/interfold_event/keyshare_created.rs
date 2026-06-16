// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::{E3id, SignedProofPayload};
use actix::Message;
use derivative::Derivative;
use e3_utils::ArcBytes;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::fmt::Display;

#[derive(Derivative, Message, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[derivative(Debug)]
#[rtype(result = "anyhow::Result<()>")]
pub struct KeyshareCreated {
    pub pubkey: ArcBytes,
    pub e3_id: E3id,
    pub node: String,
    /// Real sortition-assigned party id. Required (no `serde(default)`): a missing value
    /// would silently default to 0 and mis-route shares.
    pub party_id: u64,
    pub signed_pk_generation_proof: Option<SignedProofPayload>,
}

impl Display for KeyshareCreated {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}
