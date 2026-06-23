// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use actix::Message;
use e3_utils::ArcBytes;
use serde::{Deserialize, Serialize};
use std::fmt::{self, Display};

use crate::E3id;

/// Lossless observation of a watched contract log that has no protocol-driving
/// typed event.
///
/// Current ABI events are named through the EVM event catalog. `known` is false
/// only when the deployed contract emits a signature absent from this binary.
#[derive(Message, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[rtype(result = "()")]
pub struct EvmLogObserved {
    pub contract: String,
    pub chain_id: u64,
    pub e3_id: Option<E3id>,
    pub event_name: String,
    pub signature: Option<String>,
    pub known: bool,
    pub topics: Vec<String>,
    pub data: ArcBytes,
}

impl Display for EvmLogObserved {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "EvmLogObserved {{ contract: {}, event: {}, chain_id: {}, known: {}, data_len: {} }}",
            self.contract,
            self.event_name,
            self.chain_id,
            self.known,
            self.data.len()
        )
    }
}
