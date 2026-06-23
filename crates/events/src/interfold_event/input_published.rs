// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::E3id;
use actix::Message;
use e3_utils::ArcBytes;
use serde::{Deserialize, Serialize};
use std::fmt::{self, Display};

#[derive(Message, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[rtype(result = "()")]
pub struct InputPublished {
    pub e3_id: E3id,
    pub data: ArcBytes,
    pub input_hash: String,
    pub index: String,
}

impl Display for InputPublished {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "InputPublished {{ e3_id: {}, index: {}, data_len: {} }}",
            self.e3_id,
            self.index,
            self.data.len()
        )
    }
}
