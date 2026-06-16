// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::{E3id, Seed};
use actix::Message;
use e3_fhe_params::BfvPreset;
use e3_utils::utility_types::ArcBytes;
use serde::{Deserialize, Serialize};
use std::fmt::{self, Display};

#[derive(Message, Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[rtype(result = "()")]
pub struct CiphernodeSelected {
    pub e3_id: E3id,
    pub threshold_m: usize,
    pub threshold_n: usize,
    pub seed: Seed,
    pub error_size: ArcBytes,
    pub params_preset: BfvPreset,
    pub params: ArcBytes,
    pub party_id: u64,
}

impl Default for CiphernodeSelected {
    fn default() -> Self {
        CiphernodeSelected {
            e3_id: E3id::new("0", 0),
            error_size: ArcBytes::from_bytes(&[]),
            params_preset: BfvPreset::InsecureThreshold512,
            params: ArcBytes::from_bytes(&[]),
            party_id: 0,
            seed: Seed([0u8; 32]),
            threshold_m: 0,
            threshold_n: 0,
        }
    }
}

impl Display for CiphernodeSelected {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}
