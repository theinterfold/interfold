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
pub struct E3Requested {
    /// The E3 round ID
    pub e3_id: E3id,
    /// The minimum number of shares required to decrypt a ciphertext
    pub threshold_m: usize,
    /// The total committee size for the round
    pub threshold_n: usize,
    /// Shared per-E3 seed for the E3 computation.
    pub seed: Seed,
    /// Timestamp-mode checkpoint recorded when the E3 was requested.
    pub request_block: u64,
    /// The error size for the FHE computation. This can be calculated for the E3 program based on
    /// the size of the ciphertext and the depth of the program [tbd add link]
    pub error_size: ArcBytes,
    /// The threshold BFV preset selected on-chain. The DKG counterpart is
    /// derived automatically via `BfvPreset::dkg_counterpart()`.
    pub params_preset: BfvPreset,
    /// ABI-encoded BFV parameters (derived from `params_preset`).
    /// Kept for downstream code that needs the raw bytes (e.g. `TrBFVConfig`).
    pub params: ArcBytes,
    /// FHE scheme, mapped from the on-chain `encryptionSchemeId` the E3
    /// program bound at request time. Defaults to `Bfv` for events
    /// serialized before this field existed.
    #[serde(default)]
    pub scheme: crate::E3Scheme,
}

impl Default for E3Requested {
    fn default() -> Self {
        E3Requested {
            e3_id: E3id::new("99", 0),
            error_size: ArcBytes::from_bytes(&[]),
            params_preset: BfvPreset::InsecureThreshold512,
            params: ArcBytes::from_bytes(&[]),
            seed: Seed([0u8; 32]),
            request_block: 0,
            threshold_m: 0,
            threshold_n: 0,
            scheme: crate::E3Scheme::default(),
        }
    }
}

impl Display for E3Requested {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}
