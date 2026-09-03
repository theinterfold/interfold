// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! FHE scheme identity for an E3.
//!
//! On-chain source of truth: the E3 program's `encryptionSchemeId`
//! (`bytes32`, `keccak256("fhe.rs:BFV")` / `keccak256("fhe.rs:CKKS")`),
//! returned by `IE3Program.validate` at request time and carried in the
//! `E3Requested` event's `E3` struct. The EVM reader maps that id to this
//! enum, and it travels `E3Requested` -> `E3Meta` -> `CiphernodeSelected`
//! so every actor dispatches on a chain-bound fact instead of sniffing
//! params bytes. A requester therefore chooses the scheme by choosing the
//! PROGRAM; committee size and paramSet stay scheme-independent inputs.
//!
//! `#[serde(default)]` on every carrying field keeps pre-CKKS persisted
//! events/states deserializing as `Bfv`.

use serde::{Deserialize, Serialize};

/// Which FHE scheme an E3 runs, as bound on-chain by its program.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
pub enum E3Scheme {
    /// Exact integer arithmetic (`keccak256("fhe.rs:BFV")`).
    #[default]
    Bfv,
    /// Approximate fixed-point arithmetic (`keccak256("fhe.rs:CKKS")`).
    Ckks,
}

impl E3Scheme {
    /// The preimage string of the on-chain `encryptionSchemeId`.
    pub fn scheme_id_preimage(&self) -> &'static str {
        match self {
            E3Scheme::Bfv => "fhe.rs:BFV",
            E3Scheme::Ckks => "fhe.rs:CKKS",
        }
    }
}
