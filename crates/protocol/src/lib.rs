// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! The ciphernode's protocol rules, free of I/O: what a node accepts, decides, and emits.
//!
//! Each capability module owns its rules, its wire messages, and the bytes that the contracts
//! verify for it.

pub mod accusation;
pub mod decryption;
pub mod dkg;
mod e3;
mod failover;
mod ids;
mod machine;
pub mod node;
pub mod proof;
mod registry;
mod resend;
pub mod selection;
#[cfg(any(test, feature = "testing"))]
pub mod testing;
pub mod wire;

pub use ids::{BlobRef, E3Id};

/// The version of what a node persists of the machine: its inputs and effects in the journal, and
/// its snapshots. Change it with any change to their encoding; a node refuses a data directory
/// written in another version.
pub const ENCODING_VERSION: u32 = 10;
pub use machine::{Machine, Tick, UnixSecs};

use alloy_primitives::{Address, U256};
use alloy_sol_types::Eip712Domain;
use std::borrow::Cow;

/// Every Interfold contract that verifies EIP-712 data uses version "1" of its domain.
fn contract_domain(name: &'static str, chain_id: u64, verifying_contract: Address) -> Eip712Domain {
    Eip712Domain {
        name: Some(Cow::Borrowed(name)),
        version: Some(Cow::Borrowed("1")),
        chain_id: Some(U256::from(chain_id)),
        verifying_contract: Some(verifying_contract),
        salt: None,
    }
}
