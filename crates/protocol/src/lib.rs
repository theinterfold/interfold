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
pub mod dkg;
mod ids;
pub mod proof;

pub use ids::E3Id;

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
