// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Threshold CKKS integration for the Interfold node.
//!
//! Mirrors the `e3-trbfv` crate for the CKKS scheme: serializable
//! request/response job payloads for distributed key generation, encryption
//! (client side), homomorphic evaluation policies, decryption-share
//! computation, and threshold decryption. The underlying cryptography lives
//! in `fhe::ckks` and `fhe::trckks`.
//!
//! The RISC Zero guest integration is intentionally out of scope for now:
//! [`policy`] provides plain-Rust evaluation policies (the shape a Secure
//! Process would run) so the full DKG -> encrypt -> evaluate -> threshold
//! decrypt pipeline runs end to end in the node.

pub mod config;
pub mod dkg;
pub mod policy;
pub mod program;
#[cfg(test)]
mod program_tests;
pub mod threshold_decryption;

pub use config::TrCkksConfig;
pub type PartyId = u64;
