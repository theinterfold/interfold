// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Threshold-CKKS keyshare capability (scheme twin of `threshold_keyshare`).
//!
//! Layers, bottom-up:
//! - `workflow`: pure plan-building functions over `e3_fhe::CkksFhe`;
//! - `encrypted_dkg`: per-recipient BFV transport of dealt Shamir rows;
//! - `proofs`: the C2 share-constraint gate;
//! - `machine`: the pure phase machine (events in, commands out) covering
//!   DKG, the two-round relin-key ceremony with chunked transport, and
//!   single-use threshold decryption;
//! - `timing`: machine-readable `ckks_timing` marks the actor shell emits.
//!
//! The actor shell (`threshold_keyshare::effects::ckks_shell`) drives the
//! machine for E3s whose program binds `E3Scheme::Ckks`.

#[cfg(test)]
mod c8_gate_tests;
pub mod encrypted_dkg;
#[cfg(test)]
mod encrypted_dkg_tests;
pub mod machine;
#[cfg(test)]
mod machine_tests;
pub mod proofs;
#[cfg(test)]
mod proofs_tests;
pub mod timing;
pub mod workflow;
#[cfg(test)]
mod workflow_tests;
