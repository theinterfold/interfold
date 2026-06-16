// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Micro committee size: N=9, T=4, H=5.
//! Parity matrices are auto-generated; switch with `pnpm build:circuits --committee micro`.

/// Number of registered parties (matches on-chain `topNodes` length).
pub global N_PARTIES: u32 = 9;
/// Secret-sharing reconstruction threshold.
pub global T: u32 = 4;
/// Honest-party count expected during the DKG (`H <= N_PARTIES`).
pub global H: u32 = 5;

pub mod parity_insecure;
pub mod parity_secure;
