// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Large committee size: N=39, T=14, H=28.
//! Parity matrices are auto-generated; switch with `pnpm build:circuits --committee large`.

pub global N_PARTIES: u32 = 39;
pub global T: u32 = 14;
pub global H: u32 = 28;

pub mod parity_insecure;
pub mod parity_secure;
