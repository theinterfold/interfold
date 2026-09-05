// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Small committee size: N=19, T=9, H=14.
//! Parity matrices are auto-generated; switch with `pnpm build:circuits --committee small`.

pub global N_PARTIES: u32 = 19;
pub global T: u32 = 9;
pub global H: u32 = 14;

pub mod parity_insecure;
pub mod parity_secure_8192;
pub mod parity_secure_16384;
pub mod smudging;
