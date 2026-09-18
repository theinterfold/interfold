// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
include!(concat!(env!("OUT_DIR"), "/methods.rs"));

pub use CRISP_RISC0_BASELINE_GUEST_ELF as GUEST_ELF;
pub use CRISP_RISC0_BASELINE_GUEST_ID as GUEST_ID;
pub const KERNEL: &str = "production-pinned compute-provider, shared CRISP program source, production bincode input and RISC Zero journal";
pub const COMPUTE_PROVIDER_REVISION: &str = "5668f4c9ee0992aeb05b320eaa3b998a6c32e525";
pub const OPTIMIZATIONS: &[&str] = &[];

pub fn selected_guest() -> (
    &'static [u8],
    [u32; 8],
    &'static str,
    &'static [&'static str],
) {
    (GUEST_ELF, GUEST_ID, KERNEL, OPTIMIZATIONS)
}
