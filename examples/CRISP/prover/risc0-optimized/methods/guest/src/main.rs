// SPDX-License-Identifier: LGPL-3.0-only
#![no_main]

#[cfg(not(any(crisp_fhe_optimized, crisp_fhe_reference)))]
compile_error!("The RISC Zero experiment requires an explicit optimization configuration");

use e3_support_types::{ComputeGuestInput, ComputeJournal};
use risc0_zkvm::guest::env;
use std::io::Read;

#[path = "../../../../../program/src/lib.rs"]
mod user_program;

risc0_zkvm::guest::entry!(main);

fn main() {
    let mut bytes = Vec::new();
    env::stdin()
        .take((512u64 << 20) + 1)
        .read_to_end(&mut bytes)
        .expect("Cannot read the CRISP input");
    assert!(bytes.len() <= 512 << 20, "The input exceeds the byte limit");
    let input: ComputeGuestInput =
        bincode::deserialize(&bytes).expect("Cannot decode the CRISP input");
    drop(bytes);
    let result = input
        .input
        .process(user_program::fhe_processor, user_program::policy())
        .expect("CRISP computation failed");
    let journal =
        ComputeJournal::new(input.domain, result).expect("Cannot encode the CRISP journal");
    env::commit(&journal);
}
