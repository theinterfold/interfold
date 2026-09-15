// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use bincode::deserialize;
use e3_support_types::{ComputeGuestInput, ComputeJournal};
use e3_user_program::{fhe_processor, policy};
use risc0_zkvm::guest::env;
use std::io::Read;

fn main() {
    let mut input_slice = Vec::<u8>::new();
    env::stdin().read_to_end(&mut input_slice).unwrap();
    // The host sends raw bincode bytes. RISC Zero serde is reserved for the committed journal.
    let input: ComputeGuestInput = deserialize(&input_slice).unwrap();

    // The policy comes from the user program, not from a default here: it decides the input-tree
    // leaf and which inputs count, and both have to agree with what the E3 program's contract did.
    let result = input.input.process(fhe_processor, policy()).unwrap();
    let journal = ComputeJournal::new(input.domain, result).unwrap();

    env::commit(&journal);
}
