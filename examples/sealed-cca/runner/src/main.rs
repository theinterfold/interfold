// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Serves this project's E3 program. `interfold program start` runs `program-runner dev` for the
//! unproved development runner, or `program-runner openvm` for the OpenVM proving service.

fn main() -> anyhow::Result<()> {
    e3_program_runner::run(e3_user_program::fhe_processor, e3_user_program::policy())
}
