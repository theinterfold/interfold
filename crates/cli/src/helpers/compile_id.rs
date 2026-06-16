// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use petname::{Generator, Petnames};
use rand08::rngs::StdRng;
use rand08::SeedableRng;

static COMPILE_ID: u64 = compile_time::unix!();

/// Generate a unique compilation ID for the build based on the time of compilation
pub fn generate_id() -> String {
    let mut rng = StdRng::seed_from_u64(COMPILE_ID);
    format!(
        "c:{}",
        Petnames::small()
            .generate(&mut rng, 3, "_")
            .unwrap_or("default-name".to_owned())
    )
}
