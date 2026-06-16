// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

#[allow(dead_code)]
mod helpers;
#[allow(dead_code)]
pub use helpers::*;

/// Call at the top of any setup function that hard-codes `CiphernodesCommitteeSize::Minimum`.
/// Returns `None` (causing the test to skip) when the compiled circuits were built for a
/// non-minimum committee — the Minimum-sized samples would not satisfy the circuit ABI.
#[allow(dead_code)]
pub fn require_minimum_circuits() -> Option<()> {
    if circuits_compiled_for_minimum() {
        Some(())
    } else {
        println!(
            "skipping: circuits not compiled for minimum committee. \
             Rebuild with `pnpm build:circuits --committee minimum` to run this test."
        );
        None
    }
}

use std::path::PathBuf;

use num_bigint::{BigInt, Sign};

#[allow(dead_code)]
pub fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
}

#[allow(dead_code)]
const FIELD_SIZE: usize = 32;

/// Extract a field element from public signals at the given index (0-based).
#[allow(dead_code)]
pub fn extract_field(signals: &[u8], index: usize) -> BigInt {
    let offset = index * FIELD_SIZE;
    BigInt::from_bytes_be(Sign::Plus, &signals[offset..offset + FIELD_SIZE])
}

/// Extract a field element from the end of public signals (0 = last, 1 = second to last, etc.)
#[allow(dead_code)]
pub fn extract_field_from_end(signals: &[u8], from_end: usize) -> BigInt {
    let total_fields = signals.len() / FIELD_SIZE;
    extract_field(signals, total_fields - 1 - from_end)
}
