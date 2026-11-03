// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Committee compatibility with the compiled Noir circuits.

use anyhow::Result;
use e3_committee::{CiphernodesCommittee, CiphernodesCommitteeSize};

/// Validate `(T, N, H)` against the canonical committee table used by compiled Noir circuits.
///
/// Callers must use the committee that the active Noir module was built with.
/// Smudging bounds and C1 public IO depend on the party count, not the BFV degree.
pub fn canonical_committee_for_circuit(
    committee: &CiphernodesCommittee,
) -> Result<CiphernodesCommittee> {
    let expected =
        CiphernodesCommitteeSize::from_threshold(committee.threshold, committee.n)?.values();
    if committee.h != expected.h {
        anyhow::bail!(
            "committee.h={} does not match canonical h={} for (T={}, N={})",
            committee.h,
            expected.h,
            committee.threshold,
            committee.n
        );
    }
    if committee.n != expected.n || committee.threshold != expected.threshold {
        anyhow::bail!(
            "committee (T={}, N={}, H={}) is not a canonical committee size",
            committee.threshold,
            committee.n,
            committee.h
        );
    }
    Ok(expected)
}
