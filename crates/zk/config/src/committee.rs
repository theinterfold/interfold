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

/// Resolve a canonical committee row from `(n, threshold)` alone, deriving `h` from the table.
///
/// Codegen paths that parameterize the parity matrix from `(N, T)` only use this. Returns the
/// canonical row when `(n, threshold)` matches a known committee size; otherwise errors.
pub fn try_canonical_from_t_n(n: usize, threshold: usize) -> Result<CiphernodesCommittee> {
    Ok(CiphernodesCommitteeSize::from_threshold(threshold, n)?.values())
}
