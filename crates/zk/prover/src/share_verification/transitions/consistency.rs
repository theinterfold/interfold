// SPDX-License-Identifier: LGPL-3.0-only

//! Consistency-result filtering.

use super::*;

/// Filter out inconsistent parties and collect dispatched party IDs.
/// Returns `None` if all parties were filtered out (nothing to verify).
pub(crate) fn filter_consistent<P>(
    proofs: Vec<P>,
    inconsistent: &BTreeSet<u64>,
    party_id_of: impl Fn(&P) -> u64,
) -> Option<(Vec<P>, HashSet<u64>)> {
    let passed: Vec<P> = proofs
        .into_iter()
        .filter(|p| !inconsistent.contains(&party_id_of(p)))
        .collect();
    if passed.is_empty() {
        return None;
    }
    let ids = passed.iter().map(party_id_of).collect();
    Some((passed, ids))
}
