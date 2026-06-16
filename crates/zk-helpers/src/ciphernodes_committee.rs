// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use std::collections::BTreeSet;
use std::fmt;
use std::str::FromStr;

use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};

/// @todo this must be integrated inside Ciphernodes & Smart Contract
/// instead of being a separate type in here. The pvss crate should import this and
/// the default values that must be used and shared among the whole interfold repository.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CiphernodesCommitteeSize {
    /// Minimum committee size (fast local/testing).
    Minimum,
    /// Micro committee size.
    Micro,
    /// Small committee size (higher assurance).
    Small,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CiphernodesCommittee {
    /// Total number of parties (N_PARTIES).
    pub n: usize,
    /// Number of honest parties (H).
    pub h: usize,
    /// Threshold value (T).
    pub threshold: usize,
}

impl CiphernodesCommitteeSize {
    /// Derives the committee size from threshold values (M, N).
    pub fn from_threshold(threshold_m: usize, threshold_n: usize) -> Result<Self> {
        match (threshold_m, threshold_n) {
            (1, 3) => Ok(Self::Minimum),
            (4, 9) => Ok(Self::Micro),
            (9, 19) => Ok(Self::Small),
            _ => bail!(
                "Unknown committee size for threshold ({}, {})",
                threshold_m,
                threshold_n
            ),
        }
    }

    /// Derives the committee size from total parties (N) and honest count (H).
    pub fn from_n_h(n: usize, h: usize) -> Result<Self> {
        match (n, h) {
            (3, 2) => Ok(Self::Minimum),
            (9, 5) => Ok(Self::Micro),
            (19, 10) => Ok(Self::Small),
            _ => bail!("Unknown committee size for (n={n}, h={h})"),
        }
    }

    /// Lower-case name as written into `circuits/bin/.active-preset.json` and the
    /// `--committee` flag of `scripts/build-circuits.ts`. Use this for stamp/env cross-checks.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Minimum => "minimum",
            Self::Micro => "micro",
            Self::Small => "small",
        }
    }

    /// Returns `(num_parties, num_honest_parties, threshold)` for this size.
    pub fn values(self) -> CiphernodesCommittee {
        match self {
            CiphernodesCommitteeSize::Minimum => CiphernodesCommittee {
                n: 3,
                h: 2,
                threshold: 1,
            },
            CiphernodesCommitteeSize::Micro => CiphernodesCommittee {
                n: 9,
                h: 5,
                threshold: 4,
            },
            CiphernodesCommitteeSize::Small => CiphernodesCommittee {
                n: 19,
                h: 10,
                threshold: 9,
            },
        }
    }
}

/// Validate `(T, N, H)` against the canonical committee table used by compiled Noir circuits.
///
/// Returns the canonical row on success. Callers must pass the same `(threshold_m, threshold_n,
/// h)` the active `committee/*/mod.nr` was built with — smudging bounds and C1 public IO depend on
/// `N_PARTIES` (= `n`), not BFV preset degree.
pub fn canonical_committee_for_circuit(
    committee: &CiphernodesCommittee,
) -> Result<CiphernodesCommittee, anyhow::Error> {
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

impl FromStr for CiphernodesCommitteeSize {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "minimum" => Ok(Self::Minimum),
            "micro" => Ok(Self::Micro),
            "small" => Ok(Self::Small),
            _ => bail!("Unknown committee size '{s}'. Expected minimum|micro|small"),
        }
    }
}

impl fmt::Display for CiphernodesCommitteeSize {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Select the canonical honest roster of size at most `committee_h`: ascending `party_id`,
/// truncated to the lowest `H` when the candidate set is larger.
///
/// Used by the public-key aggregator (C5 / NodeFold) and threshold keyshare (C4) so both sides
/// agree on which parties occupy the circuit's `H` slots when `H < N`.
pub fn cap_honest_party_ids(
    committee_h: usize,
    party_ids: impl IntoIterator<Item = u64>,
) -> BTreeSet<u64> {
    let mut ids: Vec<u64> = party_ids.into_iter().collect();
    ids.sort_unstable();
    ids.dedup();
    if ids.len() > committee_h {
        ids.truncate(committee_h);
    }
    ids.into_iter().collect()
}

/// Merge external honest `party_id`s with `own_party_id`, then [`cap_honest_party_ids`].
pub fn canonical_honest_party_ids_with_own(
    committee_h: usize,
    external_honest_party_ids: impl IntoIterator<Item = u64>,
    own_party_id: u64,
) -> BTreeSet<u64> {
    cap_honest_party_ids(
        committee_h,
        external_honest_party_ids
            .into_iter()
            .chain(std::iter::once(own_party_id)),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_committee_for_circuit_accepts_micro_row() {
        let committee = CiphernodesCommitteeSize::Micro.values();
        assert_eq!(
            canonical_committee_for_circuit(&committee).unwrap(),
            committee
        );
    }

    #[test]
    fn cap_honest_party_ids_keeps_lowest_h() {
        let capped = cap_honest_party_ids(8, 0..10);
        assert_eq!(capped, BTreeSet::from([0, 1, 2, 3, 4, 5, 6, 7]));
    }

    #[test]
    fn cap_honest_party_ids_noop_when_at_most_h() {
        let capped = cap_honest_party_ids(8, [2u64, 0, 1]);
        assert_eq!(capped, BTreeSet::from([0, 1, 2]));
    }

    #[test]
    fn canonical_with_own_matches_global_lowest_h_when_own_is_high() {
        // Micro-style: N=9, H=5, all external 0..8 honest, own=8.
        let external: Vec<u64> = (0..9).collect();
        let canonical = canonical_honest_party_ids_with_own(5, external, 8);
        assert_eq!(canonical, BTreeSet::from([0, 1, 2, 3, 4]));
        assert!(!canonical.contains(&8));
    }

    #[test]
    fn canonical_with_own_includes_own_when_in_lowest_h() {
        let external: Vec<u64> = (0..9).collect();
        let canonical = canonical_honest_party_ids_with_own(5, external, 4);
        assert_eq!(canonical, BTreeSet::from([0, 1, 2, 3, 4]));
        assert!(canonical.contains(&4));
    }

    #[test]
    fn old_keyshare_cap_rule_diverges_from_canonical() {
        let external: Vec<u64> = (0..9).collect();
        let committee_h = 5usize;
        let own = 8u64;
        let mut old_external = external.clone();
        old_external.truncate(committee_h.saturating_sub(1));
        let mut old = BTreeSet::from_iter(old_external);
        old.insert(own);
        let canonical = canonical_honest_party_ids_with_own(committee_h, external, own);
        assert_ne!(old, canonical);
    }
}
