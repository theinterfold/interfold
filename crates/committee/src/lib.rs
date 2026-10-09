// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Shared committee configurations and canonical honest-party selection.

use std::collections::BTreeSet;
use std::fmt;
use std::str::FromStr;

use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};

/// Committee sizes in their serialized variant order.
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
    const ALL: [Self; 3] = [Self::Minimum, Self::Micro, Self::Small];

    /// Derives the committee size from threshold values (M, N).
    pub fn from_threshold(threshold_m: usize, threshold_n: usize) -> Result<Self> {
        for size in Self::ALL {
            let committee = size.values();
            if (committee.threshold, committee.n) == (threshold_m, threshold_n) {
                return Ok(size);
            }
        }
        bail!(
            "Unknown committee size for threshold ({}, {})",
            threshold_m,
            threshold_n
        )
    }

    /// Derives the committee size from total parties (N) and honest count (H).
    pub fn from_n_h(n: usize, h: usize) -> Result<Self> {
        for size in Self::ALL {
            let committee = size.values();
            if (committee.n, committee.h) == (n, h) {
                return Ok(size);
            }
        }
        bail!("Unknown committee size for (n={n}, h={h})")
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
                h: 14,
                threshold: 9,
            },
        }
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn committee_configuration_preserves_wire_variants_and_numeric_values() {
        for (size, name, bytes, (n, h, threshold)) in [
            (
                CiphernodesCommitteeSize::Minimum,
                "Minimum",
                [0, 0, 0, 0],
                (3, 2, 1),
            ),
            (
                CiphernodesCommitteeSize::Micro,
                "Micro",
                [1, 0, 0, 0],
                (9, 5, 4),
            ),
            (
                CiphernodesCommitteeSize::Small,
                "Small",
                [2, 0, 0, 0],
                (19, 14, 9),
            ),
        ] {
            assert_eq!(bincode::serialize(&size).unwrap(), bytes);
            assert_eq!(
                bincode::deserialize::<CiphernodesCommitteeSize>(&bytes).unwrap(),
                size
            );
            assert_eq!(serde_json::to_value(size).unwrap(), name);
            let committee = size.values();
            assert_eq!(
                (committee.n, committee.h, committee.threshold),
                (n, h, threshold)
            );
            assert_eq!(
                CiphernodesCommitteeSize::from_threshold(threshold, n).unwrap(),
                size
            );
            assert_eq!(CiphernodesCommitteeSize::from_n_h(n, h).unwrap(), size);
        }
        assert!(CiphernodesCommitteeSize::from_threshold(2, 3).is_err());
        assert!(CiphernodesCommitteeSize::from_n_h(3, 3).is_err());
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
        assert_eq!(
            cap_honest_party_ids(2, [7, 2, 2, 1, 7]),
            BTreeSet::from([1, 2])
        );
        assert!(cap_honest_party_ids(0, [1, 2]).is_empty());
    }
}
