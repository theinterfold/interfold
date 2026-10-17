// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Committee compatibility with the compiled Noir circuits.

use crate::ConfigError;
use e3_committee::{CiphernodesCommittee, CiphernodesCommitteeSize};

/// Validate `(T, N, H)` against the canonical committee table used by compiled Noir circuits.
///
/// Callers must use the committee that the active Noir module was built with.
/// Smudging bounds and C1 public IO depend on the party count, not the BFV degree.
pub fn canonical_committee_for_circuit(
    committee: &CiphernodesCommittee,
) -> Result<CiphernodesCommittee, ConfigError> {
    let expected = CiphernodesCommitteeSize::from_threshold(committee.threshold, committee.n)
        .map_err(|e| ConfigError::Other(e.to_string()))?
        .values();
    if committee.h != expected.h {
        return Err(ConfigError::Other(format!(
            "committee.h={} does not match canonical h={} for (T={}, N={})",
            committee.h, expected.h, committee.threshold, committee.n
        )));
    }
    if committee.n != expected.n || committee.threshold != expected.threshold {
        return Err(ConfigError::Other(format!(
            "committee (T={}, N={}, H={}) is not a canonical committee size",
            committee.threshold, committee.n, committee.h
        )));
    }
    Ok(expected)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_committee_rejects_wrong_h_and_unknown_threshold_pairs() {
        for committee in [
            CiphernodesCommittee {
                n: 3,
                h: 8,
                threshold: 1,
            },
            CiphernodesCommittee {
                n: 5,
                h: 5,
                threshold: 1,
            },
        ] {
            assert!(canonical_committee_for_circuit(&committee).is_err());
        }
        for size in [
            CiphernodesCommitteeSize::Minimum,
            CiphernodesCommitteeSize::Micro,
            CiphernodesCommitteeSize::Small,
        ] {
            let committee = size.values();
            assert_eq!(
                canonical_committee_for_circuit(&committee).unwrap(),
                committee
            );
        }
    }
}
