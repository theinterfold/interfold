// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! RLWE security limit on the ciphertext modulus q.

/// Error and secret bounds that [`MAX_LOG2_Q_128`] holds for.
const TABLE_B: u128 = 20;
const TABLE_B_CHI: u128 = 1;

/// Largest log2(q) with at least 128 bits of security, for each ring dimension d.
///
/// Source: lattice-estimator commit 53da598 with Xs = CBD(1), Xe = CBD(20) and m = 2d samples.
/// Each value is the bisected ceiling of the cheapest attack among primal BDD, primal uSVP and
/// dual-hybrid. A full estimate at each value for d <= 16384 gives 128.0 to 128.1 bits.
/// `Parameters/security/q_ceiling.py` in gnosisguild/enclave-research generates the rows.
/// Generate them again when the estimator version changes.
const MAX_LOG2_Q_128: &[(u64, f64)] =
    &[(4096, 106.4), (8192, 213.9), (16384, 430.6), (32768, 867.9)];

/// Source of a security limit on log2(q)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LimitSource {
    /// [`MAX_LOG2_Q_128`]
    Estimator,
    /// `log2(B) + (d - 75) / 37.5`. This formula allows 5 to 9 more bits of q than the estimator
    /// at the tabulated d, so the search uses it only where the table has no entry.
    Formula,
}

/// Largest log2(q) that the search accepts at ring dimension `d`, and its source.
pub fn max_log2_q(b: u128, b_chi: u128, d: u64) -> (f64, LimitSource) {
    if b == TABLE_B && b_chi == TABLE_B_CHI {
        if let Some(&(_, limit)) = MAX_LOG2_Q_128.iter().find(|(table_d, _)| *table_d == d) {
            return (limit, LimitSource::Estimator);
        }
    }
    (
        (b as f64).log2() + ((d as f64) - 75.0) / 37.5,
        LimitSource::Formula,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_is_below_the_formula_and_grows_with_d() {
        let mut prev = 0.0;
        for &(d, limit) in MAX_LOG2_Q_128 {
            let formula = (TABLE_B as f64).log2() + ((d as f64) - 75.0) / 37.5;
            assert!(limit < formula, "d={d}: table {limit} >= formula {formula}");
            assert!(limit > prev);
            prev = limit;
        }
    }

    #[test]
    fn uses_the_formula_outside_the_table() {
        assert_eq!(max_log2_q(20, 1, 8192), (213.9, LimitSource::Estimator));
        assert_eq!(max_log2_q(20, 1, 64).1, LimitSource::Formula);
        assert_eq!(max_log2_q(32, 1, 8192).1, LimitSource::Formula);
    }
}
