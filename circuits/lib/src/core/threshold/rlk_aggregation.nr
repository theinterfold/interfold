// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::math::commitments::{
    compute_packed_polynomials_commitment, compute_rlk_component_commitment_from_carriers,
    DS_RLK_AGGREGATION,
};
use crate::math::packed_sum::reduce_packed_sum;
use crate::math::polynomial::Polynomial;

/// Parameters for l-BFV relinearization key aggregation (new circuit, row-level).
pub struct Configs<let L: u32> {
    /// CRT moduli for each basis: [q_0, q_1, ..., q_{L-1}]
    pub qis: [Field; L],
}

impl<let L: u32> Configs<L> {
    pub fn new(qis: [Field; L]) -> Self {
        Configs { qis }
    }
}

/// l-BFV relinearization key aggregation for one component of one gadget row (analogous to
/// `pk_aggregation` (C5), for the RLK's `d0` or `d2`), summing the parties' rows while still packed
/// (see `math::packed_sum`).
///
/// Each row is proved once per component (`d0` when `component == 0`, `d2` when `component == 1`):
/// the two components are independent, and one proof per component halves the circuit, which keeps
/// it at `2^22` instead of `2^23` for secure-16384. `lbfv_aggregation_fold` verifies both proofs of
/// a row and binds them to components 0 and 1. `d1`/`a` are not part of this circuit; they enter
/// only through `rlk_generation`, which opens them against the generated row commitments.
///
/// `value_carriers[party][limb]` are the carriers `rlk_generation` hashed into the party's d0 or d2
/// row commitment. They open that commitment directly, which binds them to the creator's carriers
/// and so to the centred values it range-checked; the centred aggregate is derived from their sum,
/// so it needs no witness or range check of its own. `row_index` must be the statement's
/// range-checked row and `component` the statement's component: the commitments it opens are bound
/// to both through each limb commitment. Returns `commit(agg)`.
pub fn packed_rlk_aggregation<let N: u32, let H: u32, let L: u32, let BIT_D: u32>(
    qis: [Field; L],
    row_index: u32,
    component: u32,
    expected_commitments: [Field; H],
    value_carriers: [[[Field; N / 4]; L]; H],
) -> Field {
    for i in 0..H {
        assert(
            compute_rlk_component_commitment_from_carriers::<N, L>(
                component,
                row_index,
                value_carriers[i],
            )
                == expected_commitments[i],
            "RLK commitment mismatch",
        );
    }
    // Centred residues fit `BIT_D` bits of magnitude, so the moduli fit `BIT_D + 1`.
    let mut aggregate: [[Field; N / 4]; L] = [[0; N / 4]; L];
    for l in 0..L {
        aggregate[l] = reduce_packed_sum::<N / 4, H, BIT_D, BIT_D + 1, _>(
            |party, g| value_carriers[party][l][g],
            qis[l],
            true,
        );
    }
    compute_packed_polynomials_commitment::<N / 4, L>(aggregate, DS_RLK_AGGREGATION)
}

use crate::math::commitments::{
    compute_multiple_polynomial_commitment, compute_rlk_limb_d0_commitment_bounded,
    compute_rlk_limb_d2_commitment_bounded, compute_rlk_row_commitment_from_limbs,
};
use crate::math::helpers::pack;

/// Two parties, `N = 4`, `L = 2`, `q = [101, 97]`; the first two coefficients wrap by one modulus.
fn fixture_values() -> ([[Polynomial<4>; 2]; 2], [Polynomial<4>; 2]) {
    let values = [
        [Polynomial::new([50, 0 - 50, 10, 0]), Polynomial::new([48, 0 - 48, 5, 7])],
        [Polynomial::new([50, 0 - 50, 20, 1]), Polynomial::new([48, 0 - 48, 5, 0 - 7])],
    ];
    // 100 - 101 = -1, -100 + 101 = 1; 96 - 97 = -1, -96 + 97 = 1.
    let agg = [Polynomial::new([0 - 1, 1, 30, 1]), Polynomial::new([0 - 1, 1, 10, 0])];
    (values, agg)
}

/// Packs each party's limbs the way `rlk_generation` does at a four-slot width (`BIT = 50`).
fn fixture_carriers(values: [[Polynomial<4>; 2]; 2]) -> [[[Field; 1]; 2]; 2] {
    let mut carriers = [[[0; 1]; 2]; 2];
    for i in 0..2 {
        for l in 0..2 {
            carriers[i][l] = [pack::<4, 50>(values[i][l].coefficients)[0]];
        }
    }
    carriers
}

/// The row commitments `rlk_generation` outputs for `commitment_component` at row 3, built from
/// the limb commitments it computes from the coefficients.
fn generation_commitments(
    values: [[Polynomial<4>; 2]; 2],
    commitment_component: u32,
) -> [Field; 2] {
    let kind_tag = 2 + commitment_component as Field;
    let mut commitments = [0; 2];
    for i in 0..2 {
        let mut limbs = [0; 2];
        for l in 0..2 {
            limbs[l] = if commitment_component == 0 {
                compute_rlk_limb_d0_commitment_bounded::<4, 50>(3, l, values[i][l])
            } else {
                compute_rlk_limb_d2_commitment_bounded::<4, 50>(3, l, values[i][l])
            };
        }
        commitments[i] = compute_rlk_row_commitment_from_limbs(kind_tag, 3, limbs);
    }
    commitments
}

/// The circuit returns the commitment to the mod-q sum, which is hand-computed in `fixture_values`,
/// for both components.
#[test]
fn test_packed_rlk_aggregation_commits_the_modular_sum_for_both_components() {
    let (values, agg) = fixture_values();
    let expected = compute_multiple_polynomial_commitment::<4, 2, 50>(agg, DS_RLK_AGGREGATION);
    for component in 0..2 {
        let packed = packed_rlk_aggregation::<4, 2, 2, 50>(
            [101, 97],
            3,
            component,
            generation_commitments(values, component),
            fixture_carriers(values),
        );
        assert(packed == expected);
    }
}

/// A `d2` commitment does not open as `d0`: the component is bound through the kind tag.
#[test(should_fail_with = "RLK commitment mismatch")]
fn test_packed_rlk_aggregation_rejects_the_other_components_commitments() {
    let (values, _) = fixture_values();
    let _ = packed_rlk_aggregation::<4, 2, 2, 50>(
        [101, 97],
        3,
        0,
        generation_commitments(values, 1),
        fixture_carriers(values),
    );
}

/// A commitment made for another row does not open.
#[test(should_fail_with = "RLK commitment mismatch")]
fn test_packed_rlk_aggregation_rejects_another_rows_commitments() {
    let (values, _) = fixture_values();
    let _ = packed_rlk_aggregation::<4, 2, 2, 50>(
        [101, 97],
        2,
        0,
        generation_commitments(values, 0),
        fixture_carriers(values),
    );
}

#[test(should_fail_with = "RLK component must be d0 or d2")]
fn test_packed_rlk_aggregation_rejects_an_unknown_component() {
    let (values, _) = fixture_values();
    let _ = packed_rlk_aggregation::<4, 2, 2, 50>(
        [101, 97],
        3,
        2,
        generation_commitments(values, 0),
        fixture_carriers(values),
    );
}
