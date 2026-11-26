// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::core::threshold::pk_aggregation::SUM_BIT_CARRY;
use crate::math::commitments::{
    compute_multiple_polynomial_commitment, compute_packed_polynomials_commitment,
    compute_rlk_component_commitment, compute_rlk_component_commitment_from_carriers,
    DS_RLK_AGGREGATION,
};
use crate::math::helpers::pack;
use crate::math::modulo::U64::ModU64;
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
/// `pk_aggregation` (C5), for the RLK's `d0` or `d2`).
///
/// **Role:** Sum honest parties' row limbs of one component (`d0` when `component == 0`, `d2` when
/// `component == 1`) into `agg` and commit it. Each row is proved once per component: the two
/// components are independent, and one proof per component halves the circuit, which keeps it at
/// `2^22` instead of `2^23` for secure-16384. `lbfv_aggregation_fold` verifies both proofs of a row
/// and binds them to components 0 and 1. `d1`/`a` are not part of this circuit: both are
/// compile-time constants already pinned by the verification key.
///
/// **Consumes:** `commit(values[h])` from RLK generation per honest party `h`, for this component.
///
/// **Produces:** `commit(agg)`, the same value the two-component circuit returned for that
/// component.
///
/// **Verifies:** For each limb and coefficient, `agg` matches the mod-q_l sum of the parties'
/// (centered) coefficients -- the `pk_aggregation` technique.
pub struct RlkAggregation<let N: u32, let H: u32, let L: u32, let BIT_D: u32> {
    /// Circuit parameters including CRT moduli.
    configs: Configs<L>,

    /// Expected commitments to each honest party's component row (public witnesses).
    expected_commitments: [Field; H],

    /// The component row limbs from `H` honest parties (committed witnesses).
    values: [[Polynomial<N>; L]; H],

    /// Claimed aggregate for each CRT basis. Must equal `sum(values[h][l]) mod q_l`.
    agg: [Polynomial<N>; L],
}

impl<let N: u32, let H: u32, let L: u32, let BIT_D: u32> RlkAggregation<N, H, L, BIT_D> {
    pub fn new(
        configs: Configs<L>,
        expected_commitments: [Field; H],
        values: [[Polynomial<N>; L]; H],
        agg: [Polynomial<N>; L],
    ) -> Self {
        RlkAggregation { configs, expected_commitments, values, agg }
    }

    /// Verifies that each honest party's component row hashes to its expected commitment from RLK
    /// generation. The opening packs with checked digits, which pins each coefficient to the
    /// centered value `rlk_generation` bounded.
    fn verify_commitments(self, row_index: u32, component: u32) {
        for i in 0..H {
            assert(
                compute_rlk_component_commitment::<N, L, BIT_D>(
                    component,
                    row_index,
                    self.values[i],
                )
                    == self.expected_commitments[i],
                "RLK commitment mismatch",
            );
        }
    }

    /// Verifies aggregation correctness at one CRT basis. Same modular-sum technique as
    /// `pk_aggregation::verify_pk_for_basis`.
    fn verify_sum_for_basis(self, basis_idx: u32) {
        // The quotient divided out below is at most (3H + 1) / 2; see SUM_BIT_CARRY.
        assert(H <= 128, "committee exceeds the sum carry bound");

        let q_l = self.configs.qis[basis_idx];
        let mod_q_l = ModU64::new(q_l as u64);

        let half_qi: Field = (q_l - 1) / 2;
        let h_half_qi: Field = H as Field * half_qi;
        let offset: Field = H as Field * q_l;

        // Only the aggregate needs a range check. Each party's limbs are opened with checked digits
        // from rlk_generation's commitment, which pins them to the centered values that circuit
        // bounded (as in C5).
        self.agg[basis_idx].range_check_2bounds::<BIT_D>(half_qi, half_qi);

        for coeff_idx in 0..N {
            let mut sum_shifted: Field = 0;
            for party_idx in 0..H {
                sum_shifted = sum_shifted
                    + self.values[party_idx][basis_idx].coefficients[coeff_idx]
                    + half_qi;
            }
            // The quotient is range-checked to SUM_BIT_CARRY bits instead of cast to u64.
            mod_q_l.assert_zero_mod_bounded::<SUM_BIT_CARRY>(
                sum_shifted + offset - self.agg[basis_idx].coefficients[coeff_idx] - h_half_qi,
            );
        }
    }

    /// Returns `commit(agg)` for downstream consumption.
    ///
    /// `row_index` must be the statement's range-checked row and `component` the statement's
    /// component: the row commitments it opens are bound to both through each limb commitment.
    pub fn execute(self, row_index: u32, component: u32) -> Field {
        // Step 1: Bind each party's component row to its RLK generation commitment.
        self.verify_commitments(row_index, component);

        // Step 2: Check `agg` is the mod-q_l sum of party limbs.
        for basis_idx in 0..L {
            self.verify_sum_for_basis(basis_idx);
        }

        // Step 3: Commit to the aggregate. Step 2 range-checks it to the centered window, so every
        // digit already fits its slot and plain packing is injective; checked packing would repeat
        // that bound and give the same value.
        compute_multiple_polynomial_commitment::<N, L, BIT_D>(self.agg, DS_RLK_AGGREGATION)
    }
}

/// Two parties, `N = 4`, `L = 2`, `q = [101, 97]`; the first two coefficients wrap by one modulus.
/// The parties' commitments are made for `commitment_component`.
/// [`RlkAggregation::execute`] summing the parties' rows while still packed (see
/// `math::packed_sum`). `value_carriers[party][limb]` are the carriers `rlk_generation` hashed into
/// the party's d0 or d2 row commitment; the centred aggregate is derived from their sum, so it needs
/// no witness or range check of its own. Returns the same commitment as the coefficient-wise circuit.
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

fn fixture(commitment_component: u32) -> RlkAggregation<4, 2, 2, 7> {
    let values = [
        [Polynomial::new([50, 0 - 50, 10, 0]), Polynomial::new([48, 0 - 48, 5, 7])],
        [Polynomial::new([50, 0 - 50, 20, 1]), Polynomial::new([48, 0 - 48, 5, 0 - 7])],
    ];
    // 100 - 101 = -1, -100 + 101 = 1; 96 - 97 = -1, -96 + 97 = 1.
    let agg = [Polynomial::new([0 - 1, 1, 30, 1]), Polynomial::new([0 - 1, 1, 10, 0])];
    let mut commitments = [0; 2];
    for i in 0..2 {
        commitments[i] =
            compute_rlk_component_commitment::<4, 2, 7>(commitment_component, 3, values[i]);
    }
    RlkAggregation::new(Configs::new([101, 97]), commitments, values, agg)
}

#[test]
fn test_component_commitments_match_the_d0_and_d2_forms() {
    let values = [Polynomial::new([1, 0 - 2, 3, 0]), Polynomial::new([0 - 4, 5, 0, 6])];
    assert(
        compute_rlk_component_commitment::<4, 2, 7>(0, 3, values)
            == crate::math::commitments::compute_rlk_d0_commitment::<4, 2, 7>(3, values),
    );
    assert(
        compute_rlk_component_commitment::<4, 2, 7>(1, 3, values)
            == crate::math::commitments::compute_rlk_d2_commitment::<4, 2, 7>(3, values),
    );
}

#[test]
fn test_honest_aggregation_holds_for_both_components() {
    for component in 0..2 {
        let circuit = fixture(component);
        let expected =
            compute_multiple_polynomial_commitment::<4, 2, 7>(circuit.agg, DS_RLK_AGGREGATION);
        assert(circuit.execute(3, component) == expected);
    }
}

/// A `d2` commitment does not open as `d0`: the component is bound through the kind tag.
#[test(should_fail_with = "RLK commitment mismatch")]
fn test_aggregation_rejects_the_other_components_commitments() {
    let _ = fixture(1).execute(3, 0);
}

#[test(should_fail_with = "RLK component must be d0 or d2")]
fn test_aggregation_rejects_an_unknown_component() {
    let _ = fixture(0).execute(3, 2);
}

#[test(should_fail_with = "Divisibility check failed")]
fn test_aggregation_rejects_a_wrong_sum() {
    let mut circuit = fixture(0);
    circuit.agg[0].coefficients[2] = 31;
    let _ = circuit.execute(3, 0);
}

/// The coefficient-wise circuit on `fixture`'s rows at the four-slot width (`BIT = 50`), plus the
/// carriers `rlk_generation` would have hashed.
fn wide_fixture(commitment_component: u32) -> (RlkAggregation<4, 2, 2, 50>, [[[Field; 1]; 2]; 2]) {
    let narrow = fixture(commitment_component);
    let mut commitments = [0; 2];
    let mut carriers = [[[0; 1]; 2]; 2];
    for i in 0..2 {
        commitments[i] =
            compute_rlk_component_commitment::<4, 2, 50>(commitment_component, 3, narrow.values[i]);
        for l in 0..2 {
            carriers[i][l] = [pack::<4, 50>(narrow.values[i][l].coefficients)[0]];
        }
    }
    (
        RlkAggregation::new(
            Configs::new([101, 97]),
            commitments,
            narrow.values,
            narrow.agg,
        ), carriers,
    )
}

#[test]
fn test_packed_rlk_aggregation_matches_the_coefficient_wise_circuit() {
    for component in 0..2 {
        let (circuit, carriers) = wide_fixture(component);
        let packed = packed_rlk_aggregation::<4, 2, 2, 50>(
            [101, 97],
            3,
            component,
            circuit.expected_commitments,
            carriers,
        );
        assert(packed == circuit.execute(3, component));
    }
}

#[test(should_fail_with = "RLK commitment mismatch")]
fn test_packed_rlk_aggregation_rejects_the_other_components_commitments() {
    let (circuit, carriers) = wide_fixture(1);
    let _ = packed_rlk_aggregation::<4, 2, 2, 50>(
        [101, 97],
        3,
        0,
        circuit.expected_commitments,
        carriers,
    );
}
