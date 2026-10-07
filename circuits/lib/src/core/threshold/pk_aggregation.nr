// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::math::commitments::{
    compute_pk_aggregation_commitment, compute_threshold_pk_commitment_checked,
};
use crate::math::modulo::U64::ModU64;
use crate::math::polynomial::Polynomial;

/// Parameters for threshold public key aggregation (C5).
/// Bit width of the quotient `verify_pk_for_basis` divides out of each coefficient sum.
///
/// The checked value is `sum(pk_i) + H * q - pk_agg`. Every `pk_i` equals the canonical residue C1
/// committed (the checked opening transfers that bound) and `pk_agg` is range-checked here, so each
/// lies in `[-(q-1)/2, (q-1)/2]` and the value is at most `H * q + (H + 1) * (q - 1) / 2`. Its
/// quotient by `q` is therefore at most `(3H + 1) / 2`, which is 192 at `H = 128`. Eight bits cover
/// every committee up to that size; `verify_pk_for_basis` asserts it.
///
/// Only completeness rests on this bound. A prover that opens a non-canonical `pk_i` cannot pass
/// the commitment check, and a quotient that does not fit makes the circuit unsatisfiable.
pub global SUM_BIT_CARRY: u32 = 8;

pub struct Configs<let L: u32> {
    /// CRT moduli for each basis: [q_0, q_1, ..., q_{L-1}]
    pub qis: [Field; L],
}

impl<let L: u32> Configs<L> {
    pub fn new(qis: [Field; L]) -> Self {
        Configs { qis }
    }
}

/// Threshold public key aggregation (C5).
///
/// **Role:** Sum honest parties' threshold PK limbs into `pk0_agg`, pin `pk1_agg` to the
/// circuit-constant CRS `a`, and commit the aggregated key for P3.
///
/// **Consumes:** `commit(pk0[h])` from C1 per honest party `h`.
///
/// **Produces:** `commit(pk0_agg, crp)` for user-data encryption (P3).
///
/// **Verifies:** Every party `pk0` and `pk0_agg` coefficient is a centered residue, then that
/// for each limb and coefficient `pk0_agg` matches the mod-q_l sum of party pk0. pk1_agg is not a
/// witness; the CRS `crp` is used directly, eliminating H*L*N per-party pk1 witness elements and
/// the pk1 consistency loop.
pub struct PkAggregation<let N: u32, let H: u32, let L: u32, let BIT_PK: u32> {
    /// Circuit parameters including CRT moduli
    configs: Configs<L>,

    /// Common Reference String polynomials (circuit constant, one per CRT basis).
    /// Used directly as pk1_agg in the final commitment; no per-party pk1 witness needed.
    crp: [Polynomial<N>; L],

    /// Expected commitments to each honest party's threshold public key share.
    /// commit(pk0[h]) produced by C1 for each h in H.
    /// (public witnesses)
    expected_threshold_pk_commitments: [Field; H],

    /// Individual threshold public key first components from H honest parties.
    /// pk0[party_idx][basis_idx] for each party and CRT basis.
    /// (committed witnesses)
    pk0: [[Polynomial<N>; L]; H],

    /// Claimed aggregated public key first component for each CRT basis.
    /// Must equal sum(pk0[h][l]) mod q_l for each basis l.
    /// (committed witness)
    pk0_agg: [Polynomial<N>; L],
}

impl<let N: u32, let H: u32, let L: u32, let BIT_PK: u32> PkAggregation<N, H, L, BIT_PK> {
    pub fn new(
        configs: Configs<L>,
        crp: [Polynomial<N>; L],
        expected_threshold_pk_commitments: [Field; H],
        pk0: [[Polynomial<N>; L]; H],
        pk0_agg: [Polynomial<N>; L],
    ) -> Self {
        PkAggregation { configs, crp, expected_threshold_pk_commitments, pk0, pk0_agg }
    }

    /// Bounds every `pk0_agg` coefficient to a centered residue `[-(q_l-1)/2, (q_l-1)/2]`.
    ///
    /// Only `pk0_agg` needs this. The per-party `pk0` limbs are opened from C1's commitment, and
    /// `compute_threshold_pk_commitment_checked` makes that opening unique, so they are forced to
    /// equal the coefficients C1 committed and already bounded. `pk0_agg` is opened from nothing:
    /// `verify_pk_for_basis` pins it only modulo `q_l`, so `pk0_agg + k * q_l` satisfies the sum for
    /// any `k`, and the packing slot alone would admit `k` of order a hundred. A non-canonical
    /// aggregate breaks honest encryption downstream, because `user_data_encryption_ct0` does not
    /// bound `pk0is` and its `r1` bounds were derived for a centered key.
    fn verify_pk_ranges(self) {
        for basis_idx in 0..L {
            let bound: Field = (self.configs.qis[basis_idx] - 1) / 2;
            self.pk0_agg[basis_idx].range_check_2bounds::<BIT_PK>(bound, bound);
        }
    }

    /// Verifies that each honest party's pk0 hashes to its expected commitment from C1.
    ///
    /// C1 commits only to pk0 (not pk1) because pk1 = CRS is a public constant.
    /// Binding pk0 per-party is sufficient: pk1 is pinned globally via the crp field.
    ///
    /// Opens with the checked packing helper: asserting each digit fits its slot makes the opening
    /// unique, so the witness must be the coefficients C1 committed. That transfers C1's centered
    /// bound at one assert per coefficient instead of repeating it as a two-sided range check.
    fn verify_pk_commitments(self) {
        for i in 0..H {
            assert(
                compute_threshold_pk_commitment_checked::<N, L, BIT_PK>(self.pk0[i])
                    == self.expected_threshold_pk_commitments[i],
                "PK commitment mismatch",
            );
        }
    }

    /// Verifies aggregation correctness for one component (pk0 or pk1) at a given CRT basis.
    ///
    /// For each coefficient position i, checks:
    ///   pk_agg[basis_idx][i] = sum(pk[h][basis_idx][i]) mod q_l  for h in 0..H
    ///
    /// The modular reduction ensures the aggregated coefficients stay within
    /// the valid range for the CRT modulus q_l.
    fn verify_pk_for_basis(
        self,
        pk: [[Polynomial<N>; L]; H],
        pk_agg: [Polynomial<N>; L],
        basis_idx: u32,
    ) {
        // The quotient divided out below is at most (3H + 1) / 2; see SUM_BIT_CARRY.
        assert(H <= 128, "committee exceeds the sum carry bound");

        let q_l = self.configs.qis[basis_idx];
        let mod_q_l = ModU64::new(q_l as u64);

        let half_qi: Field = (q_l - 1) / 2;
        let h_half_qi: Field = H as Field * half_qi;
        // Offset keeps (sum_shifted - expected_unred + offset) non-negative in the integer
        // sense (not Field-wrapped). sum_shifted in [0, H*q_l), expected_unred in
        // [(H-1)*q_l/2, (H+1)*q_l/2) -> delta + H*q_l >= (H-1)*q_l/2 >= 0.
        let offset: Field = H as Field * q_l;

        for coeff_idx in 0..N {
            let mut sum_shifted: Field = 0;
            for party_idx in 0..H {
                sum_shifted =
                    sum_shifted + pk[party_idx][basis_idx].coefficients[coeff_idx] + half_qi;
            }
            // Single divisibility check replaces two reduce_mod calls + equality assert, and the
            // quotient is range-checked to SUM_BIT_CARRY bits instead of cast to u64.
            mod_q_l.assert_zero_mod_bounded::<SUM_BIT_CARRY>(
                sum_shifted + offset - pk_agg[basis_idx].coefficients[coeff_idx] - h_half_qi,
            );
        }
    }

    /// Returns `commit(pk0_agg, crp)` for P3 (`user_data_encryption_ct0` / `ct1`).
    pub fn execute(self) -> Field {
        // Step 1: Pin every opened coefficient to a single centered residue. Must run before the
        // commitment check, which is only binding for bounded coefficients.
        self.verify_pk_ranges();

        // Step 2: Bind each party pk0 to its C1 commitment.
        self.verify_pk_commitments();

        // Step 3: Check `pk0_agg` is the mod-q_l sum of party pk0 limbs (per CRT basis).
        for basis_idx in 0..L {
            self.verify_pk_for_basis(self.pk0, self.pk0_agg, basis_idx);
        }

        // Step 4: Commit to (pk0_agg, crp). crp is the circuit-constant CRS a used as pk1_agg.
        compute_pk_aggregation_commitment::<N, L, BIT_PK>(self.pk0_agg, self.crp)
    }
}

/// Three parties, `N = 4`, `L = 2`, `q = [101, 97]`. The first two coefficients sit at the edges
/// of the centered range so the sums wrap by one modulus in each direction.
fn fixture() -> PkAggregation<4, 3, 2, 7> {
    let qis = [101, 97];
    let pk0 = [
        [Polynomial::new([50, 0 - 50, 10, 0]), Polynomial::new([48, 0 - 48, 5, 7])],
        [Polynomial::new([50, 0 - 50, 20, 1]), Polynomial::new([48, 0 - 48, 5, 0 - 7])],
        [Polynomial::new([50, 0 - 50, 0 - 30, 2]), Polynomial::new([48, 0 - 48, 5, 1])],
    ];
    // 150 - 101 = 49, -150 + 101 = -49; 144 - 97 = 47, -144 + 97 = -47.
    let pk0_agg = [Polynomial::new([49, 0 - 49, 0, 3]), Polynomial::new([47, 0 - 47, 15, 1])];
    let crp = [Polynomial::new([1, 2, 3, 4]), Polynomial::new([5, 6, 7, 8])];

    let mut commitments = [0; 3];
    for i in 0..3 {
        commitments[i] = compute_threshold_pk_commitment_checked::<4, 2, 7>(pk0[i]);
    }

    PkAggregation::new(Configs::new(qis), crp, commitments, pk0, pk0_agg)
}

#[test]
fn honest_aggregation_holds() {
    let circuit = fixture();
    let expected = compute_pk_aggregation_commitment::<4, 2, 7>(circuit.pk0_agg, circuit.crp);
    assert(circuit.execute() == expected);
}

#[test(should_fail_with = "Divisibility check failed")]
fn wrong_sum_is_rejected() {
    let mut circuit = fixture();
    circuit.pk0_agg[0].coefficients[2] = 1;
    let _ = circuit.execute();
}

/// `49 - 101` is the same residue as the honest `49`, so the sum check alone accepts it. The range
/// check is what pins the aggregate to one representative.
#[test(should_fail)]
fn non_canonical_aggregate_is_rejected() {
    let mut circuit = fixture();
    circuit.pk0_agg[0].coefficients[0] = 49 - 101;
    let _ = circuit.execute();
}

#[test(should_fail_with = "PK commitment mismatch")]
fn party_key_not_matching_its_commitment_is_rejected() {
    let mut circuit = fixture();
    // Keeps the sum intact, so only the commitment check can catch it.
    circuit.pk0[0][0].coefficients[3] = 1;
    circuit.pk0[1][0].coefficients[3] = 0;
    let _ = circuit.execute();
}
