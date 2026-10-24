// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::math::commitments::{
    compute_aggregated_shares_commitment, compute_share_encryption_commitment_from_message_checked,
};
use crate::math::modulo::U128::centered_mod_bounded;
use crate::math::polynomial::Polynomial;

/// Bits allowed for the carry that [`normalize_aggregated`] divides out.
///
/// The aggregate is a sum of `H` coefficients, each in `[0, q)`, so the carry is at most `H`. Eight
/// bits cover every committee up to 255 members, and `execute` asserts that. It is deliberately
/// loose: the carry bound exists to keep the reduction an integer identity, not to select the
/// representative — the centered window does that — so slack costs a fraction of a gate per
/// coefficient and buys independence from the committee config.
pub global AGGREGATION_BIT_CARRY: u32 = 8;

/// DKG share decryption and aggregation (C4a / C4b).
///
/// **Role:** Verify decrypted shares against C2 commitments and publish a commitment to the sum
/// over honest parties (run twice: sk path and e_sm path).
///
/// **Consumes:** Per-party share commitments from C2 (sk or e_sm branch).
///
/// **Produces:**
/// - C4a: `commit(agg_sk)` -> C6 (threshold share decryption).
/// - C4b: `commit(agg_e_sm)` -> C6 (threshold share decryption).
///
/// `BIT_MSG` hashes per-share plaintexts (aligned with C2). `BIT_AGG` hashes the CRT aggregate
/// (`compute_aggregated_shares_commitment`) and must match threshold C6 `BIT_SK` / `BIT_E_SM`.
pub struct ShareDecryption<let N: u32, let L: u32, let H: u32, let BIT_MSG: u32, let BIT_AGG: u32> {
    /// Expected commitments to the share polynomials, produced in C2a (for C4a) or C2b (for C4b)
    /// via commit_to_party_shares. Organised as [party_idx][mod_idx], covering all H honest
    /// parties and L CRT moduli.
    /// (public witnesses)
    expected_commitments: [[Field; L]; H],

    /// Decrypted share polynomials from H honest parties.
    /// Organised as [party_idx][mod_idx].
    /// (secret witnesses)
    decrypted_shares: [[Polynomial<N>; L]; H],
}

impl<let N: u32, let L: u32, let H: u32, let BIT_MSG: u32, let BIT_AGG: u32> ShareDecryption<N, L, H, BIT_MSG, BIT_AGG> {
    pub fn new(
        expected_commitments: [[Field; L]; H],
        decrypted_shares: [[Polynomial<N>; L]; H],
    ) -> Self {
        ShareDecryption { expected_commitments, decrypted_shares }
    }

    /// Executes the share decryption and aggregation circuit.
    ///
    /// Returns a commitment to the aggregated shares:
    /// - C4a: commit(agg_sk), consumed by C6 in P4
    /// - C4b: commit(agg_e_sm), consumed by C6 in P4
    ///
    /// `moduli` must be the threshold CRT moduli `[q_0, ..., q_{L-1}]`.
    /// They are used to reverse and center the aggregated polynomials so that
    /// `compute_aggregated_shares_commitment` produces the same hash as C6's
    /// Rust witness (which operates on sk coefficients already reduced to `[0, q_l)`
    /// and then applies `.reverse()` and `.center(&qi)` before hashing).
    pub fn execute(self, moduli: [Field; L]) -> Field {
        let mut normalized: [Polynomial<N>; L] = [Polynomial::new([0; N]); L];
        for mod_idx in 0..L {
            let mut commitments = [0; H];
            let mut shares = [Polynomial::new([0; N]); H];
            for party_idx in 0..H {
                commitments[party_idx] = self.expected_commitments[party_idx][mod_idx];
                shares[party_idx] = self.decrypted_shares[party_idx][mod_idx];
            }
            normalized[mod_idx] =
                aggregate_limb::<N, H, BIT_MSG>(commitments, shares, moduli[mod_idx]);
        }

        // Publish commitment to the aggregate (C6 input).
        compute_aggregated_shares_commitment::<N, L, BIT_AGG>(normalized)
    }
}

/// C4's statement for one CRT limb with modulus `q`: every honest party's decrypted share opens its
/// C2 commitment, and the shares' sum, reversed and centered as C6 hashes it, is returned.
///
/// **Openings.** Each share is reversed to C2's highest-degree-first order and opened with the
/// checked packing helper. Asserting each digit fits its slot makes the opening unique, so the
/// witness must be the share C2 committed and already bounded to `[0, q)`. Any substitution, a
/// different decrypted value or the wrong secret key, fails the commitment check.
///
/// **Sum.** No reduction is applied while summing: each coefficient is the value C2 bounded to
/// `[0, q)`, so the sum stays under `H * q` and fits the field. This is the threshold key
/// construction, `sk = sum(sk_i)` over the honest parties.
///
/// **Normalization.** [`normalize_aggregated`]'s reduction relies on that transferred bound to cap
/// its carry at `H`; the aggregate needs no bound of its own.
pub fn aggregate_limb<let N: u32, let H: u32, let BIT_MSG: u32>(
    expected_commitments: [Field; H],
    decrypted_shares: [Polynomial<N>; H],
    q: Field,
) -> Polynomial<N> {
    for party_idx in 0..H {
        let share = decrypted_shares[party_idx];
        let mut reversed_coeffs: [Field; N] = [0; N];
        for i in 0..N {
            reversed_coeffs[N - 1 - i] = share.coefficients[i];
        }
        assert(
            compute_share_encryption_commitment_from_message_checked::<N, BIT_MSG>(Polynomial::new(
                reversed_coeffs,
            ))
                == expected_commitments[party_idx],
            "Commitment mismatch",
        );
    }

    let mut sum = [0 as Field; N];
    for coeff_idx in 0..N {
        let mut total = 0 as Field;
        for party_idx in 0..H {
            total = total + decrypted_shares[party_idx].coefficients[coeff_idx];
        }
        sum[coeff_idx] = total;
    }

    // The carry `normalize_aggregated` divides out is at most H; see AGGREGATION_BIT_CARRY.
    assert(H < 256, "committee exceeds the aggregation carry bound");
    // `BIT_MSG` is the share width, so it covers `q` and can serve as the canonical range width
    // below. Both are compile-time constants, so this folds away rather than costing gates -- it
    // turns that agreement into something the build checks instead of assumes.
    (q - 1).assert_max_bit_size::<BIT_MSG>();

    normalize_aggregated::<N, 1, BIT_MSG, AGGREGATION_BIT_CARRY>([Polynomial::new(sum)], [q])[0]
}

/// Normalize aggregated share polynomials to match C6's Rust witness representation.
///
/// C6 hashes each limb reversed (highest-degree-first) and centered, so each coefficient lands in
/// `[-(q-1)/2, (q-1)/2]` rather than `[0, q)`.
///
/// This used to reach that form in two steps: `ModU64::reduce_mod` into `[0, q)`, then a `u64`
/// comparison against `half` selecting `c` or `c - q`. Both steps carry `u64` casts -- about eleven
/// lookup gates each, four of them per coefficient -- to materialise a canonical residue that is
/// then immediately thrown away. [`centered_mod_bounded`] lands on the centered representative in
/// one division, so only the representation C6 actually hashes is ever built, and the one range
/// check it does is the one that pins the result.
///
/// The input bound is inherited, not re-derived. C2 range-checks every share coefficient to
/// `[0, q_l)`, and `verify_commitments` opens the C2 commitment with the checked packing helper, so
/// the opening is injective and the witness must be the coefficient C2 bounded. Summing `H` of them
/// gives `aggregated < H * q_l`, which is what makes the carry at most `H`.
fn normalize_aggregated<let N: u32, let L: u32, let BIT_Q: u32, let BIT_CARRY: u32>(
    aggregated: [Polynomial<N>; L],
    moduli: [Field; L],
) -> [Polynomial<N>; L] {
    let mut normalized: [Polynomial<N>; L] = [Polynomial::new([0; N]); L];

    for mod_idx in 0..L {
        let poly = aggregated[mod_idx];
        let q = moduli[mod_idx];

        let mut coeffs: [Field; N] = [0; N];
        for i in 0..N {
            // Reverse: position i gets the coefficient from N-1-i.
            coeffs[i] = centered_mod_bounded::<BIT_Q, BIT_CARRY>(poly.coefficients[N - 1 - i], q);
        }
        normalized[mod_idx] = Polynomial::new(coeffs);
    }

    normalized
}

/// `normalize_aggregated` must reverse and centre exactly as the two-step version did.
///
/// The replacement changed how the representative is reached, not which one it is: C6 hashes this
/// output, so any drift would silently break the C4-to-C6 link rather than fail a constraint. The
/// coefficients below sit on the boundaries where a reduce-then-centre and a centred division could
/// disagree -- `half`, `half + 1`, an exact multiple of `q`, and the top of the `H`-share range --
/// and the two limbs use different moduli so a limb mix-up would show.
#[test]
fn test_normalize_aggregated_reverses_and_centers() {
    // q = 101 (half = 50) and q = 97 (half = 48); sums of at most three shares.
    let aggregated = [Polynomial::new([0, 50, 51, 302]), Polynomial::new([96, 48, 49, 194])];
    let normalized = normalize_aggregated::<4, 2, 7, AGGREGATION_BIT_CARRY>(aggregated, [101, 97]);

    // Reversed, then centred: 302 -> 100 -> -1, 51 -> -50, 50 -> 50, 0 -> 0.
    assert(normalized[0].coefficients == [-1, -50, 50, 0]);
    // 194 -> 0, 49 -> -48, 48 -> 48, 96 -> -1.
    assert(normalized[1].coefficients == [0, -48, 48, -1]);
}

/// Every coefficient the honest aggregate can produce, against the formula that was replaced.
///
/// The test above pins the boundaries; this one sweeps the whole `[0, H*q)` range for a small
/// modulus, so the two definitions are compared exhaustively rather than at sampled points.
#[test]
fn test_normalize_aggregated_matches_previous_formula() {
    let q: Field = 101;
    let half = (q - 1) / 2;
    // Three shares, each in [0, q): the aggregate runs over [0, 3 * (q - 1)].
    for n in 0..303 {
        let normalized = normalize_aggregated::<1, 1, 7, AGGREGATION_BIT_CARRY>(
            [Polynomial::new([n as Field])],
            [q],
        );
        // The old path: reduce into [0, q), then subtract q above half.
        let reduced = (n % 101) as Field;
        let expected = if (reduced as u64) > (half as u64) {
            reduced - q
        } else {
            reduced
        };
        assert(normalized[0].coefficients[0] == expected);
    }
}
