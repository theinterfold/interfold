// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::math::commitments::{
    compute_aggregated_shares_commitment, compute_aggregated_shares_commitment_from_carriers,
    compute_sc_party_share_root_from_carriers,
    compute_share_encryption_commitment_from_message_checked,
};
use crate::math::modulo::U128::centered_mod_bounded;
use crate::math::packed_sum::reduce_packed_sum;
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

/// The l-BFV C4 (C4a / C4b), summing the shares while they are still packed.
///
/// [`ShareDecryption`] opens every sender's share coefficient by coefficient: it rebuilds each
/// packed carrier from `H * L * N` witnessed coefficients and range-checks every digit, so that the
/// opening is injective. That per-sender work is almost all of C4 at larger committees. Here the
/// witnesses are the packed carriers themselves: `share_carriers[sender][limb][g]` holds reversed
/// coefficients `4g..4g + 4` exactly as C2 packed them, digit `v + 2^nib` in radix `R = 2^(nib + 4)`,
/// where `nib` is `BIT_MSG` rounded up to a nibble (52 at secure-16384, 56 at insecure).
///
/// 1. **Opening.** Each sender's carriers are hashed into its C2 chunk root
///    ([`compute_sc_party_share_root_from_carriers`]). Collision resistance makes them C2's carriers,
///    and C2 range-checked every digit in them to `[0, q)` when it created the commitment, so they
///    need no check here.
/// 2. **Packed sum.** Adding the `H` senders' carriers adds every slot at once. Subtracting
///    `H * B`, with `B` the packed base offsets, leaves `S = sum_i R^(3 - i) * s_i` where `s_i` is
///    the slot sum, below `H * q <= R`, so no slot carries into the next.
/// 3. **Unpack and centre.** Hints `k_i, c_i` with `k_i < 2^K`, `c_i + half in [0, q)` and
///    `S == sum_i R^(3 - i) * (k_i * q + c_i)`, where `K = nib + 4 - BIT_MSG` makes
///    `2^K * q <= R`. Each digit `k_i * q + c_i` then lies in a window narrower than one slot, so
///    two digit vectors meeting the same `S` agree slot by slot from the lowest one up: the digits
///    are the slot sums `s_i` (whose honest carry is at most `H < 2^K`), and `c_i` is the centred
///    residue [`normalize_aggregated`] computes. Every term is below `2^241`, far from the field
///    prime, so the field identity is the integer one.
/// 4. **Commit.** The aggregate's carrier is `S - q * sum_i R^(3 - i) * k_i + B`, the packing of
///    the `c_i` that [`compute_aggregated_shares_commitment`] builds, in the same reversed order, so
///    the output equals the unpacked circuit's.
///
/// `BIT_MSG` and `BIT_AGG` must round to the same nibble width with four slots per carrier.
pub fn packed_share_decryption<let N: u32, let L: u32, let H: u32, let N_CHUNKS: u32, let CHUNK_SIZE: u32, let BIT_MSG: u32, let BIT_AGG: u32>(
    expected_commitments: [[Field; L]; H],
    share_carriers: [[[Field; N / 4]; L]; H],
    recipient_party_idx: u32,
    moduli: [Field; L],
) -> Field {
    let nib = ((BIT_MSG + 3) / 4) * 4;
    // Four slots per carrier, the same layout for the shares and the aggregate.
    assert(254 / (nib + 4) == 4, "share carriers must hold four slots");
    assert(((BIT_AGG + 3) / 4) * 4 == nib, "aggregate carriers must match the share layout");

    // Step 1: open every sender's share root from its carriers.
    for sender in 0..H {
        for mod_idx in 0..L {
            assert(
                compute_sc_party_share_root_from_carriers::<N, N_CHUNKS, CHUNK_SIZE>(
                    recipient_party_idx,
                    mod_idx,
                    share_carriers[sender][mod_idx],
                )
                    == expected_commitments[sender][mod_idx],
                "Commitment mismatch",
            );
        }
    }

    // Steps 2-4: sum the carriers, unpack and centre the slot sums, repack the aggregate.
    let mut aggregate: [[Field; N / 4]; L] = [[0; N / 4]; L];
    for mod_idx in 0..L {
        aggregate[mod_idx] = reduce_packed_sum::<N / 4, H, BIT_MSG, BIT_MSG, _>(
            |sender, g| share_carriers[sender][mod_idx][g],
            moduli[mod_idx],
            false,
        );
    }

    compute_aggregated_shares_commitment_from_carriers::<N, L>(aggregate)
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

use crate::math::commitments::compute_sc_party_share_root_from_reversed;
use crate::math::helpers::pack;

/// The unpacked l-BFV C4 the packed tests compare against: open each sender's chunk root from its
/// coefficients, then sum, normalize and commit as [`aggregate_limb`] does.
fn unpacked_chunk_root_decryption<let N: u32, let L: u32, let H: u32, let BIT_MSG: u32, let BIT_AGG: u32>(
    expected_commitments: [[Field; L]; H],
    decrypted_shares: [[Polynomial<N>; L]; H],
    recipient_party_idx: u32,
    moduli: [Field; L],
) -> Field {
    let mut aggregated: [Polynomial<N>; L] = [Polynomial::new([0; N]); L];
    for mod_idx in 0..L {
        let mut sum = [0; N];
        for sender in 0..H {
            let share = decrypted_shares[sender][mod_idx];
            assert(
                compute_sc_party_share_root_from_reversed::<N, 2, 4, BIT_MSG>(
                    recipient_party_idx,
                    mod_idx,
                    share,
                )
                    == expected_commitments[sender][mod_idx],
                "Commitment mismatch",
            );
            for i in 0..N {
                sum[i] += share.coefficients[i];
            }
        }
        aggregated[mod_idx] = Polynomial::new(sum);
    }
    let normalized =
        normalize_aggregated::<N, L, BIT_MSG, AGGREGATION_BIT_CARRY>(aggregated, moduli);
    compute_aggregated_shares_commitment::<N, L, BIT_AGG>(normalized)
}

/// Packs each sender's reversed share the way C2 does (4 slots per carrier) for the packed tests.
fn packed_test_inputs<let BIT: u32>() -> ([[Field; 2]; 3], [[[Field; 2]; 2]; 3], [[Polynomial<8>; 2]; 3]) {
    // Three senders, two limbs (q = 101, 97), degree 8; every coefficient a canonical residue, with
    // slot sums reaching 3 * (q - 1) so the carry and the centred boundary both get exercised.
    let shares = [
        [
            Polynomial::new([0, 50, 51, 100, 7, 99, 1, 100]),
            Polynomial::new([96, 48, 49, 0, 96, 12, 13, 96]),
        ],
        [
            Polynomial::new([100, 0, 50, 100, 33, 99, 2, 100]),
            Polynomial::new([96, 48, 0, 1, 96, 40, 41, 96]),
        ],
        [
            Polynomial::new([1, 100, 51, 100, 60, 99, 3, 100]),
            Polynomial::new([96, 1, 48, 2, 96, 70, 71, 96]),
        ],
    ];
    let mut expected = [[0; 2]; 3];
    let mut carriers = [[[0; 2]; 2]; 3];
    for sender in 0..3 {
        for mod_idx in 0..2 {
            let share = shares[sender][mod_idx];
            expected[sender][mod_idx] =
                compute_sc_party_share_root_from_reversed::<8, 2, 4, BIT>(1, mod_idx, share);
            let mut reversed = [0; 8];
            for i in 0..8 {
                reversed[i] = share.coefficients[7 - i];
            }
            let packed = pack::<8, BIT>(reversed);
            carriers[sender][mod_idx] = [packed[0], packed[1]];
        }
    }
    (expected, carriers, shares)
}

#[test]
fn test_packed_share_decryption_matches_the_unpacked_opening() {
    let (expected, carriers, shares) = packed_test_inputs::<51>();
    let unpacked =
        unpacked_chunk_root_decryption::<8, 2, 3, 51, 50>(expected, shares, 1, [101, 97]);
    let packed = packed_share_decryption::<8, 2, 3, 2, 4, 51, 50>(expected, carriers, 1, [101, 97]);
    assert(packed == unpacked);
}

#[test(should_fail_with = "Commitment mismatch")]
fn test_packed_share_decryption_rejects_a_tampered_carrier() {
    let (expected, mut carriers, _) = packed_test_inputs::<51>();
    // Move one unit between two slots: same carrier sum, different digits.
    carriers[0][1][0] += 2.pow_32(56) - 1;
    let _ = packed_share_decryption::<8, 2, 3, 2, 4, 51, 50>(expected, carriers, 1, [101, 97]);
}

#[test(should_fail_with = "Commitment mismatch")]
fn test_packed_share_decryption_rejects_the_wrong_recipient() {
    let (expected, carriers, _) = packed_test_inputs::<51>();
    let _ = packed_share_decryption::<8, 2, 3, 2, 4, 51, 50>(expected, carriers, 2, [101, 97]);
}

#[test]
fn test_packed_share_decryption_matches_at_the_insecure_layout() {
    // 56-bit shares round to 56-bit nibbles: 60-bit slots, still four per carrier, 4-bit carries.
    let (expected, carriers, shares) = packed_test_inputs::<56>();
    let unpacked =
        unpacked_chunk_root_decryption::<8, 2, 3, 56, 55>(expected, shares, 1, [101, 97]);
    let packed = packed_share_decryption::<8, 2, 3, 2, 4, 56, 55>(expected, carriers, 1, [101, 97]);
    assert(packed == unpacked);
}
