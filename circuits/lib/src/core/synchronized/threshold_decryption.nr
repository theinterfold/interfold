// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Direct Minimum C6. Public setup/domain/anchors require the final verifier's canonical authority.

use crate::core::threshold::decrypted_shares_aggregation::lagrange_coefficients;
use crate::math::commitments::{
    compute_aggregated_shares_commitment_checked, compute_commitment,
    compute_multiple_polynomial_commitment_checked, compute_threshold_decryption_share_commitment,
    DS_CIPHERTEXT,
};
use crate::math::helpers::assert_in_range;
use crate::math::polynomial::{negacyclic_kernel, Polynomial};
use super::{commitments::{commit, key_bundle}, prf};

// The C4 and ciphertext commitments use centered, descending coefficients. The PRF and native
// calculation must use the same values, but in ascending canonical residue order.
pub fn centered_for<let D: u32, let M: u32>(
    rows: [[u64; D]; M],
    qis: [Field; M],
) -> [Polynomial<D>; M] {
    let mut result = [Polynomial::new([0; D]); M];
    for l in 0..M {
        let q = qis[l] as u64;
        for j in 0..D {
            let r = rows[l][j];
            assert(r < q);
            result[l].coefficients[D - 1 - j] = r as Field - (r > q / 2) as Field * q as Field;
        }
    }
    result
}

struct Openings<let N: u32, let L: u32, let S: u32> {
    secret: [Polynomial<N>; L],
    c1: [Polynomial<N>; L],
    c0_hash: Field,
    c1_hash: Field,
    mask: [[u64; N]; L],
    weights: [[Field; S]; L],
    slot: u32,
}

pub fn designated<let R: u32, let S: u32>(owner: u32, roster: [u32; R]) -> ([u32; S], u32) {
    assert(S > 0);
    assert(S <= R);
    let mut ids = [0; S];
    let mut slot = S;
    for i in 0..S {
        ids[i] = roster[i] + 1;
        if roster[i] == owner {
            slot = i;
        }
    }
    assert(slot < S, "Owner outside designated set");
    (ids, slot)
}

fn c0_commitment<let N: u32, let L: u32, let BIT: u32>(
    rows: [[u64; N]; L],
    qis: [Field; L],
) -> Field {
    compute_multiple_polynomial_commitment_checked::<N, L, BIT>(
        centered_for(rows, qis),
        DS_CIPHERTEXT,
    )
}

fn open<let N: u32, let L: u32, let H: u32, let T: u32, let N_PARTIES: u32, let AGGREGATE_BIT: u32, let KEY_BITS: u32, let SHARE_BIT: u32>(
    setup: [Field; 2],
    owner: u32,
    roster: [u32; H],
    expected_sk: Field,
    expected_bundle: Field,
    expected_ct: Field,
    outgoing: [[u8; 32]; N_PARTIES],
    incoming: [[u8; 32]; H],
    sk: [[u64; N]; L],
    ct: [[[u64; N]; L]; 2],
    qis: [Field; L],
    profile: [Field; 2],
    center_c1_first: bool,
) -> Openings<N, L, T + 1> {
    let secret = centered_for(sk, qis);
    assert(
        compute_aggregated_shares_commitment_checked::<N, L, AGGREGATE_BIT>(secret) == expected_sk,
        "Wrong synchronized SK opening",
    );
    assert(
        key_bundle::<N_PARTIES, H, KEY_BITS>(
            profile,
            setup,
            owner,
            roster,
            expected_sk,
            outgoing,
            incoming,
        )
            == expected_bundle,
        "Wrong synchronized key bundle opening",
    );
    let (ids, slot) = designated::<H, T + 1>(owner, roster);
    let mut plus = [[0; 32]; T];
    let mut minus = [[0; 32]; T];
    for i in 0..T {
        let row = if i < slot { i } else { i + 1 };
        plus[i] = outgoing[roster[row]];
        minus[i] = incoming[row];
    }
    // bb's VK commits to gate order. Secure C6 historically centered c1 before opening c0;
    // direct C6 opened c0 first. Both still hash the same ordered pair below.
    let (c0_hash, c1) = if center_c1_first {
        let c1 = centered_for(ct[1], qis);
        (c0_commitment::<N, L, AGGREGATE_BIT>(ct[0], qis), c1)
    } else {
        let c0 = c0_commitment::<N, L, AGGREGATE_BIT>(ct[0], qis);
        (c0, centered_for(ct[1], qis))
    };
    let c1_hash =
        compute_multiple_polynomial_commitment_checked::<N, L, AGGREGATE_BIT>(c1, DS_CIPHERTEXT);
    assert(
        compute_commitment([c0_hash, c1_hash].as_vector(), DS_CIPHERTEXT) == expected_ct,
        "Wrong synchronized ciphertext opening",
    );
    let mask = prf::mask(ids, ct, qis.map(|q| q as u64), plus, minus);
    let weights = lagrange_coefficients::<T + 1, L, SHARE_BIT, SHARE_BIT + 6>(
        qis,
        ids.map(|id| id as Field),
        N_PARTIES,
    );
    Openings { secret, c1, c0_hash, c1_hash, mask, weights, slot }
}

pub fn direct_share<let N: u32, let L: u32, let H: u32, let T: u32, let N_PARTIES: u32, let AGGREGATE_BIT: u32, let KEY_BITS: u32, let SHARE_BIT: u32>(
    setup: [Field; 2],
    owner: u32,
    roster: [u32; H],
    expected_sk: Field,
    expected_bundle: Field,
    expected_ct: Field,
    outgoing: [[u8; 32]; N_PARTIES],
    incoming: [[u8; 32]; H],
    sk: [[u64; N]; L],
    ct: [[[u64; N]; L]; 2],
    shifted_noise: [u64; N],
    d: [[u64; N]; L],
    qis: [Field; L],
    profile: [Field; 2],
    bound: u64,
) -> (Field, Field) {
    let opened = open::<N, L, H, T, N_PARTIES, AGGREGATE_BIT, KEY_BITS, SHARE_BIT>(
        setup,
        owner,
        roster,
        expected_sk,
        expected_bundle,
        expected_ct,
        outgoing,
        incoming,
        sk,
        ct,
        qis,
        profile,
        false,
    );
    let mut share = [Polynomial::new([0; N]); L];
    for j in 0..N {
        assert(shifted_noise[j] <= 2 * bound, "Local noise outside signed bound");
    }
    for l in 0..L {
        let q = qis[l] as u128;
        // This is the degree-64 baseline: each product sum is < N*q^2. Guard the width
        // before converting into u128; do not reuse this bound for a secure preset.
        assert(N <= 64);
        assert(q < (1 as u128 << 28));
        let weight = opened.weights[l][opened.slot] as u128;
        for j in 0..N {
            let mut product: Field = 0;
            for k in 0..N {
                // Wrapped terms have a minus sign in Z_q[X]/(X^N + 1).
                let v = if k <= j {
                    sk[l][j - k] as Field
                } else {
                    qis[l] - sk[l][N + j - k] as Field
                };
                product += ct[1][l][k] as Field * v;
            }
            // All limbs use the very same signed integer e[j] = shifted_noise[j] - B.
            let noise = shifted_noise[j] as u128 + q - (bound as u128 % q);
            let residue = (product as u128 * weight + noise + opened.mask[l][j] as u128) % q;
            assert(d[l][j] as u128 == residue, "Wrong synchronized partial decryption");
            share[l].coefficients[j] = d[l][j] as Field;
        }
    }
    (compute_threshold_decryption_share_commitment::<N, L, SHARE_BIT>(share), opened.c0_hash)
}

pub fn secure_share<let N: u32, let L: u32, let H: u32, let T: u32, let N_PARTIES: u32, let AGGREGATE_BIT: u32, let KEY_BITS: u32, let SHARE_BIT: u32, let NOISE_BIT: u32, let SHIFTED_NOISE_BIT: u32>(
    setup: [Field; 2],
    owner: u32,
    roster: [u32; H],
    expected_sk: Field,
    expected_bundle: Field,
    expected_ct: Field,
    outgoing: [[u8; 32]; N_PARTIES],
    incoming: [[u8; 32]; H],
    sk: [[u64; N]; L],
    ct: [[[u64; N]; L]; 2],
    shifted_noise: [Field; N],
    d: [[u64; N]; L],
    product: [[Field; N]; L],
    qis: [Field; L],
    profile: [Field; 2],
    bound: Field,
) -> (Field, Field) {
    let opened = open::<N, L, H, T, N_PARTIES, AGGREGATE_BIT, KEY_BITS, SHARE_BIT>(
        setup,
        owner,
        roster,
        expected_sk,
        expected_bundle,
        expected_ct,
        outgoing,
        incoming,
        sk,
        ct,
        qis,
        profile,
        true,
    );
    // Commit the complete centered negacyclic product before its evaluation point.
    let mut transcript = [0; 5 + L * N];
    transcript[0] = 0x73796e632d63362d70726f642d7631; // "sync-c6-prod-v1"
    transcript[1] = profile[0];
    transcript[2] = profile[1];
    transcript[3] = expected_sk;
    transcript[4] = opened.c1_hash;
    for l in 0..L {
        for j in 0..N {
            transcript[5 + l * N + j] = product[l][j];
        }
    }
    let gamma = commit(transcript.as_vector());
    // The bound B has NOISE_BIT bits and the shifted noise lies in [0, 2B], so SHIFTED_NOISE_BIT
    // is one more. The quotient window below needs B/q < 2^86 with q >= 2^59, so B < 2^145.
    std::static_assert(SHIFTED_NOISE_BIT == NOISE_BIT + 1, "shifted noise width");
    std::static_assert(
        NOISE_BIT <= 145,
        "noise bound too wide for the quotient window",
    );
    bound.assert_max_bit_size::<NOISE_BIT>();
    for j in 0..N {
        check_secure_noise::<SHIFTED_NOISE_BIT>(shifted_noise[j], bound);
    }
    let mut share = [Polynomial::new([0; N]); L];
    for l in 0..L {
        let q = qis[l];
        q.assert_max_bit_size::<60>();
        assert(
            Polynomial::new(product[l]).eval(gamma)
                == opened.c1[l].dot(negacyclic_kernel(opened.secret[l], gamma)),
            "Wrong negacyclic product",
        );
        for j in 0..N {
            assert(d[l][j] < q as u64);
            let delta = opened.weights[l][opened.slot] * product[l][N - 1 - j] + shifted_noise[j]
                - bound
                + opened.mask[l][j] as Field
                - d[l][j] as Field;
            // |lambda*product| < N*q^3, quotient < 2^134, and B/q < 2^86.
            ((delta / q) + 0x10000000000000000000000000000000000).assert_max_bit_size::<137>();
            share[l].coefficients[j] = d[l][j] as Field;
        }
    }
    (compute_threshold_decryption_share_commitment::<N, L, SHARE_BIT>(share), opened.c0_hash)
}

fn check_secure_noise<let BIT: u32>(shifted: Field, bound: Field) {
    assert_in_range::<BIT>(shifted, 2 * bound + 1);
}

#[test]
fn lowest_designated_coordinates_ignore_later_h_rows() {
    let (ids, slot) = designated::<4, 3>(4, [0, 2, 4, 6]);
    assert(ids == [1, 3, 5]);
    assert(slot == 2);
}

#[test(should_fail_with = "Owner outside designated set")]
fn non_designated_h_member_cannot_decrypt() {
    let _ = designated::<4, 3>(6, [0, 2, 4, 6]);
}
