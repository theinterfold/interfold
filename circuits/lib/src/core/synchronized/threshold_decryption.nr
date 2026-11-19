// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Direct Minimum C6. Public setup/domain/anchors require the final verifier's canonical authority.

use crate::configs::synchronized::sync_insecure_64::{
    AGGREGATE_BIT, C6_NOISE_BOUND, H, L_THRESHOLD as L, N, N_PARTIES, PRF_KEY_BITS, PROFILE_ID,
    QIS_THRESHOLD, SHARE_BIT, T,
};
use crate::core::threshold::decrypted_shares_aggregation::lagrange_coefficients;
use crate::math::commitments::{
    compute_aggregated_shares_commitment_checked, compute_commitment,
    compute_multiple_polynomial_commitment_checked, compute_threshold_decryption_share_commitment,
    DS_CIPHERTEXT,
};
use crate::math::polynomial::Polynomial;
use super::{commitments::key_bundle, prf};

// The C4 and ciphertext commitments use centered, descending coefficients. The PRF and native
// calculation must use the same values, but in ascending canonical residue order.
fn centered(rows: [[u64; N]; L]) -> [Polynomial<N>; L] {
    let mut result = [Polynomial::new([0; N]); L];
    for l in 0..L {
        let q = QIS_THRESHOLD[l] as u64;
        for j in 0..N {
            let r = rows[l][j];
            assert(r < q);
            result[l].coefficients[N - 1 - j] = r as Field - (r > q / 2) as Field * q as Field;
        }
    }
    result
}

fn designated<let R: u32, let S: u32>(owner: u32, roster: [u32; R]) -> ([u32; S], u32) {
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

pub fn execute(
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
) -> (Field, Field) {
    assert(
        compute_aggregated_shares_commitment_checked::<N, L, AGGREGATE_BIT>(centered(sk))
            == expected_sk,
    );
    assert(
        key_bundle::<N_PARTIES, H, PRF_KEY_BITS>(
            PROFILE_ID,
            setup,
            owner,
            roster,
            expected_sk,
            outgoing,
            incoming,
        )
            == expected_bundle,
    );
    let (ids, slot) = designated::<H, T + 1>(owner, roster);
    let mut plus = [[0; 32]; T];
    let mut minus = [[0; 32]; T];
    for i in 0..T {
        let row = if i < slot { i } else { i + 1 };
        plus[i] = outgoing[roster[row]];
        minus[i] = incoming[row];
    }
    let c0 = compute_multiple_polynomial_commitment_checked::<N, L, AGGREGATE_BIT>(
        centered(ct[0]),
        DS_CIPHERTEXT,
    );
    let c1 = compute_multiple_polynomial_commitment_checked::<N, L, AGGREGATE_BIT>(
        centered(ct[1]),
        DS_CIPHERTEXT,
    );
    assert(compute_commitment([c0, c1].as_vector(), DS_CIPHERTEXT) == expected_ct);
    let mask = prf::mask(ids, ct, QIS_THRESHOLD.map(|q| q as u64), plus, minus);
    let weights = lagrange_coefficients::<T + 1, L, SHARE_BIT, SHARE_BIT + 6>(
        QIS_THRESHOLD,
        ids.map(|id| id as Field),
        N_PARTIES,
    );
    let mut share = [Polynomial::new([0; N]); L];
    for j in 0..N {
        assert(shifted_noise[j] <= 2 * C6_NOISE_BOUND, "Local noise outside signed bound");
    }
    for l in 0..L {
        let q = QIS_THRESHOLD[l] as u128;
        // This is the degree-64 baseline: each product sum is < N*q^2. Guard the width
        // before converting into u128; do not reuse this bound for a secure preset.
        assert(N <= 64);
        assert(q < (1 as u128 << 28));
        let weight = weights[l][slot] as u128;
        for j in 0..N {
            let mut product: Field = 0;
            for k in 0..N {
                // Wrapped terms have a minus sign in Z_q[X]/(X^N + 1).
                let v = if k <= j {
                    sk[l][j - k] as Field
                } else {
                    QIS_THRESHOLD[l] - sk[l][N + j - k] as Field
                };
                product += ct[1][l][k] as Field * v;
            }
            // All limbs use the very same signed integer e[j] = shifted_noise[j] - B.
            let noise = shifted_noise[j] as u128 + q - (C6_NOISE_BOUND as u128 % q);
            let residue = (product as u128 * weight + noise + mask[l][j] as u128) % q;
            assert(d[l][j] as u128 == residue, "Wrong synchronized partial decryption");
            share[l].coefficients[j] = d[l][j] as Field;
        }
    }
    (compute_threshold_decryption_share_commitment::<N, L, SHARE_BIT>(share), c0)
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
