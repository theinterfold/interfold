// SPDX-License-Identifier: LGPL-3.0-only
use lib::configs::synchronized::sync_secure_8192::{
    AGGREGATE_BIT, C6_NOISE_BOUND, H, KEY_BITS, L, N, N_PARTIES, PROFILE_ID, QIS, SHARE_BIT, T,
};
use lib::core::synchronized::{
    commitments::{commit, key_bundle},
    prf,
    threshold_decryption::{centered_for, designated},
};
use lib::core::threshold::decrypted_shares_aggregation::lagrange_coefficients;
use lib::math::commitments::{
    compute_aggregated_shares_commitment_checked, compute_commitment,
    compute_multiple_polynomial_commitment_checked, compute_threshold_decryption_share_commitment,
    DS_CIPHERTEXT,
};
use lib::math::helpers::assert_in_range;
use lib::math::polynomial::{negacyclic_kernel, Polynomial};

// Product is the exact centered c1*SK in Z[X]/(X^N+1), as descending field coefficients.
// Commit it BEFORE deriving the evaluation point. SK and c1 are already uniquely opened.
// The polynomial identity authenticates only this product; the complete PRF and noise
// relation below is still checked coefficient by coefficient.
fn main(
    setup: pub [Field; 2],
    owner: pub u32,
    roster: pub [u32; H],
    domain: pub [u128; 2],
    expected_sk: pub Field,
    expected_bundle: pub Field,
    expected_ct: pub Field,
    outgoing: [[u8; 32]; N_PARTIES],
    incoming: [[u8; 32]; H],
    sk: [[u64; N]; L],
    ct: [[[u64; N]; L]; 2],
    shifted_noise: [Field; N],
    d: [[u64; N]; L],
    product: [[Field; N]; L],
) -> pub (Field, Field) {
    let _ = domain;
    let secret = centered_for(sk, QIS);
    assert(
        compute_aggregated_shares_commitment_checked::<N, L, AGGREGATE_BIT>(secret) == expected_sk,
    );
    assert(
        key_bundle::<N_PARTIES, H, KEY_BITS>(
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
    let c1 = centered_for(ct[1], QIS);
    let c0_hash = compute_multiple_polynomial_commitment_checked::<N, L, AGGREGATE_BIT>(
        centered_for(ct[0], QIS),
        DS_CIPHERTEXT,
    );
    let c1_hash =
        compute_multiple_polynomial_commitment_checked::<N, L, AGGREGATE_BIT>(c1, DS_CIPHERTEXT);
    assert(compute_commitment([c0_hash, c1_hash].as_vector(), DS_CIPHERTEXT) == expected_ct);
    let mask = prf::mask(ids, ct, QIS.map(|q| q as u64), plus, minus);
    let weights = lagrange_coefficients::<T + 1, L, SHARE_BIT, SHARE_BIT + 6>(
        QIS,
        ids.map(|id| id as Field),
        N_PARTIES,
    );
    let mut transcript = [0; 5 + L * N];
    // "sync-c6-prod-v1"; no key material is exposed by this private challenge.
    transcript[0] = 0x73796e632d63362d70726f642d7631;
    transcript[1] = PROFILE_ID[0];
    transcript[2] = PROFILE_ID[1];
    transcript[3] = expected_sk;
    transcript[4] = c1_hash;
    for l in 0..L {
        for j in 0..N {
            transcript[5 + l * N + j] = product[l][j];
        }
    }
    let gamma = commit(transcript.as_vector());
    // B < 2^144; a shifted draw represents precisely one signed integer in [-B,B].
    C6_NOISE_BOUND.assert_max_bit_size::<144>();
    for j in 0..N {
        assert_in_range::<145>(shifted_noise[j], 2 * C6_NOISE_BOUND + 1);
    }
    let mut share = [Polynomial::new([0; N]); L];
    for l in 0..L {
        let q = QIS[l];
        q.assert_max_bit_size::<60>();
        assert(
            Polynomial::new(product[l]).eval(gamma)
                == c1[l].dot(negacyclic_kernel(secret[l], gamma)),
            "Wrong negacyclic product",
        );
        for j in 0..N {
            assert(d[l][j] < q as u64);
            let delta = weights[l][slot] * product[l][N - 1 - j] + shifted_noise[j] - C6_NOISE_BOUND
                + mask[l][j] as Field
                - d[l][j] as Field;
            // |lambda*product| < N*q^3, so its quotient is < 2^134. B/q < 2^86.
            // The bounded signed quotient times q is far below the scalar modulus.
            ((delta / q) + 0x10000000000000000000000000000000000).assert_max_bit_size::<137>();
            share[l].coefficients[j] = d[l][j] as Field;
        }
    }
    (compute_threshold_decryption_share_commitment::<N, L, SHARE_BIT>(share), c0_hash)
}
