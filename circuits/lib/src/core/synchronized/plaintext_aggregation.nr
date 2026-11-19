// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::configs::protocol::MAX_MSG_NON_ZERO_COEFFS as K;
use crate::configs::synchronized::sync_insecure_64::{
    C6_PUBLIC_FIELDS, C7_BIT_K, C7_BIT_Q_TOTAL, C7_BIT_T, C7_PLAINTEXT_MODULUS, H, L_THRESHOLD as L,
    N, N_PARTIES, QIS_THRESHOLD, SHARE_BIT, T,
};
use crate::core::threshold::decrypted_shares_aggregation::{garner_reconstruct, rounded_decode};
use crate::math::commitments::compute_threshold_decryption_share_commitment;
use crate::math::modulo::U128::reduce_mod_bounded;
use crate::math::polynomial::Polynomial;
use super::threshold_decryption::component_commitment;

/// `rows` are the *public* statements of the C6 leaves in designated order. The recursive
/// consumer must compare these exact rows (including each SK/bundle anchor) to verified proofs.
pub fn execute(
    rows: [[Field; C6_PUBLIC_FIELDS]; T + 1],
    message: [u64; K],
    c0: [[u64; N]; L],
    shares: [[[u64; N]; L]; T + 1],
) {
    std::static_assert(T + 1 <= H, "designated set exceeds H");
    std::static_assert(K <= N, "message exceeds ring degree");
    std::static_assert(
        C6_PUBLIC_FIELDS == H + 10,
        "unexpected synchronized C6 layout",
    );
    // Layout: setup[2], owner, roster[H], domain[2], SK, bundle, ct, d, c0.
    let first = rows[0];
    for i in 0..H {
        let id = first[3 + i];
        id.assert_max_bit_size::<32>();
        assert((id as u32) < N_PARTIES);
        if i > 0 {
            assert((first[2 + i] as u32) < (id as u32));
        }
    }
    for i in 0..2 {
        first[i].assert_max_bit_size::<128>();
        first[3 + H + i].assert_max_bit_size::<128>();
    }
    let c0_commitment = component_commitment(c0);
    for s in 0..T + 1 {
        let row = rows[s];
        assert(row[2] == first[3 + s], "Unexpected designated owner");
        assert((row[0] == first[0]) & (row[1] == first[1]), "Mixed C6 setup");
        for i in 0..H {
            assert(row[3 + i] == first[3 + i], "Mixed C6 roster");
        }
        for i in 0..2 {
            assert(row[3 + H + i] == first[3 + H + i], "Mixed C6 domain");
        }
        assert(row[7 + H] == first[7 + H], "Mixed C6 ciphertext");
        assert(row[9 + H] == c0_commitment, "Wrong C6 c0 opening");
        let mut polynomials = [Polynomial::new([0; N]); L];
        for l in 0..L {
            for j in 0..N {
                let r = shares[s][l][j];
                assert(r < QIS_THRESHOLD[l] as u64);
                polynomials[l].coefficients[j] = r as Field;
            }
        }
        assert(
            compute_threshold_decryption_share_commitment::<N, L, SHARE_BIT>(polynomials)
                == row[8 + H],
            "Wrong C6 share opening",
        );
    }
    let mut q_total: Field = 1;
    for q in QIS_THRESHOLD {
        q_total *= q;
    }
    for j in 0..K {
        let mut residues = [0; L];
        for l in 0..L {
            let mut sum = c0[l][j] as Field;
            for s in 0..T + 1 {
                sum += shares[s][l][j] as Field;
            }
            residues[l] = reduce_mod_bounded::<SHARE_BIT, C7_BIT_K>(sum, QIS_THRESHOLD[l]);
        }
        let u = garner_reconstruct::<L, SHARE_BIT, C7_BIT_K>(residues, QIS_THRESHOLD);
        let decoded = rounded_decode::<C7_BIT_T, C7_BIT_Q_TOTAL>(
            u,
            C7_PLAINTEXT_MODULUS,
            q_total,
            (q_total - 1) / 2,
        );
        assert(decoded == message[j] as Field, "Decoded plaintext mismatch");
    }
}
