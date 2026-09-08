// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use lib::configs::default::MAX_MSG_NON_ZERO_COEFFS;
use lib::configs::default::threshold::{
    L, N, THRESHOLD_SHARE_DECRYPTION_BIT_CT, THRESHOLD_SHARE_DECRYPTION_BIT_D,
    THRESHOLD_SHARE_DECRYPTION_BIT_D_NATIVE, THRESHOLD_SHARE_DECRYPTION_BIT_E_SM,
    THRESHOLD_SHARE_DECRYPTION_BIT_R1, THRESHOLD_SHARE_DECRYPTION_BIT_R2,
    THRESHOLD_SHARE_DECRYPTION_BIT_SK, THRESHOLD_SHARE_DECRYPTION_CONFIGS,
};
use lib::core::threshold::share_decryption::ShareDecryption;
use lib::math::polynomial::Polynomial;

fn main(
    expected_sk_commitment: pub Field,
    expected_e_sm_commitment: pub Field,
    ct_commitment: pub Field,
    domain_hi: pub Field,
    domain_lo: pub Field,
    ct0: [Polynomial<N>; L],
    ct1: [Polynomial<N>; L],
    sk: [Polynomial<N>; L],
    e_sm: [Polynomial<N>; L],
    r1: [Polynomial<(2 * N) - 1>; L],
    r2: [Polynomial<N - 1>; L],
    d: [Polynomial<N>; L],
    d_native_trunc: [Polynomial<MAX_MSG_NON_ZERO_COEFFS>; L],
) -> pub Field {
    // Preserve both public domain limbs through the leaf and recursive proofs.
    let share_decryption: ShareDecryption<N, MAX_MSG_NON_ZERO_COEFFS, L, THRESHOLD_SHARE_DECRYPTION_BIT_CT, THRESHOLD_SHARE_DECRYPTION_BIT_SK, THRESHOLD_SHARE_DECRYPTION_BIT_E_SM, THRESHOLD_SHARE_DECRYPTION_BIT_R1, THRESHOLD_SHARE_DECRYPTION_BIT_R2, THRESHOLD_SHARE_DECRYPTION_BIT_D, THRESHOLD_SHARE_DECRYPTION_BIT_D_NATIVE> = ShareDecryption::new(
        THRESHOLD_SHARE_DECRYPTION_CONFIGS,
        expected_sk_commitment,
        expected_e_sm_commitment,
        ct_commitment,
        ct0,
        ct1,
        sk,
        e_sm,
        r1,
        r2,
        d,
        d_native_trunc,
    );
    share_decryption.execute(domain_hi, domain_lo)
}
