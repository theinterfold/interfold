// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use lib::configs::default::{MAX_MSG_NON_ZERO_COEFFS, N_PARTIES, T};
use lib::configs::default::threshold::{
    L, N, Q_BIT, THRESHOLD_SHARE_DECRYPTION_BIT_CT, THRESHOLD_SHARE_DECRYPTION_BIT_D,
    THRESHOLD_SHARE_DECRYPTION_BIT_D_NATIVE, THRESHOLD_SHARE_DECRYPTION_BIT_E_FRESH,
    THRESHOLD_SHARE_DECRYPTION_BIT_R, THRESHOLD_SHARE_DECRYPTION_BIT_SK,
    THRESHOLD_SHARE_DECRYPTION_CONFIGS,
};
use lib::core::threshold::share_decryption::ShareDecryption;
use lib::math::polynomial::Polynomial;

fn main(
    expected_sk_commitment: pub Field,
    ct_commitment: pub Field,
    c0_commitment: pub Field,
    domain_hi: pub Field,
    domain_lo: pub Field,
    ct0: [Polynomial<N>; L],
    ct1: [Polynomial<N>; L],
    sk: [Polynomial<N>; L],
    e_fresh: [Polynomial<N>; L],
    e_signed: Polynomial<N>,
    e_quot: [Polynomial<N>; L],
    r: [Polynomial<N>; L],
    d: [Polynomial<N>; L],
    d_native_trunc: [Polynomial<MAX_MSG_NON_ZERO_COEFFS>; L],
    party_idx: pub u32,
    decryptors: pub [Field; T + 1],
    outgoing_key_commitments: pub [Field; N_PARTIES],
    incoming_key_commitments: pub [Field; N_PARTIES],
    outgoing_keys: [Field; N_PARTIES],
    incoming_keys: [Field; N_PARTIES],
) -> pub Field {
    // The domain is intentionally not part of the BFV arithmetic. Making it a
    // public input of this secret-bearing proof cryptographically authorizes
    // this exact E3 context; recursive aggregation must preserve both limbs.
    let _ = (domain_hi, domain_lo);
    let share_decryption: ShareDecryption<N, MAX_MSG_NON_ZERO_COEFFS, L, THRESHOLD_SHARE_DECRYPTION_BIT_CT, THRESHOLD_SHARE_DECRYPTION_BIT_SK, THRESHOLD_SHARE_DECRYPTION_BIT_E_FRESH, THRESHOLD_SHARE_DECRYPTION_BIT_R, THRESHOLD_SHARE_DECRYPTION_BIT_D, THRESHOLD_SHARE_DECRYPTION_BIT_D_NATIVE, N_PARTIES, T + 1, Q_BIT> = ShareDecryption::new(
        THRESHOLD_SHARE_DECRYPTION_CONFIGS,
        expected_sk_commitment,
        ct_commitment,
        c0_commitment,
        ct0,
        ct1,
        sk,
        e_fresh,
        e_signed,
        e_quot,
        r,
        d,
        d_native_trunc,
        party_idx,
        decryptors,
        outgoing_keys,
        incoming_keys,
        outgoing_key_commitments,
        incoming_key_commitments,
    );
    share_decryption.execute()
}
