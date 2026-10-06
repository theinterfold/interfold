// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use lib::configs::default::dkg::PRF_KEY_BITS;
use lib::configs::default::{DECRYPTOR_COUNT, MAX_MSG_NON_ZERO_COEFFS, N_PARTIES};
use lib::configs::default::threshold::{
    L, N, PK_GENERATION_BIT_E_SM, PK_GENERATION_E_SM_BOUND, THRESHOLD_SHARE_DECRYPTION_BIT_CT,
    THRESHOLD_SHARE_DECRYPTION_BIT_D, THRESHOLD_SHARE_DECRYPTION_BIT_D_NATIVE,
    THRESHOLD_SHARE_DECRYPTION_BIT_R1, THRESHOLD_SHARE_DECRYPTION_BIT_R2,
    THRESHOLD_SHARE_DECRYPTION_BIT_SK, THRESHOLD_SHARE_DECRYPTION_CONFIGS,
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
    r1: [Polynomial<(2 * N) - 1>; L],
    r2: [Polynomial<N - 1>; L],
    d: [Polynomial<N>; L],
    d_native_trunc: [Polynomial<MAX_MSG_NON_ZERO_COEFFS>; L],
    party_idx: pub u32,
    decryptors: pub [Field; DECRYPTOR_COUNT],
    outgoing_key_commitments: pub [Field; N_PARTIES],
    incoming_key_commitments: pub [Field; N_PARTIES],
    outgoing_key_bits: [[Field; PRF_KEY_BITS]; N_PARTIES],
    incoming_key_bits: [[Field; PRF_KEY_BITS]; N_PARTIES],
) -> pub Field {
    // The domain is intentionally not part of the BFV arithmetic. Making it a
    // public input of this secret-bearing proof cryptographically authorizes
    // this exact E3 context; recursive aggregation must preserve both limbs.
    let _ = (domain_hi, domain_lo);
    let configs = THRESHOLD_SHARE_DECRYPTION_CONFIGS.with_fresh_bound(PK_GENERATION_E_SM_BOUND);
    let share_decryption: ShareDecryption<N, MAX_MSG_NON_ZERO_COEFFS, L, THRESHOLD_SHARE_DECRYPTION_BIT_CT, THRESHOLD_SHARE_DECRYPTION_BIT_SK, PK_GENERATION_BIT_E_SM, THRESHOLD_SHARE_DECRYPTION_BIT_R1, THRESHOLD_SHARE_DECRYPTION_BIT_R2, THRESHOLD_SHARE_DECRYPTION_BIT_D, THRESHOLD_SHARE_DECRYPTION_BIT_D_NATIVE, PRF_KEY_BITS, N_PARTIES, DECRYPTOR_COUNT> = ShareDecryption::new(
        configs,
        expected_sk_commitment,
        ct_commitment,
        c0_commitment,
        ct0,
        ct1,
        sk,
        e_fresh,
        r1,
        r2,
        d,
        d_native_trunc,
        party_idx,
        decryptors,
        outgoing_key_bits,
        incoming_key_bits,
        outgoing_key_commitments,
        incoming_key_commitments,
    );
    share_decryption.execute()
}
