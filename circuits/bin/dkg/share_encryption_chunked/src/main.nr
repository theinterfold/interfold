// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use lib::configs::default::dkg::{
    L, N, SHARE_COMPUTATION_BIT_SHARE, SHARE_COMPUTATION_CHUNK_SIZE, SHARE_COMPUTATION_N_CHUNKS,
    SHARE_ENCRYPTION_BIT_CT, SHARE_ENCRYPTION_BIT_E0, SHARE_ENCRYPTION_BIT_E1,
    SHARE_ENCRYPTION_BIT_MSG, SHARE_ENCRYPTION_BIT_PK, SHARE_ENCRYPTION_BIT_Q0,
    SHARE_ENCRYPTION_BIT_Q0_DIFF, SHARE_ENCRYPTION_BIT_Q1, SHARE_ENCRYPTION_BIT_U,
    SHARE_ENCRYPTION_BIT_Z, SHARE_ENCRYPTION_CONFIGS, SHARE_ENCRYPTION_CT0_BIT_R,
    SHARE_ENCRYPTION_CT1_BIT_R,
};
use lib::core::dkg::share_encryption::ShareEncryption;
use lib::math::commitments::compute_sc_party_share_root_from_polynomial;
use lib::math::polynomial::Polynomial;

/// C3 for the l-BFV path: identical to `share_encryption` except that the share is committed as
/// a chunk root keyed by `(party_idx, mod_idx)`, the form the chunked C2 outputs. Both indices are
/// public so the fold can place the proof in its slot.
fn main(
    expected_pk_commitment: pub Field,
    expected_message_commitment: pub Field,
    party_idx: pub u32,
    mod_idx: pub u32,
    pk0is: [Polynomial<N>; L],
    pk1is: [Polynomial<N>; L],
    ct0is: [Polynomial<N>; L],
    ct1is: [Polynomial<N>; L],
    u: Polynomial<N>,
    e0: Polynomial<N>,
    e1: Polynomial<N>,
    message: Polynomial<N>,
    ct0_r: [Polynomial<N>; L],
    ct1_r: [Polynomial<N>; L],
    z: [Polynomial<N>; 1],
) -> pub Field {
    // C3 re-opens the chunk roots C2 committed, so both must pack at the same digit width.
    assert(SHARE_ENCRYPTION_BIT_MSG == SHARE_COMPUTATION_BIT_SHARE);
    let share_encryption: ShareEncryption<N, L, SHARE_ENCRYPTION_BIT_PK, SHARE_ENCRYPTION_BIT_CT, SHARE_ENCRYPTION_BIT_U, SHARE_ENCRYPTION_BIT_E0, SHARE_ENCRYPTION_BIT_E1, SHARE_ENCRYPTION_BIT_MSG, SHARE_ENCRYPTION_CT0_BIT_R, SHARE_ENCRYPTION_CT1_BIT_R, SHARE_ENCRYPTION_BIT_Z, SHARE_ENCRYPTION_BIT_Q0, SHARE_ENCRYPTION_BIT_Q0_DIFF, SHARE_ENCRYPTION_BIT_Q1> = ShareEncryption::new(
        SHARE_ENCRYPTION_CONFIGS,
        expected_pk_commitment,
        expected_message_commitment,
        pk0is,
        pk1is,
        ct0is,
        ct1is,
        u,
        e0,
        e1,
        message,
        ct0_r,
        ct1_r,
        z,
    );
    share_encryption.execute_with(|message| {
        compute_sc_party_share_root_from_polynomial::<N, SHARE_COMPUTATION_N_CHUNKS, SHARE_COMPUTATION_CHUNK_SIZE, SHARE_ENCRYPTION_BIT_MSG>(
            party_idx,
            mod_idx,
            message,
        )
    })
}
