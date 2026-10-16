// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! User-data encryption (P3): both ciphertext legs of one BFV encryption in one circuit.

use crate::core::threshold::user_data_encryption_ct0::UserDataEncryptionCt0;
use crate::core::threshold::user_data_encryption_ct1::UserDataEncryptionCt1;
use crate::math::commitments::{compute_commitment, DS_CIPHERTEXT, DS_PK_AGGREGATION};

/// Proves ct0 and then ct1 over one `u`, and returns `(pk_commitment, ct_commitment,
/// k1_commitment)`.
///
/// ct0 constrains `u` to `{-1, 0, 1}` and commits it, and ct1 reuses that commitment in its own
/// transcript instead of checking and committing `u` again. That is only sound for one `u`, so both
/// legs must read the same one; the binary builds both from one witness, which makes the equality
/// below free, and anything else fails it. `pk_commitment` and `ct_commitment` combine the legs'
/// commitments as C5 and the ballot circuits expect.
pub fn execute<let N: u32, let L: u32, let BIT_PK: u32, let BIT_CT: u32, let BIT_U: u32, let BIT_E0: u32, let BIT_K: u32, let BIT_R0: u32, let BIT_E1: u32, let BIT_R1: u32>(
    ct0: UserDataEncryptionCt0<N, L, BIT_PK, BIT_CT, BIT_U, BIT_E0, BIT_K, BIT_R0>,
    ct1: UserDataEncryptionCt1<N, L, BIT_PK, BIT_CT, BIT_U, BIT_E1, BIT_R1>,
) -> (Field, Field, Field) {
    assert(ct0.u().coefficients == ct1.u().coefficients, "both legs must read the same u");

    let (pk0_commitment, ct0_commitment, k1_commitment, u_commitment) = ct0.execute();
    let (pk1_commitment, ct1_commitment) = ct1.execute_with_u_commitment(u_commitment);

    let ct_commitment =
        compute_commitment([ct0_commitment, ct1_commitment].as_vector(), DS_CIPHERTEXT);
    let pk_commitment = compute_commitment(
        [pk0_commitment, pk1_commitment].as_vector(),
        DS_PK_AGGREGATION,
    );

    (pk_commitment, ct_commitment, k1_commitment)
}

// Tests use the hand-worked `N = 4`, `q = 97`, `k0 = 5` legs from the ct0 and ct1 tests, which share
// `u = [0, 1, 0, -1]`; honest ciphertexts are ct0 `[47, -30, -5, 48]` and ct1 `[47, -30, -10, 48]`.

use crate::core::threshold::user_data_encryption_ct0::Configs as Ct0Configs;
use crate::core::threshold::user_data_encryption_ct1::Configs as Ct1Configs;
use crate::math::polynomial::Polynomial;

global U: [Field; 4] = [0, 1, 0, -1];
global CT0: [Field; 4] = [47, -30, -5, 48];
global CT1: [Field; 4] = [47, -30, -10, 48];

/// ct0 reading `u0` with ciphertext `ct0`, and ct1 reading `u1` with ciphertext `ct1`.
fn legs(
    u0: [Field; 4],
    ct0: [Field; 4],
    u1: [Field; 4],
    ct1: [Field; 4],
) -> (UserDataEncryptionCt0<4, 1, 6, 6, 1, 1, 1, 3>, UserDataEncryptionCt1<4, 1, 6, 6, 1, 1, 3>) {
    let leg0 = UserDataEncryptionCt0::new(
        Ct0Configs::new([97], [5], 1, 1, [3], 1, 1),
        [Polynomial::new([30, 40, -20, 10])],
        [Polynomial::new(ct0)],
        Polynomial::new(u0),
        Polynomial::new([0, 0, 0, 1]),
        Polynomial::new([0, 0, 1, 0]),
        [Polynomial::new([1, 0, 0, 1])],
    );
    let leg1 = UserDataEncryptionCt1::new(
        Ct1Configs::new([97], 1, 1, [3]),
        [Polynomial::new([30, 40, -20, 10])],
        [Polynomial::new(ct1)],
        Polynomial::new(u1),
        Polynomial::new([0, 0, 0, 1]),
        [Polynomial::new([1, 0, 0, 1])],
    );
    (leg0, leg1)
}

#[test]
fn both_legs_over_one_u_are_accepted() {
    let (ct0, ct1) = legs(U, CT0, U, CT1);
    let (pk_commitment, ct_commitment, k1_commitment) = execute(ct0, ct1);

    // The same values the separate legs and the former fold produced.
    let (pk0_commitment, ct0_commitment, expected_k1, _) = ct0.execute();
    let (pk1_commitment, ct1_commitment, _) = ct1.execute();
    assert(k1_commitment == expected_k1);
    assert(
        ct_commitment
            == compute_commitment([ct0_commitment, ct1_commitment].as_vector(), DS_CIPHERTEXT),
    );
    assert(
        pk_commitment
            == compute_commitment(
                [pk0_commitment, pk1_commitment].as_vector(),
                DS_PK_AGGREGATION,
            ),
    );
}

/// ct0 bounds the shared `u` in the merged path: a non-ternary `u` fails before any identity.
#[test(should_fail_with = "coefficient is not ternary")]
fn a_non_ternary_shared_u_is_rejected() {
    let u = [0, 2, 0, -1];
    let (ct0, ct1) = legs(u, CT0, u, CT1);
    let _ = execute(ct0, ct1);
}

/// ct1 reuses ct0's commitment, so the legs may not read different `u`s.
#[test(should_fail_with = "both legs must read the same u")]
fn legs_with_different_u_are_rejected() {
    let (ct0, ct1) = legs(U, CT0, [0, 1, 0, 0], CT1);
    let _ = execute(ct0, ct1);
}

#[test(should_fail_with = "ct0 encryption check failed")]
fn a_wrong_ct0_is_rejected() {
    let (ct0, ct1) = legs(U, [46, -30, -5, 48], U, CT1);
    let _ = execute(ct0, ct1);
}

/// The merged path still checks ct1's identity although it skips ct1's own `u` checks.
#[test(should_fail_with = "ct1 encryption check failed")]
fn a_wrong_ct1_is_rejected() {
    let (ct0, ct1) = legs(U, CT0, U, [46, -30, -10, 48]);
    let _ = execute(ct0, ct1);
}
