// SPDX-License-Identifier: LGPL-3.0-only

use crate::core::threshold::pk_generation::verify_key_evaluations;
use crate::math::commitments::{
    compute_share_computation_sk_commitment, compute_threshold_pk_commitment,
};
use crate::math::helpers::flatten;
use crate::math::polynomial::Polynomial;
use super::commitments::{assert_context, commit};

/// Sync C1 proves the same bounded key contribution, without the SS smudging-sharing branch.
pub fn execute<let N: u32, let L: u32, let N_PARTIES: u32, let BIT_EEK: u32, let BIT_SK: u32, let BIT_R: u32, let BIT_PK: u32>(
    profile: [Field; 2],
    setup_binding: [Field; 2],
    dealer: u32,
    moduli: [Field; L],
    error_bound: Field,
    crp: [Polynomial<N>; L],
    eek: Polynomial<N>,
    sk: Polynomial<N>,
    r: [Polynomial<N>; L],
    pk0: [Polynomial<N>; L],
) -> (Field, Field) {
    assert_context(profile, setup_binding);
    assert(dealer < N_PARTIES, "Dealer outside committee");
    sk.assert_ternary();
    eek.range_check_2bounds::<BIT_EEK>(error_bound, error_bound);
    for limb in 0..L {
        let bound = (moduli[limb] - 1) / 2;
        pk0[limb].range_check_2bounds::<BIT_PK>(bound, bound);
        r[limb].range_check_signed_power_of_two::<BIT_R>();
    }
    let sk_commitment = compute_share_computation_sk_commitment::<N, BIT_SK>(sk);
    let pk_commitment = compute_threshold_pk_commitment::<N, L, BIT_PK>(pk0);
    let mut payload = [
        4,
        profile[0],
        profile[1],
        setup_binding[0],
        setup_binding[1],
        N_PARTIES as Field,
        dealer as Field,
    ]
        .as_vector();
    payload = flatten::<_, _, BIT_PK>(payload, crp);
    payload = flatten::<_, _, BIT_EEK>(payload, [eek]);
    payload = payload.push_back(sk_commitment);
    payload = payload.push_back(pk_commitment);
    payload = flatten::<_, _, BIT_R>(payload, r);
    verify_key_evaluations(moduli, crp, eek, sk, r, pk0, commit(payload));
    (sk_commitment, pk_commitment)
}
