// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

// C8-CKKS (HYBRID gadget): proves a party's round-1 share of the CKKS
// hybrid relinearization key ceremony is well formed, over Q.P:
//   h0[j][l] = -a[j][l]*u + ((P*g_j) mod q_l)*s + e0[j]  (mod q_l, mod x^N+1)
//   h1[j][l] = a[j][l]*s + e1[j]                         (mod q_l, mod x^N+1)
// for every gadget digit j and limb l of Q.P (L ciphertext moduli then k
// special primes), with s and u bound by commitments (u is reused in
// round 2) and the h0/h1 limbs bound to the published share. The gadget
// constants (P*g_j) mod q_l are PUBLIC circuit constants baked into the
// generated config; ONE config serves every level.

use lib::configs::ckks_relin_round1_hybrid::{
    RELIN_ROUND1_HYBRID_CKKS_BIT_A, RELIN_ROUND1_HYBRID_CKKS_BIT_E, RELIN_ROUND1_HYBRID_CKKS_BIT_H,
    RELIN_ROUND1_HYBRID_CKKS_BIT_R1, RELIN_ROUND1_HYBRID_CKKS_BIT_R2,
    RELIN_ROUND1_HYBRID_CKKS_BIT_SK, RELIN_ROUND1_HYBRID_CKKS_BIT_U,
    RELIN_ROUND1_HYBRID_CKKS_CONFIGS, RELIN_ROUND1_HYBRID_CKKS_D, RELIN_ROUND1_HYBRID_CKKS_LT,
    RELIN_ROUND1_HYBRID_CKKS_N,
};
use lib::core::threshold::relin_round1_hybrid_ckks::RelinRound1Hybrid;
use lib::math::polynomial::Polynomial;

fn main(
    a: [Polynomial<RELIN_ROUND1_HYBRID_CKKS_N>; RELIN_ROUND1_HYBRID_CKKS_D * RELIN_ROUND1_HYBRID_CKKS_LT],
    s: Polynomial<RELIN_ROUND1_HYBRID_CKKS_N>,
    u: Polynomial<RELIN_ROUND1_HYBRID_CKKS_N>,
    e0: [Polynomial<RELIN_ROUND1_HYBRID_CKKS_N>; RELIN_ROUND1_HYBRID_CKKS_D],
    e1: [Polynomial<RELIN_ROUND1_HYBRID_CKKS_N>; RELIN_ROUND1_HYBRID_CKKS_D],
    r1_h0: [Polynomial<(2 * RELIN_ROUND1_HYBRID_CKKS_N) - 1>; RELIN_ROUND1_HYBRID_CKKS_D * RELIN_ROUND1_HYBRID_CKKS_LT],
    r2_h0: [Polynomial<RELIN_ROUND1_HYBRID_CKKS_N - 1>; RELIN_ROUND1_HYBRID_CKKS_D * RELIN_ROUND1_HYBRID_CKKS_LT],
    r1_h1: [Polynomial<(2 * RELIN_ROUND1_HYBRID_CKKS_N) - 1>; RELIN_ROUND1_HYBRID_CKKS_D * RELIN_ROUND1_HYBRID_CKKS_LT],
    r2_h1: [Polynomial<RELIN_ROUND1_HYBRID_CKKS_N - 1>; RELIN_ROUND1_HYBRID_CKKS_D * RELIN_ROUND1_HYBRID_CKKS_LT],
    h0: [Polynomial<RELIN_ROUND1_HYBRID_CKKS_N>; RELIN_ROUND1_HYBRID_CKKS_D * RELIN_ROUND1_HYBRID_CKKS_LT],
    h1: [Polynomial<RELIN_ROUND1_HYBRID_CKKS_N>; RELIN_ROUND1_HYBRID_CKKS_D * RELIN_ROUND1_HYBRID_CKKS_LT],
) -> pub (Field, Field, Field) {
    let relin_round1: RelinRound1Hybrid<RELIN_ROUND1_HYBRID_CKKS_N, RELIN_ROUND1_HYBRID_CKKS_D, RELIN_ROUND1_HYBRID_CKKS_LT, RELIN_ROUND1_HYBRID_CKKS_BIT_A, RELIN_ROUND1_HYBRID_CKKS_BIT_SK, RELIN_ROUND1_HYBRID_CKKS_BIT_U, RELIN_ROUND1_HYBRID_CKKS_BIT_E, RELIN_ROUND1_HYBRID_CKKS_BIT_R1, RELIN_ROUND1_HYBRID_CKKS_BIT_R2, RELIN_ROUND1_HYBRID_CKKS_BIT_H> = RelinRound1Hybrid::new(
        RELIN_ROUND1_HYBRID_CKKS_CONFIGS,
        a,
        s,
        u,
        e0,
        e1,
        r1_h0,
        r2_h0,
        r1_h1,
        r2_h1,
        h0,
        h1,
    );
    relin_round1.execute()
}
