// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

// C8-CKKS: proves a party's round-1 share of the CKKS relinearization key
// ceremony is well formed:
//   h0[i][j] = -a[i][j]*u + (g_i mod q_j)*s + e0[i]  (mod q_j, mod x^N+1)
//   h1[i][j] = a[i][j]*s + e1[i]                     (mod q_j, mod x^N+1)
// for every decomposition index i and CKKS limb j, with s and u bound by
// commitments (u is reused in round 2) and the h0/h1 limbs bound to the
// published share. The garner constants g_i mod q_j are PUBLIC circuit
// constants baked into the generated config (level-0 key material).

use lib::configs::ckks_relin_round1::{
    RELIN_ROUND1_CKKS_BIT_A, RELIN_ROUND1_CKKS_BIT_E, RELIN_ROUND1_CKKS_BIT_H,
    RELIN_ROUND1_CKKS_BIT_R1, RELIN_ROUND1_CKKS_BIT_R2, RELIN_ROUND1_CKKS_BIT_SK,
    RELIN_ROUND1_CKKS_BIT_U, RELIN_ROUND1_CKKS_CONFIGS, RELIN_ROUND1_CKKS_L, RELIN_ROUND1_CKKS_N,
};
use lib::core::threshold::relin_round1_ckks::RelinRound1;
use lib::math::polynomial::Polynomial;

fn main(
    a: [Polynomial<RELIN_ROUND1_CKKS_N>; RELIN_ROUND1_CKKS_L * RELIN_ROUND1_CKKS_L],
    s: Polynomial<RELIN_ROUND1_CKKS_N>,
    u: Polynomial<RELIN_ROUND1_CKKS_N>,
    e0: [Polynomial<RELIN_ROUND1_CKKS_N>; RELIN_ROUND1_CKKS_L],
    e1: [Polynomial<RELIN_ROUND1_CKKS_N>; RELIN_ROUND1_CKKS_L],
    r1_h0: [Polynomial<(2 * RELIN_ROUND1_CKKS_N) - 1>; RELIN_ROUND1_CKKS_L * RELIN_ROUND1_CKKS_L],
    r2_h0: [Polynomial<RELIN_ROUND1_CKKS_N - 1>; RELIN_ROUND1_CKKS_L * RELIN_ROUND1_CKKS_L],
    r1_h1: [Polynomial<(2 * RELIN_ROUND1_CKKS_N) - 1>; RELIN_ROUND1_CKKS_L * RELIN_ROUND1_CKKS_L],
    r2_h1: [Polynomial<RELIN_ROUND1_CKKS_N - 1>; RELIN_ROUND1_CKKS_L * RELIN_ROUND1_CKKS_L],
    h0: [Polynomial<RELIN_ROUND1_CKKS_N>; RELIN_ROUND1_CKKS_L * RELIN_ROUND1_CKKS_L],
    h1: [Polynomial<RELIN_ROUND1_CKKS_N>; RELIN_ROUND1_CKKS_L * RELIN_ROUND1_CKKS_L],
) -> pub (Field, Field, Field) {
    let relin_round1: RelinRound1<RELIN_ROUND1_CKKS_N, RELIN_ROUND1_CKKS_L, RELIN_ROUND1_CKKS_BIT_A, RELIN_ROUND1_CKKS_BIT_SK, RELIN_ROUND1_CKKS_BIT_U, RELIN_ROUND1_CKKS_BIT_E, RELIN_ROUND1_CKKS_BIT_R1, RELIN_ROUND1_CKKS_BIT_R2, RELIN_ROUND1_CKKS_BIT_H> = RelinRound1::new(
        RELIN_ROUND1_CKKS_CONFIGS,
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
