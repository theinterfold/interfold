// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

// C8-CKKS (HYBRID gadget), ONE GADGET DIGIT of the ParamSet-2 share:
//   h0[l] = -a[l]*u + ((P*g_digit) mod q_l)*s + e0  (mod q_l, mod x^N+1)
//   h1[l] = a[l]*s + e1                              (mod q_l, mod x^N+1)
// for every limb l of Q.P, with the PUBLIC s/u commitments reproduced from
// the private s/u (so the dnum digit proofs of one share are bound to one
// secret pair) and the digit index public (the gadget row comes from the
// config table). Output: the per-digit share commitment commit(h0||h1).
//
// Witnesses: `cargo run -p e3-zk-helpers --example gen_ckks_c8_hybrid_digit_prover -- --param-set 2`
// (one Prover_digit_<j>.toml per digit; Prover.toml is digit 0).

use lib::configs::ckks_relin_round1_hybrid_ps2::{
    RELIN_ROUND1_HYBRID_CKKS_BIT_A, RELIN_ROUND1_HYBRID_CKKS_BIT_E, RELIN_ROUND1_HYBRID_CKKS_BIT_H,
    RELIN_ROUND1_HYBRID_CKKS_BIT_R1, RELIN_ROUND1_HYBRID_CKKS_BIT_R2,
    RELIN_ROUND1_HYBRID_CKKS_BIT_SK, RELIN_ROUND1_HYBRID_CKKS_BIT_U,
    RELIN_ROUND1_HYBRID_CKKS_CONFIGS, RELIN_ROUND1_HYBRID_CKKS_D, RELIN_ROUND1_HYBRID_CKKS_LT,
    RELIN_ROUND1_HYBRID_CKKS_N,
};
use lib::core::threshold::relin_round1_hybrid_ckks_digit::RelinRound1HybridDigit;
use lib::math::polynomial::Polynomial;

fn main(
    s_commitment: pub Field,
    u_commitment: pub Field,
    digit: pub Field,
    a: [Polynomial<RELIN_ROUND1_HYBRID_CKKS_N>; RELIN_ROUND1_HYBRID_CKKS_LT],
    s: Polynomial<RELIN_ROUND1_HYBRID_CKKS_N>,
    u: Polynomial<RELIN_ROUND1_HYBRID_CKKS_N>,
    e0: Polynomial<RELIN_ROUND1_HYBRID_CKKS_N>,
    e1: Polynomial<RELIN_ROUND1_HYBRID_CKKS_N>,
    r1_h0: [Polynomial<(2 * RELIN_ROUND1_HYBRID_CKKS_N) - 1>; RELIN_ROUND1_HYBRID_CKKS_LT],
    r2_h0: [Polynomial<RELIN_ROUND1_HYBRID_CKKS_N - 1>; RELIN_ROUND1_HYBRID_CKKS_LT],
    r1_h1: [Polynomial<(2 * RELIN_ROUND1_HYBRID_CKKS_N) - 1>; RELIN_ROUND1_HYBRID_CKKS_LT],
    r2_h1: [Polynomial<RELIN_ROUND1_HYBRID_CKKS_N - 1>; RELIN_ROUND1_HYBRID_CKKS_LT],
    h0: [Polynomial<RELIN_ROUND1_HYBRID_CKKS_N>; RELIN_ROUND1_HYBRID_CKKS_LT],
    h1: [Polynomial<RELIN_ROUND1_HYBRID_CKKS_N>; RELIN_ROUND1_HYBRID_CKKS_LT],
) -> pub Field {
    let relin_digit: RelinRound1HybridDigit<RELIN_ROUND1_HYBRID_CKKS_N, RELIN_ROUND1_HYBRID_CKKS_D, RELIN_ROUND1_HYBRID_CKKS_LT, RELIN_ROUND1_HYBRID_CKKS_BIT_A, RELIN_ROUND1_HYBRID_CKKS_BIT_SK, RELIN_ROUND1_HYBRID_CKKS_BIT_U, RELIN_ROUND1_HYBRID_CKKS_BIT_E, RELIN_ROUND1_HYBRID_CKKS_BIT_R1, RELIN_ROUND1_HYBRID_CKKS_BIT_R2, RELIN_ROUND1_HYBRID_CKKS_BIT_H> = RelinRound1HybridDigit::new(
        RELIN_ROUND1_HYBRID_CKKS_CONFIGS,
        s_commitment,
        u_commitment,
        digit,
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
    relin_digit.execute()
}
