// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::math::commitments::{
    compute_lbfv_pk_limb_challenge, compute_lbfv_pk_limb_commitment,
    compute_lbfv_pk_limb_eek_commitment, compute_sc_sk_secret_root_from_polynomial,
};
use crate::math::polynomial::Polynomial;
use crate::math::secure_arithmetic::{append, centered, dot, fold_negacyclic, kernel};

/// Prove one CRT limb of one l-BFV public-key row.
///
/// **Verifies:** `pk0 = -(a*sk mod X^N+1) + eek + q*short` at a Fiat-Shamir point, with every
/// operand of that equation range-checked first. The bounds are what make the field identity imply
/// the integer one: the field has no ordering, so a checked equation alone proves only a congruence
/// modulo the native prime, and `q` is invertible there.
///
/// **Produces (tuple order):** `commit(sk)`, `commit(eek)`, `commit(pk0 limb)`. The row terminal
/// checks the first two for equality across the row's `L` limbs, which is what makes the limbs one
/// contribution rather than `L` unrelated ones.
///
/// `a` is pinned by the configuration, so it is a circuit constant rather than a caller-supplied
/// value and needs no transcript entry.
pub struct LbfvPkGenerationLimb<let N: u32, let BIT_EEK: u32, let BIT_SK: u32, let BIT_R1: u32, let BIT_PK: u32, let N_CHUNKS: u32, let CHUNK_SIZE: u32> {
    eek_bound: Field,
    sk_bound: Field,
    qi: Field,
    a: Polynomial<N>,
    row_index: u32,
    limb_index: u32,
    eek: Polynomial<N>,
    sk: Polynomial<N>,
    /// Modulus-switching quotient, degree `2N-2`. Reduced to length `N` inside the circuit; only
    /// the reduction is constrained, which is what removes the separate cyclotomic quotient.
    r1: Polynomial<2 * N - 1>,
    pk0: Polynomial<N>,
}

impl<let N: u32, let BIT_EEK: u32, let BIT_SK: u32, let BIT_R1: u32, let BIT_PK: u32, let N_CHUNKS: u32, let CHUNK_SIZE: u32> LbfvPkGenerationLimb<N, BIT_EEK, BIT_SK, BIT_R1, BIT_PK, N_CHUNKS, CHUNK_SIZE> {
    pub fn new(
        eek_bound: Field,
        sk_bound: Field,
        qi: Field,
        a: Polynomial<N>,
        row_index: u32,
        limb_index: u32,
        eek: Polynomial<N>,
        sk: Polynomial<N>,
        r1: Polynomial<2 * N - 1>,
        pk0: Polynomial<N>,
    ) -> Self {
        LbfvPkGenerationLimb { eek_bound, sk_bound, qi, a, row_index, limb_index, eek, sk, r1, pk0 }
    }

    pub fn execute(self) -> (Field, Field, Field) {
        // A ternary secret is the one parameter this circuit cannot read off the config. The
        // generated `r1_bounds`, and so the quotient window below, are derived from a formula that
        // assumes it; a wider secret would make that window too narrow to hold the quotient.
        assert(self.sk_bound == 1);

        // Step 1: bound the small secrets to their configured distributions.
        self.sk.range_check_2bounds::<BIT_SK>(self.sk_bound, self.sk_bound);
        self.eek.range_check_2bounds::<BIT_EEK>(self.eek_bound, self.eek_bound);

        // Step 2: reduce the modulus-switching quotient modulo X^N + 1, then bound the result. The
        // reduction itself is a witness derivation over the native field and may wrap; only this
        // bound makes the reduced values usable as integers.
        let short_offset = 2.pow_32(BIT_R1 as Field);
        let q_short = fold_negacyclic(self.r1);
        for j in 0..N {
            (q_short.coefficients[j] + short_offset).assert_max_bit_size::<BIT_R1 + 1>();
        }

        // Step 3: pin pk0 to its canonical centered interval. Without this one public key limb
        // opens under several distinct commitments.
        centered::<N, BIT_PK>(self.pk0, self.qi);

        // Step 4: derive the commitments this limb publishes. `sk` uses the chunked-root helper so
        // the value matches what the C2 chunk pipeline finalizes, which is what C1->C2a compares.
        let sk_commitment =
            compute_sc_sk_secret_root_from_polynomial::<N, N_CHUNKS, CHUNK_SIZE, BIT_SK>(self.sk);
        let eek_commitment =
            compute_lbfv_pk_limb_eek_commitment::<N, BIT_EEK>(self.row_index, self.eek);
        let pk_limb_commitment =
            compute_lbfv_pk_limb_commitment::<N, BIT_PK>(self.row_index, self.limb_index, self.pk0);

        // Step 5: bind every independent operand before drawing the checking point. `pk0` and `sk`
        // are bound through their commitments; `eek` and the quotient are packed directly; `qi` and
        // `a` are configuration constants, and `DS_CLG_PK_GENERATION_LIMB_V1` identifies the
        // circuit, so the payload carries no circuit tag.
        let mut payload = [
            N as Field,
            self.row_index as Field,
            self.limb_index as Field,
            sk_commitment,
            eek_commitment,
            pk_limb_commitment,
            self.qi,
        ]
            .as_vector();
        payload = append::<N, BIT_EEK + 1>(payload, self.eek, self.eek_bound);
        payload = append::<N, BIT_R1 + 1>(payload, q_short, short_offset);
        let gamma = compute_lbfv_pk_limb_challenge(payload);

        // Step 6: check pk0 = -(a*sk mod X^N+1) + eek + q*short. The kernel evaluates the reduced
        // product by constrained recurrence, so no product hint is accepted.
        let k = kernel(self.sk, gamma);
        let mut residual = [0; N];
        for j in 0..N {
            residual[j] = self.pk0.coefficients[j]
                - self.eek.coefficients[j]
                - self.qi * q_short.coefficients[j];
        }
        assert(
            Polynomial::new(residual).eval(gamma) == -dot(self.a, k),
            "Public key equation failed",
        );

        (sk_commitment, eek_commitment, pk_limb_commitment)
    }
}

#[test]
fn test_lbfv_pk_generation_limb_accepts_valid_equation() {
    let zero: Polynomial<4> = Polynomial::new([0, 0, 0, 0]);
    let circuit: LbfvPkGenerationLimb<4, 2, 1, 2, 5, 1, 4> = LbfvPkGenerationLimb::new(
        1,
        1,
        17,
        zero,
        0,
        0,
        zero,
        zero,
        Polynomial::new([0, 0, 0, 0, 0, 0, 0]),
        zero,
    );
    let _ = circuit.execute();
}

#[test(should_fail)]
fn test_lbfv_pk_generation_limb_rejects_invalid_equation() {
    let zero: Polynomial<4> = Polynomial::new([0, 0, 0, 0]);
    let circuit: LbfvPkGenerationLimb<4, 2, 1, 2, 5, 1, 4> = LbfvPkGenerationLimb::new(
        1,
        1,
        17,
        zero,
        0,
        0,
        zero,
        zero,
        Polynomial::new([0, 0, 0, 0, 0, 0, 0]),
        Polynomial::new([1, 0, 0, 0]),
    );
    let _ = circuit.execute();
}
