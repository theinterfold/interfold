// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::core::threshold::pk_generation::Configs;
use crate::math::commitments::{
    compute_lbfv_pk_limb_challenge, compute_lbfv_pk_limb_commitment,
    compute_lbfv_pk_limb_eek_commitment, compute_sc_sk_secret_root_from_polynomial,
};
use crate::math::polynomial::Polynomial;
use crate::math::secure_arithmetic::{append, centered, dot, kernel};

/// Prove one CRT limb of one l-BFV public-key row.
///
/// **Verifies:** `pk0 = -(a*sk mod X^N+1) + eek + q*r` at a Fiat-Shamir point, with every
/// operand of that equation range-checked first. The bounds are what make the field identity imply
/// the integer one: the field has no ordering, so a checked equation alone proves only a congruence
/// modulo the native prime, and `q` is invertible there.
///
/// **Consumes:** `expected_sk_commitment` and `expected_eek_commitment`, both from
/// `lbfv_party_secrets`. That circuit bounds the secret key once per party and each row's error
/// once per row; this one proves the values it used open to those commitments, so neither range
/// check is repeated across the `GADGET_DIM * L` limbs.
///
/// **Produces:** `commit(pk0 limb)`. The row terminal checks the two consumed commitments for
/// equality across the row's `L` limbs, which is what makes the limbs one contribution rather than
/// `L` unrelated ones.
///
/// `a` is pinned by the configuration, so it is a circuit constant rather than a caller-supplied
/// value and needs no transcript entry.
pub struct LbfvPkGenerationLimb<let N: u32, let L: u32, let BIT_EEK: u32, let BIT_SK: u32, let BIT_R: u32, let BIT_PK: u32, let N_CHUNKS: u32, let CHUNK_SIZE: u32> {
    /// Shared with C1: this circuit proves the same relation over a gadget row's CRS instead of
    /// the single CRP, and reads its modulus out of `qis` by `limb_index`.
    configs: Configs<N, L>,
    /// Secret-key commitment this limb must open to, bound by `lbfv_party_secrets`.
    expected_sk_commitment: Field,
    /// This row's error commitment, likewise bound by `lbfv_party_secrets`.
    expected_eek_commitment: Field,
    a: Polynomial<N>,
    row_index: u32,
    limb_index: u32,
    eek: Polynomial<N>,
    sk: Polynomial<N>,
    /// Modulus-switching quotient, already reduced modulo `X^N + 1` by the generator. Only its
    /// bound is constrained here.
    r: Polynomial<N>,
    pk0: Polynomial<N>,
}

impl<let N: u32, let L: u32, let BIT_EEK: u32, let BIT_SK: u32, let BIT_R: u32, let BIT_PK: u32, let N_CHUNKS: u32, let CHUNK_SIZE: u32> LbfvPkGenerationLimb<N, L, BIT_EEK, BIT_SK, BIT_R, BIT_PK, N_CHUNKS, CHUNK_SIZE> {
    pub fn new(
        configs: Configs<N, L>,
        expected_sk_commitment: Field,
        expected_eek_commitment: Field,
        a: Polynomial<N>,
        row_index: u32,
        limb_index: u32,
        eek: Polynomial<N>,
        sk: Polynomial<N>,
        r: Polynomial<N>,
        pk0: Polynomial<N>,
    ) -> Self {
        LbfvPkGenerationLimb {
            configs,
            expected_sk_commitment,
            expected_eek_commitment,
            a,
            row_index,
            limb_index,
            eek,
            sk,
            r,
            pk0,
        }
    }

    pub fn execute(self) -> Field {
        // The quotient window below assumes a ternary secret. `config` asserts that once for the
        // whole suite, so this circuit reads the bound rather than re-checking it.
        self.perform_range_checks();

        // Binding, not bounding: `lbfv_party_secrets` already range-checked the key behind this
        // commitment, so opening to it is what lets the range check stay out of every limb.
        assert(
            compute_sc_sk_secret_root_from_polynomial::<N, N_CHUNKS, CHUNK_SIZE, BIT_SK>(self.sk)
                == self.expected_sk_commitment,
            "sk commitment mismatch",
        );
        assert(
            compute_lbfv_pk_limb_eek_commitment::<N, BIT_EEK>(self.row_index, self.eek)
                == self.expected_eek_commitment,
            "eek commitment mismatch",
        );
        let pk_limb_commitment =
            compute_lbfv_pk_limb_commitment::<N, BIT_PK>(self.row_index, self.limb_index, self.pk0);
        let gamma = self.generate_challenge(pk_limb_commitment);
        self.verify_evaluation(gamma);

        pk_limb_commitment
    }

    fn perform_range_checks(self) {
        let r_offset = 2.pow_32(BIT_R as Field);
        for j in 0..N {
            (self.r.coefficients[j] + r_offset).assert_max_bit_size::<BIT_R + 1>();
        }

        // Pin pk0 to its canonical centered interval. Without this one public key limb opens under
        // several distinct commitments.
        centered::<N, BIT_PK>(self.pk0, self.configs.qis[self.limb_index]);
    }

    fn generate_challenge(self, pk_limb_commitment: Field) -> Field {
        // Bind every independent operand before drawing the checking point. `sk` and `eek` come in
        // as commitments and `pk0` is committed here, so only the quotient is packed; `qi` and `a`
        // are configuration constants, and `DS_CLG_PK_GENERATION_LIMB_V1` identifies the circuit,
        // so the payload carries no circuit tag.
        let mut payload = [
            N as Field,
            self.row_index as Field,
            self.limb_index as Field,
            self.expected_sk_commitment,
            self.expected_eek_commitment,
            pk_limb_commitment,
            self.configs.qis[self.limb_index],
        ]
            .as_vector();
        payload = append::<N, BIT_R + 1>(payload, self.r, 2.pow_32(BIT_R as Field));
        compute_lbfv_pk_limb_challenge(payload)
    }

    fn verify_evaluation(self, gamma: Field) {
        // pk0 = -(a*sk mod X^N+1) + eek + q*r. The kernel evaluates the reduced product by
        // constrained recurrence, so no product hint is accepted.
        let k = kernel(self.sk, gamma);
        let mut residual = [0; N];
        for j in 0..N {
            residual[j] = self.pk0.coefficients[j]
                - self.eek.coefficients[j]
                - self.configs.qis[self.limb_index] * self.r.coefficients[j];
        }
        assert(
            Polynomial::new(residual).eval(gamma) == -dot(self.a, k),
            "Public key equation failed",
        );
    }
}

#[test]
fn test_lbfv_pk_generation_limb_accepts_valid_equation() {
    let zero: Polynomial<4> = Polynomial::new([0, 0, 0, 0]);
    let configs: Configs<4, 1> = Configs::new([17], 1, 1, 8);
    let expected_sk = compute_sc_sk_secret_root_from_polynomial::<4, 1, 4, 1>(zero);
    let expected_eek = compute_lbfv_pk_limb_eek_commitment::<4, 2>(0, zero);
    let circuit: LbfvPkGenerationLimb<4, 1, 2, 1, 2, 5, 1, 4> = LbfvPkGenerationLimb::new(
        configs,
        expected_sk,
        expected_eek,
        zero,
        0,
        0,
        zero,
        zero,
        zero,
        zero,
    );
    let _ = circuit.execute();
}

#[test(should_fail)]
fn test_lbfv_pk_generation_limb_rejects_invalid_equation() {
    let zero: Polynomial<4> = Polynomial::new([0, 0, 0, 0]);
    let configs: Configs<4, 1> = Configs::new([17], 1, 1, 8);
    let expected_sk = compute_sc_sk_secret_root_from_polynomial::<4, 1, 4, 1>(zero);
    let expected_eek = compute_lbfv_pk_limb_eek_commitment::<4, 2>(0, zero);
    let circuit: LbfvPkGenerationLimb<4, 1, 2, 1, 2, 5, 1, 4> = LbfvPkGenerationLimb::new(
        configs,
        expected_sk,
        expected_eek,
        zero,
        0,
        0,
        zero,
        zero,
        zero,
        Polynomial::new([1, 0, 0, 0]),
    );
    let _ = circuit.execute();
}
