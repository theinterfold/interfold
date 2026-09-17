// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::math::commitments::{
    compute_sc_esm_secret_root_from_polynomial, compute_sc_sk_secret_root_from_polynomial,
    compute_threshold_pk_challenge, compute_threshold_pk_commitment, threshold_pk_challenge_payload,
};
use crate::math::polynomial::Polynomial;
use crate::math::secure_arithmetic::{append, centered, dot, kernel};

/// Parameters for threshold public key generation (C1).
pub struct Configs<let N: u32, let L: u32> {
    /// CRT moduli: [q_0, q_1, ..., q_{L-1}]
    pub qis: [Field; L],
    /// Bound for error polynomial (eek) coefficients
    pub eek_bound: Field,
    /// Bound for secret key polynomial (sk) coefficients
    pub sk_bound: Field,
    /// Bound for smudging noise polynomial (e_sm) coefficients
    pub e_sm_bound: Field,
    /// Bounds for r1 polynomials (modulus switching quotients) for each CRT basis
    pub r1_bounds: [Field; L],
    /// Bounds for r2 polynomials (cyclotomic reduction quotients) for each CRT basis
    pub r2_bounds: [Field; L],
}

impl<let N: u32, let L: u32> Configs<N, L> {
    pub fn new(
        qis: [Field; L],
        eek_bound: Field,
        sk_bound: Field,
        e_sm_bound: Field,
        r1_bounds: [Field; L],
        r2_bounds: [Field; L],
    ) -> Self {
        Configs { qis, eek_bound, sk_bound, e_sm_bound, r1_bounds, r2_bounds }
    }
}

/// Threshold public key contribution (C1), for the secure parameter sets.
///
/// **Role:** Prove one party's TrBFV public-key contribution from hidden `sk`, `eek`, and `e_sm`
/// (the `pk1` limb is the CRS `a`).
///
/// **Verifies:** `pk0 = -(a*sk mod X^N+1) + eek + q*short` per modulus, at a Fiat-Shamir point, with
/// every operand of that equation range-checked first. The bounds are what make the field identity
/// imply the integer one: the field has no ordering, so a checked equation alone proves only a
/// congruence modulo the native prime, and `q` is invertible there.
///
/// **Produces (tuple order):**
/// - `commit(sk)` -> C2a (share computation).
/// - `commit(pk_trbfv)` -> C5 (pk aggregation).
/// - `commit(e_sm)` -> C2b (share computation).
///
/// `BIT_PK` bounds each centered coefficient and `BIT_R1` sets the quotient window. Both come from
/// the configuration, so the circuit covers every parameter set without per-preset constants.
pub struct PkGeneration<let N: u32, let L: u32, let BIT_EEK: u32, let BIT_SK: u32, let BIT_E_SM: u32, let BIT_R1: u32, let BIT_PK: u32, let N_CHUNKS: u32, let CHUNK_SIZE: u32> {
    /// Cryptographic parameters including bounds, moduli, and constants.
    configs: Configs<N, L>,

    /// Common reference polynomial, one per modulus. Pinned by the configuration, so it is a
    /// circuit constant rather than a caller-supplied value and needs no transcript entry.
    a: [Polynomial<N>; L],

    /// Error polynomial (secret witness). Small coefficients from the error distribution.
    eek: Polynomial<N>,

    /// Secret key polynomial (secret witness). Ternary coefficients.
    sk: Polynomial<N>,

    /// Smudging noise polynomial (secret witness), one limb per modulus.
    e_sm: [Polynomial<N>; L],

    /// Modulus-switching quotients (secret witnesses), one per modulus, already reduced modulo
    /// `X^N + 1` by the generator. The reduction is a witness derivation, so the circuit takes the
    /// reduced form and constrains only its range.
    q_short: [Polynomial<N>; L],

    /// Threshold public key first component per modulus (committed witness). The second component
    /// is `a[i]`.
    pk0: [Polynomial<N>; L],
}

impl<let N: u32, let L: u32, let BIT_EEK: u32, let BIT_SK: u32, let BIT_E_SM: u32, let BIT_R1: u32, let BIT_PK: u32, let N_CHUNKS: u32, let CHUNK_SIZE: u32> PkGeneration<N, L, BIT_EEK, BIT_SK, BIT_E_SM, BIT_R1, BIT_PK, N_CHUNKS, CHUNK_SIZE> {
    pub fn new(
        configs: Configs<N, L>,
        a: [Polynomial<N>; L],
        eek: Polynomial<N>,
        sk: Polynomial<N>,
        e_sm: [Polynomial<N>; L],
        q_short: [Polynomial<N>; L],
        pk0: [Polynomial<N>; L],
    ) -> Self {
        PkGeneration { configs, a, eek, sk, e_sm, q_short, pk0 }
    }

    /// Executes the threshold public key generation circuit.
    ///
    /// Returns `(commit(sk), commit(pk_trbfv), commit(e_sm))` as documented on the struct.
    pub fn execute(self) -> (Field, Field, Field) {
        // A ternary secret is the one parameter this circuit cannot read off the config. The
        // generated `r1_bounds`, and so the quotient window below, are derived from a formula that
        // assumes it; a wider secret would make that window too narrow to hold the quotient.
        assert(self.configs.sk_bound == 1);

        // Step 1: bound the small secrets to their configured distributions.
        self.sk.range_check_2bounds::<BIT_SK>(self.configs.sk_bound, self.configs.sk_bound);
        self.eek.range_check_2bounds::<BIT_EEK>(self.configs.eek_bound, self.configs.eek_bound);

        // Step 2: bound each modulus-switching quotient. The generator supplies it already reduced
        // modulo X^N + 1, and the circuit constrains no part of that derivation; only these bounds
        // make the values usable as integers.
        let short_offset = 2.pow_32(BIT_R1 as Field);
        for l in 0..L {
            for j in 0..N {
                (self.q_short[l].coefficients[j] + short_offset).assert_max_bit_size::<BIT_R1 + 1>();
            }
        }

        // Step 3: pin pk0 and each noise limb to their canonical centered intervals. Without this
        // one public key opens under several distinct commitments.
        for l in 0..L {
            centered::<N, BIT_PK>(self.pk0[l], self.configs.qis[l]);
            // Keeps the noise commitment packing injective: a centered residue is below 2^BIT_PK,
            // so the encoding needs at least that many bits per digit, or the shifted value goes
            // negative and wraps. The upper end is already enforced by `packing_layout`.
            assert(BIT_E_SM >= BIT_PK);
            // The generator already centers each noise residue modulo q_l. Prove the configured
            // global bound contains that interval, then check the narrower canonical one. This
            // implies the configured bound rather than replacing it, and leaves the global noise
            // distribution and its sampler unchanged.
            self.configs.e_sm_bound.assert_max_bit_size::<BIT_E_SM>();
            (self.configs.e_sm_bound - (self.configs.qis[l] - 1) / 2)
                .assert_max_bit_size::<BIT_E_SM>();
            centered::<N, BIT_PK>(self.e_sm[l], self.configs.qis[l]);
        }

        // Step 4: derive commitments for downstream circuits and the checking transcript.
        let sk_commitment =
            compute_sc_sk_secret_root_from_polynomial::<N, N_CHUNKS, CHUNK_SIZE, BIT_SK>(self.sk);
        let e_sm_commitment = compute_sc_esm_secret_root_from_polynomial::<N, L, N_CHUNKS, CHUNK_SIZE, BIT_E_SM>(
            self.e_sm,
        );
        let pk_commitment = compute_threshold_pk_commitment::<N, L, BIT_PK>(self.pk0);

        // Step 5: bind every independent operand before drawing the checking point. pk0 and sk are
        // bound through their commitments; eek and the quotients are packed directly; the moduli
        // and `a` are configuration constants. Smudging noise has no entry, because it is not an
        // operand of the equation below; `e_sm_commitment` is a public output, which is what binds
        // it.
        let mut payload = threshold_pk_challenge_payload::<N, L>(sk_commitment, pk_commitment);
        payload = append::<N, BIT_EEK + 1>(payload, self.eek, self.configs.eek_bound);
        for l in 0..L {
            payload = payload.push_back(self.configs.qis[l]);
            payload = append::<N, BIT_R1 + 1>(payload, self.q_short[l], short_offset);
        }
        let x = compute_threshold_pk_challenge(payload);

        // Step 6: check pk0 = -(a*sk mod X^N+1) + eek + q*short per modulus. The kernel evaluates
        // the reduced product by constrained recurrence, so no product hint is accepted.
        let k = kernel(self.sk, x);
        for l in 0..L {
            let mut residual = [0; N];
            for j in 0..N {
                residual[j] = self.pk0[l].coefficients[j]
                    - self.eek.coefficients[j]
                    - self.configs.qis[l] * self.q_short[l].coefficients[j];
            }
            assert(
                Polynomial::new(residual).eval(x) == -dot(self.a[l], k),
                "Public key equation failed",
            );
        }

        (sk_commitment, pk_commitment, e_sm_commitment)
    }
}
