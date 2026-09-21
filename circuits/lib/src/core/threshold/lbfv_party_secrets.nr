// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::core::threshold::pk_generation::Configs;
use crate::math::commitments::{
    compute_sc_esm_secret_root_from_polynomial, compute_sc_sk_secret_root_from_polynomial,
};
use crate::math::polynomial::Polynomial;
use crate::math::secure_arithmetic::centered;

/// The two per-party secrets of an l-BFV contribution, bounded and committed.
///
/// **Role:** what is left of C1 once its public-key equation is removed. At secure-16384 that
/// equation is dead weight: the aggregator ignores standalone C1 verification, and the published
/// key comes from `lbfv_pk_aggregation` over the row proofs. Its two remaining live outputs are
/// these commitments, so they get their own circuit instead of a 5-limb public-key proof.
///
/// **Verifies:** `sk` lies in its ternary distribution and each smudging-noise limb lies in the
/// canonical centered interval of its modulus. There is no polynomial identity here, so there is
/// no challenge point and no Fiat-Shamir transcript - the statement is only "I know secrets within
/// these bounds, and these are their commitments".
///
/// **Produces (tuple order):**
/// - `commit(sk)` -> C2a (share computation), and the l-BFV row proofs, which must agree with it.
/// - `commit(e_sm)` -> C2b (share computation) and C6 (threshold share decryption).
///
/// Both use the chunked-root helpers, so the values match what the C2 chunk pipeline finalizes.
/// One `e_sm` set per party is enough, and a per-limb circuit could not build this commitment
/// anyway: each `e_sm` chunk commitment spans all `L` CRT limbs at once.
pub struct LbfvPartySecrets<let N: u32, let L: u32, let BIT_SK: u32, let BIT_E_SM: u32, let BIT_PK: u32, let N_CHUNKS: u32, let CHUNK_SIZE: u32> {
    configs: Configs<N, L>,
    sk: Polynomial<N>,
    e_sm: [Polynomial<N>; L],
}

impl<let N: u32, let L: u32, let BIT_SK: u32, let BIT_E_SM: u32, let BIT_PK: u32, let N_CHUNKS: u32, let CHUNK_SIZE: u32> LbfvPartySecrets<N, L, BIT_SK, BIT_E_SM, BIT_PK, N_CHUNKS, CHUNK_SIZE> {
    pub fn new(configs: Configs<N, L>, sk: Polynomial<N>, e_sm: [Polynomial<N>; L]) -> Self {
        LbfvPartySecrets { configs, sk, e_sm }
    }

    pub fn execute(self) -> (Field, Field) {
        self.perform_range_checks();

        let sk_commitment =
            compute_sc_sk_secret_root_from_polynomial::<N, N_CHUNKS, CHUNK_SIZE, BIT_SK>(self.sk);
        let e_sm_commitment = compute_sc_esm_secret_root_from_polynomial::<N, L, N_CHUNKS, CHUNK_SIZE, BIT_E_SM>(
            self.e_sm,
        );

        (sk_commitment, e_sm_commitment)
    }

    fn perform_range_checks(self) {
        // A ternary secret is the one parameter this circuit cannot read off the config. The row
        // proofs that bind to `commit(sk)` derive their quotient window from a formula that assumes
        // it, so rejecting a wider secret here keeps both sides on the same assumption.
        assert(self.configs.sk_bound == 1);

        self.sk.range_check_2bounds::<BIT_SK>(self.configs.sk_bound, self.configs.sk_bound);

        for l in 0..L {
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
    }
}

#[test]
fn test_lbfv_party_secrets_accepts_bounded_secrets() {
    let configs: Configs<4, 1> = Configs::new([17], 1, 1, 8, [1], [1]);
    let circuit: LbfvPartySecrets<4, 1, 1, 5, 4, 1, 4> = LbfvPartySecrets::new(
        configs,
        Polynomial::new([1, -1, 0, 1]),
        [Polynomial::new([8, -8, 0, 1])],
    );
    let _ = circuit.execute();
}

#[test(should_fail)]
fn test_lbfv_party_secrets_rejects_out_of_range_sk() {
    let configs: Configs<4, 1> = Configs::new([17], 1, 1, 8, [1], [1]);
    let circuit: LbfvPartySecrets<4, 1, 1, 5, 4, 1, 4> = LbfvPartySecrets::new(
        configs,
        Polynomial::new([2, 0, 0, 0]),
        [Polynomial::new([0, 0, 0, 0])],
    );
    let _ = circuit.execute();
}

#[test(should_fail)]
fn test_lbfv_party_secrets_rejects_non_centered_e_sm() {
    let configs: Configs<4, 1> = Configs::new([17], 1, 1, 8, [1], [1]);
    let circuit: LbfvPartySecrets<4, 1, 1, 5, 4, 1, 4> = LbfvPartySecrets::new(
        configs,
        Polynomial::new([0, 0, 0, 0]),
        [Polynomial::new([9, 0, 0, 0])],
    );
    let _ = circuit.execute();
}

#[test(should_fail)]
fn test_lbfv_party_secrets_rejects_non_ternary_parameter_set() {
    let configs: Configs<4, 1> = Configs::new([17], 1, 2, 8, [1], [1]);
    let circuit: LbfvPartySecrets<4, 1, 2, 5, 4, 1, 4> = LbfvPartySecrets::new(
        configs,
        Polynomial::new([0, 0, 0, 0]),
        [Polynomial::new([0, 0, 0, 0])],
    );
    let _ = circuit.execute();
}
