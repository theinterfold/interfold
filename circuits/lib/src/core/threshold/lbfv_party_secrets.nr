// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::core::threshold::pk_generation::Configs;
use crate::math::commitments::{
    compute_lbfv_pk_limb_eek_commitment, compute_sc_esm_secret_root_from_polynomial,
    compute_sc_sk_secret_root_from_polynomial,
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
pub struct LbfvPartySecrets<let N: u32, let L: u32, let ROWS: u32, let BIT_EEK: u32, let BIT_SK: u32, let BIT_E_SM: u32, let BIT_PK: u32, let N_CHUNKS: u32, let CHUNK_SIZE: u32> {
    configs: Configs<N, L>,
    sk: Polynomial<N>,
    e_sm: [Polynomial<N>; L],
    /// One key-generation error per gadget row. Bounded here so the `ROWS * L` limb proofs can
    /// open to these commitments instead of repeating the check `L` times per row.
    eek: [Polynomial<N>; ROWS],
}

impl<let N: u32, let L: u32, let ROWS: u32, let BIT_EEK: u32, let BIT_SK: u32, let BIT_E_SM: u32, let BIT_PK: u32, let N_CHUNKS: u32, let CHUNK_SIZE: u32> LbfvPartySecrets<N, L, ROWS, BIT_EEK, BIT_SK, BIT_E_SM, BIT_PK, N_CHUNKS, CHUNK_SIZE> {
    pub fn new(
        configs: Configs<N, L>,
        sk: Polynomial<N>,
        e_sm: [Polynomial<N>; L],
        eek: [Polynomial<N>; ROWS],
    ) -> Self {
        LbfvPartySecrets { configs, sk, e_sm, eek }
    }

    pub fn execute(self) -> (Field, Field, [Field; ROWS]) {
        self.perform_range_checks();

        let sk_commitment =
            compute_sc_sk_secret_root_from_polynomial::<N, N_CHUNKS, CHUNK_SIZE, BIT_SK>(self.sk);
        // `BIT_E_SM` is the residue width, matching what C2b packs with. The lifted bound over the
        // whole CRT basis is far wider and would leave most of every carrier empty.
        let e_sm_commitment = compute_sc_esm_secret_root_from_polynomial::<N, L, N_CHUNKS, CHUNK_SIZE, BIT_E_SM>(
            self.e_sm,
        );

        // Same helper and row tag the limbs use, so a limb's computed commitment matches this one
        // exactly. A different tag here would fail only at proving time.
        let mut eek_commitments: [Field; ROWS] = [0; ROWS];
        for row in 0..ROWS {
            eek_commitments[row] =
                compute_lbfv_pk_limb_eek_commitment::<N, BIT_EEK>(row, self.eek[row]);
        }

        (sk_commitment, e_sm_commitment, eek_commitments)
    }

    fn perform_range_checks(self) {
        // The quotient window in the row proofs assumes a ternary secret. `config` asserts that
        // once for the whole suite, so this circuit reads the bound rather than re-checking it.
        self.sk.range_check_2bounds::<BIT_SK>(self.configs.sk_bound, self.configs.sk_bound);

        for row in 0..ROWS {
            self.eek[row].range_check_2bounds::<BIT_EEK>(
                self.configs.eek_bound,
                self.configs.eek_bound,
            );
        }

        for l in 0..L {
            // Each residue is checked against its own modulus. The configured `e_sm_bound` is the
            // lifted bound over the whole CRT basis, so comparing a single residue to it is not the
            // right relation; that bound still needs proving, but not here and not per limb.
            centered::<N, BIT_PK>(self.e_sm[l], self.configs.qis[l]);
        }
    }
}

#[test]
fn test_lbfv_party_secrets_accepts_bounded_secrets() {
    let configs: Configs<4, 1> = Configs::new([17], 1, 1, 8);
    let circuit: LbfvPartySecrets<4, 1, 1, 2, 1, 5, 4, 1, 4> = LbfvPartySecrets::new(
        configs,
        Polynomial::new([1, -1, 0, 1]),
        [Polynomial::new([8, -8, 0, 1])],
        [Polynomial::new([0, 0, 0, 0])],
    );
    let _ = circuit.execute();
}

#[test(should_fail)]
fn test_lbfv_party_secrets_rejects_out_of_range_sk() {
    let configs: Configs<4, 1> = Configs::new([17], 1, 1, 8);
    let circuit: LbfvPartySecrets<4, 1, 1, 2, 1, 5, 4, 1, 4> = LbfvPartySecrets::new(
        configs,
        Polynomial::new([2, 0, 0, 0]),
        [Polynomial::new([0, 0, 0, 0])],
        [Polynomial::new([0, 0, 0, 0])],
    );
    let _ = circuit.execute();
}

#[test(should_fail)]
fn test_lbfv_party_secrets_rejects_non_centered_e_sm() {
    let configs: Configs<4, 1> = Configs::new([17], 1, 1, 8);
    let circuit: LbfvPartySecrets<4, 1, 1, 2, 1, 5, 4, 1, 4> = LbfvPartySecrets::new(
        configs,
        Polynomial::new([0, 0, 0, 0]),
        [Polynomial::new([9, 0, 0, 0])],
        [Polynomial::new([0, 0, 0, 0])],
    );
    let _ = circuit.execute();
}
