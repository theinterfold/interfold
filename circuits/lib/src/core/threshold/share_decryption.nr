// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::math::commitments::{
    compute_aggregated_shares_commitment_checked, compute_ciphertext_commitment_checked,
    compute_partial_decryption_c0_commitment, compute_threshold_decryption_share_commitment,
    compute_threshold_share_decryption_challenge,
};
use crate::math::helpers::{flatten, flatten_checked};
use crate::math::modulo::U64::ModU64;
use crate::math::polynomial::{negacyclic_kernel, Polynomial};
use crate::math::prf::{native_residue, prf_decryption_mask};

pub struct Configs<let L: u32> {
    pub qis: [Field; L],
    pub r_bounds: [Field; L],
    pub e_fresh_bound: Field,
}

impl<let L: u32> Configs<L> {
    pub fn new(qis: [Field; L], r_bounds: [Field; L]) -> Self {
        Configs { qis, r_bounds, e_fresh_bound: 0 }
    }

    pub fn with_fresh_bound(mut self, bound: Field) -> Self {
        self.e_fresh_bound = bound;
        self
    }
}

/// Prove `d = lambda_i*c1*sk_i + e_i + mask_i` in the reduced ring.
/// c0 is committed here and added once by C7, never by an individual share.
pub struct ShareDecryption<let N: u32, let K: u32, let L: u32, let BIT_CT: u32, let BIT_SK: u32, let BIT_E: u32, let BIT_R: u32, let BIT_D: u32, let BIT_NATIVE: u32, let PARTIES: u32, let SET: u32, let B: u32> {
    configs: Configs<L>,
    expected_sk_commitment: Field,
    ct_commitment: Field,
    c0_commitment: Field,
    ct0: [Polynomial<N>; L],
    ct1: [Polynomial<N>; L],
    sk: [Polynomial<N>; L],
    e_fresh: [Polynomial<N>; L],
    e_signed: Polynomial<N>,
    e_quot: [Polynomial<N>; L],
    r: [Polynomial<N>; L],
    d: [Polynomial<N>; L],
    d_native_trunc: [Polynomial<K>; L],
    party_idx: u32,
    decryptors: [Field; SET],
    outgoing_keys: [Field; PARTIES],
    incoming_keys: [Field; PARTIES],
    outgoing_key_commitments: [Field; PARTIES],
    incoming_key_commitments: [Field; PARTIES],
}

impl<let N: u32, let K: u32, let L: u32, let BIT_CT: u32, let BIT_SK: u32, let BIT_E: u32, let BIT_R: u32, let BIT_D: u32, let BIT_NATIVE: u32, let PARTIES: u32, let SET: u32, let B: u32> ShareDecryption<N, K, L, BIT_CT, BIT_SK, BIT_E, BIT_R, BIT_D, BIT_NATIVE, PARTIES, SET, B> {
    pub fn new(
        configs: Configs<L>,
        expected_sk_commitment: Field,
        ct_commitment: Field,
        c0_commitment: Field,
        ct0: [Polynomial<N>; L],
        ct1: [Polynomial<N>; L],
        sk: [Polynomial<N>; L],
        e_fresh: [Polynomial<N>; L],
        e_signed: Polynomial<N>,
        e_quot: [Polynomial<N>; L],
        r: [Polynomial<N>; L],
        d: [Polynomial<N>; L],
        d_native_trunc: [Polynomial<K>; L],
        party_idx: u32,
        decryptors: [Field; SET],
        outgoing_keys: [Field; PARTIES],
        incoming_keys: [Field; PARTIES],
        outgoing_key_commitments: [Field; PARTIES],
        incoming_key_commitments: [Field; PARTIES],
    ) -> Self {
        assert(K <= N);
        ShareDecryption {
            configs,
            expected_sk_commitment,
            ct_commitment,
            c0_commitment,
            ct0,
            ct1,
            sk,
            e_fresh,
            e_signed,
            e_quot,
            r,
            d,
            d_native_trunc,
            party_idx,
            decryptors,
            outgoing_keys,
            incoming_keys,
            outgoing_key_commitments,
            incoming_key_commitments,
        }
    }

    fn verify_ct_commitment(self) {
        assert(
            compute_ciphertext_commitment_checked::<N, L, BIT_CT>(self.ct0, self.ct1)
                == self.ct_commitment,
            "Ciphertext commitment mismatch",
        );
    }

    fn ct0_low(self) -> [Polynomial<K>; L] {
        let mut low = [Polynomial::new([0; K]); L];
        for limb in 0..L {
            let mut coeffs = [0; K];
            for j in 0..K {
                coeffs[j] = native_residue(
                    self.ct0[limb].coefficients[N - 1 - j],
                    self.configs.qis[limb],
                );
            }
            low[limb] = Polynomial::new(coeffs);
        }
        low
    }

    fn verify_d_native_trunc_binding(self) {
        for limb in 0..L {
            let q = self.configs.qis[limb];
            for j in 0..K {
                let u = self.d_native_trunc[limb].coefficients[j];
                u.assert_max_bit_size::<64>();
                (q - 1 - u).assert_max_bit_size::<64>();
                let centered = if (u as u128) > (((q - 1) / 2) as u128) {
                    u - q
                } else {
                    u
                };
                assert(centered == self.d[limb].coefficients[N - 1 - j]);
            }
        }
    }

    fn check_fresh_noise(self) {
        let bound = self.configs.e_fresh_bound;
        bound.assert_max_bit_size::<234>();
        // A 188-bit quotient times a <=62-bit modulus stays below the scalar field.
        let quotient_bound: Field = 392318858461667547739736838950479151006397215279002157056;
        for j in 0..N {
            let signed = self.e_signed.coefficients[j];
            (signed + bound).assert_max_bit_size::<235>();
            (bound - signed).assert_max_bit_size::<235>();
            for limb in 0..L {
                let q = self.configs.qis[limb];
                q.assert_max_bit_size::<62>();
                let half = (q - 1) / 2;
                let residue = self.e_fresh[limb].coefficients[j];
                (residue + half).assert_max_bit_size::<64>();
                (half - residue).assert_max_bit_size::<64>();
                let quotient = self.e_quot[limb].coefficients[j];
                (quotient + quotient_bound).assert_max_bit_size::<190>();
                (quotient_bound - quotient).assert_max_bit_size::<190>();
                assert(signed == quotient * q + residue, "Fresh noise residue mismatch");
            }
        }
    }

    fn payload(self) -> [Field] {
        let mut inputs = [
            self.expected_sk_commitment,
            self.ct_commitment,
            self.c0_commitment,
            self.party_idx as Field,
        ]
            .as_vector();
        for i in 0..SET {
            inputs = inputs.push_back(self.decryptors[i]);
        }
        for i in 0..PARTIES {
            inputs = inputs.push_back(self.outgoing_key_commitments[i]);
            inputs = inputs.push_back(self.incoming_key_commitments[i]);
        }
        // Checked openings fix sk/ct. Fresh noise and r have explicit integer bounds.
        inputs = flatten::<N, L, BIT_R>(inputs, self.r);
        inputs = flatten::<N, L, BIT_E>(inputs, self.e_fresh);
        // Full d must have an injective transcript opening (IF-013).
        flatten_checked::<N, L, BIT_D>(inputs, self.d)
    }

    fn generate_challenge(self) -> Field {
        compute_threshold_share_decryption_challenge::<L>(self.payload())
    }

    fn verify_identity(self, limb: u32, gamma: Field, mask: Polynomial<N>, lambda: Field) {
        let mut residual = [0; N];
        for j in 0..N {
            residual[j] = self.d[limb].coefficients[j]
                - self.e_fresh[limb].coefficients[j]
                - mask.coefficients[j]
                - self.configs.qis[limb] * self.r[limb].coefficients[j];
        }
        assert(
            Polynomial::new(residual).eval(gamma)
                == lambda * self.ct1[limb].dot(negacyclic_kernel(self.sk[limb], gamma)),
            "Decryption share computation failed",
        );
    }

    pub fn execute(self) -> Field {
        assert(
            compute_aggregated_shares_commitment_checked::<N, L, BIT_SK>(self.sk)
                == self.expected_sk_commitment,
            "S commitment mismatch",
        );
        self.verify_ct_commitment();
        assert(
            compute_partial_decryption_c0_commitment::<K, L, BIT_NATIVE>(self.ct0_low())
                == self.c0_commitment,
            "c0 commitment mismatch",
        );
        self.check_fresh_noise();
        for limb in 0..L {
            self.r[limb].range_check_2bounds::<BIT_R>(
                self.configs.r_bounds[limb],
                self.configs.r_bounds[limb],
            );
        }
        self.verify_d_native_trunc_binding();
        // `verify_ct_commitment` has already bound this value to the opened ciphertext.
        let mask = prf_decryption_mask::<N, L, PARTIES, SET, B>(
            self.party_idx,
            self.decryptors,
            self.outgoing_keys,
            self.incoming_keys,
            self.outgoing_key_commitments,
            self.incoming_key_commitments,
            self.ct_commitment,
            self.configs.qis,
        );
        let gamma = self.generate_challenge();
        for limb in 0..L {
            let lambda =
                lagrange_at_zero(self.configs.qis[limb], self.decryptors, self.party_idx + 1);
            self.verify_identity(limb, gamma, mask[limb], lambda);
        }
        compute_threshold_decryption_share_commitment::<K, L, BIT_NATIVE>(self.d_native_trunc)
    }
}

pub fn lagrange_at_zero<let SET: u32>(q: Field, ids: [Field; SET], owner: u32) -> Field {
    let m = ModU64::new(q as u64);
    let mut numerator = 1;
    let mut denominator = 1;
    for j in 0..SET {
        if ids[j] != owner as Field {
            numerator = m.mul_mod(numerator, ids[j]);
            denominator = m.mul_mod(denominator, m.sub(ids[j], owner as Field));
        }
    }
    let value = m.div_mod(numerator, denominator);
    if (value as u128) > (((q - 1) / 2) as u128) {
        value - q
    } else {
        value
    }
}

fn zero_witness() -> ShareDecryption<8, 1, 1, 35, 35, 35, 43, 35, 36, 3, 2, 36> {
    let z = Polynomial::new([0; 8]);
    let anchor = compute_aggregated_shares_commitment_checked::<8, 1, 35>([z]);
    let ct = compute_ciphertext_commitment_checked::<8, 1, 35>([z], [z]);
    let c0 = compute_partial_decryption_c0_commitment::<1, 1, 36>([Polynomial::new([0])]);
    let key = crate::math::commitments::compute_packed_prf_key_commitment(1, 0);
    ShareDecryption::new(
        Configs::new([68719403009], [1]),
        anchor,
        ct,
        c0,
        [z],
        [z],
        [z],
        [z],
        z,
        [z],
        [z],
        [z],
        [Polynomial::new([0])],
        0,
        [1, 2],
        [0; 3],
        [0; 3],
        [key; 3],
        [crate::math::commitments::compute_packed_prf_key_commitment(0, 0); 3],
    )
}

#[test]
fn zero_witness_is_accepted() {
    let _ = zero_witness().execute();
}

#[test]
fn challenge_depends_on_the_ct_commitment() {
    let c = zero_witness();
    let mut other = c;
    other.ct_commitment += 1;
    assert(c.generate_challenge() != other.generate_challenge());
}

#[test(should_fail)]
fn forged_d_with_same_transcript_is_rejected() {
    let mut c = zero_witness();
    c.d[0].coefficients[7] = 1;
    let gamma = c.generate_challenge();
    let radix: Field = 1099511627776;
    let shift = -1 / (gamma.pow_32(6) * (gamma - radix));
    c.d[0].coefficients[0] += shift;
    c.d[0].coefficients[1] -= radix * shift;
    assert(c.generate_challenge() == gamma);
}

fn carry_into_ct0(
    mut c: ShareDecryption<8, 1, 1, 35, 35, 35, 43, 35, 36, 3, 2, 36>,
) -> ShareDecryption<8, 1, 1, 35, 35, 35, 43, 35, 36, 3, 2, 36> {
    c.ct0[0].coefficients[0] += 1;
    c.ct0[0].coefficients[1] -= 1099511627776;
    c
}

#[test]
fn carried_ciphertext_keeps_the_unchecked_commitment() {
    let c = carry_into_ct0(zero_witness());
    assert(
        crate::math::commitments::compute_ciphertext_commitment::<8, 1, 35>(c.ct0, c.ct1)
            == c.ct_commitment,
    );
}

#[test(should_fail)]
fn ciphertext_second_opening_is_rejected() {
    carry_into_ct0(zero_witness()).verify_ct_commitment();
}

#[test]
fn honest_reduced_identity_holds() {
    // For owner 1 in {1,2}, lambda=2. The descending product is [57,-26,-1,38].
    let ct1 = Polynomial::new([30, 11, -20, 7]);
    let sk = Polynomial::new([1, -1, 0, 1]);
    let gamma: Field = 123;
    let lambda = lagrange_at_zero(97, [1, 2], 1);
    assert(
        lambda * ct1.dot(negacyclic_kernel(sk, gamma))
            == Polynomial::new([114, -52, -2, 76]).eval(gamma),
    );
}

#[test(should_fail)]
fn tampered_quotient_is_rejected() {
    let mut c = zero_witness();
    c.r[0].coefficients[7] = 1;
    c.verify_identity(0, 123, Polynomial::new([0; 8]), 2);
}

#[test(should_fail)]
fn excessive_fresh_noise_is_rejected() {
    let mut c = zero_witness();
    c.e_signed.coefficients[0] = 1;
    c.check_fresh_noise();
}

#[test(should_fail)]
fn wrong_noise_lift_is_rejected() {
    let mut c = zero_witness();
    c.e_quot[0].coefficients[0] = 1;
    c.check_fresh_noise();
}
