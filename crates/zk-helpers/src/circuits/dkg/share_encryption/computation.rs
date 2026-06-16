// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Computation types for the share-encryption circuit: configs, bounds, bit widths, and input.
//!
//! [`Configs`], [`Bounds`], [`Bits`], and [`Inputs`] are produced from BFV parameters
//! and (for input) plaintext, ciphertext, and encryption randomness. Input values are
//! normalized for the ZKP field so the Noir circuit's range checks and commitment checks succeed.

use crate::circuits::commitments::{
    compute_dkg_pk_commitment, compute_share_encryption_commitment_from_message,
};
use crate::dkg::share_encryption::ShareEncryptionCircuit;
use crate::dkg::share_encryption::ShareEncryptionCircuitData;
use crate::math::{compute_k0is, compute_q_mod_t_centered, plaintext_poly_u64};
use crate::math::{cyclotomic_polynomial, decompose_residue};
use crate::polynomial_to_toml_json;
use crate::utils::{compute_modulus_bit, compute_msg_bit};
use crate::CircuitsErrors;
use crate::{calculate_bit_width, crt_polynomial_to_toml_json};
use crate::{compute_q_mod_t, compute_q_product};
use crate::{CircuitComputation, Computation};
use e3_fhe_params::build_pair_for_preset;
use e3_fhe_params::BfvPreset;
use e3_polynomial::CrtPolynomial;
use e3_polynomial::Polynomial;
use fhe::bfv::SecretKey;
use fhe_math::zq::Modulus;
use itertools::izip;
use num_bigint::ToBigInt;
use num_bigint::{BigInt, BigUint};
use num_traits::{Signed, ToPrimitive};
use rayon::iter::ParallelIterator;
use rayon::prelude::ParallelBridge;
use serde::{Deserialize, Serialize};

/// Output of [`CircuitComputation::compute`] for [`ShareEncryptionCircuit`]: bounds, bit widths, and input.
#[derive(Debug)]
pub struct ShareEncryptionOutput {
    /// Coefficient bounds used to derive bit widths.
    pub bounds: Bounds,
    /// Bit widths used by the Noir prover for packing.
    pub bits: Bits,
    /// Input for the share-encryption circuit.
    pub inputs: Inputs,
}

/// Implementation of [`CircuitComputation`] for [`ShareEncryptionCircuit`].
impl CircuitComputation for ShareEncryptionCircuit {
    type Preset = BfvPreset;
    type Data = ShareEncryptionCircuitData;
    type Output = ShareEncryptionOutput;
    type Error = CircuitsErrors;

    fn compute(preset: Self::Preset, data: &Self::Data) -> Result<Self::Output, Self::Error> {
        let bounds = Bounds::compute(preset, data)?;
        let bits = Bits::compute(preset, &bounds)?;
        let inputs = Inputs::compute(preset, data)?;

        Ok(ShareEncryptionOutput {
            bounds,
            bits,
            inputs,
        })
    }
}

/// Global configs for the share-encryption circuit: plaintext modulus, [q]_t, moduli, k0is, bits, and bounds.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Configs {
    /// Plaintext modulus (as usize).
    pub t: usize,
    /// [q]_t reduced to ZKP field modulus.
    pub q_mod_t: BigUint,
    /// centered [q]_t reduced to ZKP field modulus.
    pub q_mod_t_centered: BigInt,
    /// CRT moduli (one per limb).
    pub moduli: Vec<u64>,
    /// k0_i = [1/q_i]_t per modulus, for scaling in the circuit.
    pub k0is: Vec<u64>,
    pub bits: Bits,
    pub bounds: Bounds,
}

/// Bit widths used by the Noir prover (e.g. for packing coefficients).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Bits {
    pub pk_bit: u32,
    pub ct_bit: u32,
    pub u_bit: u32,
    pub e0_bit: u32,
    pub e1_bit: u32,
    pub msg_bit: u32,
    pub r1_bit: u32,
    pub r2_bit: u32,
    pub p1_bit: u32,
    pub p2_bit: u32,
}

/// Coefficient bounds for polynomials (used to derive bit widths).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Bounds {
    pub u_bound: BigUint,
    pub e0_bound: BigUint,
    pub e1_bound: BigUint,
    pub msg_bound: BigUint,
    pub pk_bounds: Vec<BigUint>,
    pub r1_low_bounds: Vec<BigUint>,
    pub r1_up_bounds: Vec<BigUint>,
    pub r2_bounds: Vec<BigUint>,
    pub p1_bounds: Vec<BigUint>,
    pub p2_bounds: Vec<BigUint>,
}

/// Input for the share-encryption circuit: CRT limbs for pk, ct, randomness, and message.
///
/// Coefficients are reduced to the ZKP field modulus for serialization. The circuit verifies
/// that the ciphertext and commitments match the public inputs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Inputs {
    /// Public key and ciphertext polynomials in CRT form (per modulus).
    pub pk0is: CrtPolynomial,
    pub pk1is: CrtPolynomial,
    pub ct0is: CrtPolynomial,
    pub ct1is: CrtPolynomial,
    pub r1is: CrtPolynomial,
    pub r2is: CrtPolynomial,
    pub p1is: CrtPolynomial,
    pub p2is: CrtPolynomial,
    pub e0is: CrtPolynomial,
    pub e0_quotients: CrtPolynomial,
    pub e0: Polynomial,
    pub e1: Polynomial,
    pub u: Polynomial,
    pub message: Polynomial,
    pub pk_commitment: BigInt,
    pub msg_commitment: BigInt,
}

impl Computation for Configs {
    type Preset = BfvPreset;
    type Data = ShareEncryptionCircuitData;
    type Error = CircuitsErrors;

    fn compute(preset: Self::Preset, data: &Self::Data) -> Result<Self, CircuitsErrors> {
        let (_, dkg_params) =
            build_pair_for_preset(preset).map_err(|e| CircuitsErrors::Sample(e.to_string()))?;

        let moduli = dkg_params.moduli().to_vec();
        let t = dkg_params.plaintext();
        let q = compute_q_product(&moduli);
        let q_mod_t = compute_q_mod_t(&q, t);
        let q_mod_t_centered = compute_q_mod_t_centered(&moduli, t);
        let k0is = compute_k0is(&moduli, t)?;

        let bounds = Bounds::compute(preset, data)?;
        let bits = Bits::compute(preset, &bounds)?;

        Ok(Configs {
            t: t as usize,
            q_mod_t,
            q_mod_t_centered,
            moduli,
            k0is,
            bits,
            bounds,
        })
    }
}

impl Computation for Bits {
    type Preset = BfvPreset;
    type Data = Bounds;
    type Error = crate::utils::ZkHelpersUtilsError;

    fn compute(_: Self::Preset, data: &Self::Data) -> Result<Self, Self::Error> {
        let max_pk_bound = data.pk_bounds.iter().max().unwrap();
        let max_r2_bound = data.r2_bounds.iter().max().unwrap();
        let max_p1_bound = data.p1_bounds.iter().max().unwrap();
        let max_p2_bound = data.p2_bounds.iter().max().unwrap();

        let pk_bit = calculate_bit_width(BigInt::from(max_pk_bound.clone()));
        let ct_bit = calculate_bit_width(BigInt::from(max_pk_bound.clone()));
        let u_bit = calculate_bit_width(BigInt::from(data.u_bound.clone()));
        let e0_bit = calculate_bit_width(BigInt::from(data.e0_bound.clone()));
        let e1_bit = calculate_bit_width(BigInt::from(data.e1_bound.clone()));
        let msg_bit = calculate_bit_width(BigInt::from(data.msg_bound.clone()));
        let r1_bit = calculate_bit_width(BigInt::from(
            data.r1_low_bounds
                .iter()
                .chain(data.r1_up_bounds.iter())
                .max()
                .unwrap()
                .clone(),
        ));
        let r2_bit = calculate_bit_width(BigInt::from(max_r2_bound.clone()));
        let p1_bit = calculate_bit_width(BigInt::from(max_p1_bound.clone()));
        let p2_bit = calculate_bit_width(BigInt::from(max_p2_bound.clone()));

        Ok(Bits {
            pk_bit,
            ct_bit,
            u_bit,
            e0_bit,
            e1_bit,
            msg_bit,
            r1_bit,
            r2_bit,
            p1_bit,
            p2_bit,
        })
    }
}

impl Computation for Bounds {
    type Preset = BfvPreset;
    type Data = ShareEncryptionCircuitData;
    type Error = CircuitsErrors;

    fn compute(preset: Self::Preset, _: &Self::Data) -> Result<Self, Self::Error> {
        let (_, dkg_params) =
            build_pair_for_preset(preset).map_err(|e| CircuitsErrors::Sample(e.to_string()))?;

        let n = BigInt::from(dkg_params.degree());
        let ctx = dkg_params.context_at_level(0)?;

        let t = BigInt::from(dkg_params.plaintext());

        // CBD bound
        let cbd_bound = (dkg_params.variance() * 2) as u64;
        // Uniform bound
        let uniform_bound = (dkg_params.get_error1_variance() * BigUint::from(3u32))
            .sqrt()
            .to_bigint()
            .ok_or_else(|| {
                CircuitsErrors::Other("Failed to convert uniform bound to BigInt".into())
            })?;

        let u_bound = SecretKey::sk_bound() as u128; // u_bound is the same as sk_bound

        // e0 = e1 in the fhe.rs
        let e0_bound: u128 = if dkg_params.get_error1_variance() <= &BigUint::from(16u32) {
            cbd_bound as u128
        } else {
            uniform_bound.to_u128().unwrap()
        };
        let e1_bound = cbd_bound; // e1 = e2 in the fhe.rs

        // Message bound: message is in [0, t), so bound is t - 1
        let msg_bound = t.clone() - BigInt::from(1);

        let ptxt_up_bound = (t.clone() - BigInt::from(1)) / BigInt::from(2);
        let ptxt_low_bound: BigInt = if (t.clone() % BigInt::from(2)) == BigInt::from(1) {
            -1 * ptxt_up_bound.clone()
        } else {
            -1 * ptxt_up_bound.clone() - BigInt::from(1)
        };

        // Calculate bounds for each CRT basis
        let moduli: Vec<u64> = ctx.moduli_operators().iter().map(|q| **q).collect();
        let k0is = compute_k0is(&moduli, dkg_params.plaintext())?;

        let mut pk_bounds: Vec<BigInt> = Vec::new();
        let mut r1_low_bounds: Vec<BigInt> = Vec::new();
        let mut r1_up_bounds: Vec<BigInt> = Vec::new();
        let mut r2_bounds: Vec<BigInt> = Vec::new();
        let mut p1_bounds: Vec<BigInt> = Vec::new();
        let mut p2_bounds: Vec<BigInt> = Vec::new();

        for (i, qi) in ctx.moduli_operators().iter().enumerate() {
            let qi_bigint = BigInt::from(**qi);
            let qi_bound = (&qi_bigint - BigInt::from(1)) / BigInt::from(2);

            let k0qi = BigInt::from(k0is[i]);

            // PK and R2 bounds (same as qi_bound)
            pk_bounds.push(qi_bound.clone());
            r2_bounds.push(qi_bound.clone());

            let e0_bound_i = e0_bound % qi_bigint.clone();

            // R1 bounds (more complex calculation)
            let r1_low: BigInt = (&ptxt_low_bound * k0qi.abs()
                - &((&n * u_bound + BigInt::from(2)) * &qi_bound + e0_bound_i.clone()))
                / &qi_bigint;
            let r1_up: BigInt = (&ptxt_up_bound * k0qi.abs()
                + ((&n * u_bound + BigInt::from(2)) * &qi_bound + e0_bound_i.clone()))
                / &qi_bigint;

            r1_low_bounds.push(BigInt::from(-1) * r1_low.clone());
            r1_up_bounds.push(r1_up.clone());

            // P1 and P2 bounds
            let p1_bound: BigInt =
                ((&n * u_bound + BigInt::from(2)) * &qi_bound + e1_bound) / &qi_bigint;
            p1_bounds.push(p1_bound.clone());
            p2_bounds.push(qi_bound.clone());
        }

        Ok(Bounds {
            pk_bounds: pk_bounds
                .iter()
                .map(|b| BigUint::from(b.to_u128().unwrap()))
                .collect(),
            u_bound: BigUint::from(u_bound as u64),
            e0_bound: BigUint::from(e0_bound),
            e1_bound: BigUint::from(e1_bound),
            msg_bound: BigUint::from(msg_bound.to_u128().unwrap()),
            r1_low_bounds: r1_low_bounds
                .iter()
                .map(|b| BigUint::from(b.to_u128().unwrap()))
                .collect(),
            r1_up_bounds: r1_up_bounds
                .iter()
                .map(|b| BigUint::from(b.to_u128().unwrap()))
                .collect(),
            r2_bounds: r2_bounds
                .iter()
                .map(|b| BigUint::from(b.to_u128().unwrap()))
                .collect(),
            p1_bounds: p1_bounds
                .iter()
                .map(|b| BigUint::from(b.to_u128().unwrap()))
                .collect(),
            p2_bounds: p2_bounds
                .iter()
                .map(|b| BigUint::from(b.to_u128().unwrap()))
                .collect(),
        })
    }
}

impl Computation for Inputs {
    type Preset = BfvPreset;
    type Data = ShareEncryptionCircuitData;
    type Error = CircuitsErrors;

    fn compute(_preset: Self::Preset, data: &Self::Data) -> Result<Self, Self::Error> {
        let (_, dkg_params) =
            build_pair_for_preset(_preset).map_err(|e| CircuitsErrors::Sample(e.to_string()))?;

        let pk = data.public_key.clone();
        let pt = data.plaintext.clone();
        let ct = &data.ciphertext;
        let u = &data.u_rns;
        let e0 = &data.e0_rns;
        let e1 = &data.e1_rns;

        let ctx = dkg_params.context_at_level(pt.level())?;
        let moduli = dkg_params.moduli();

        #[allow(non_snake_case)]
        let modulus_q = BigInt::from(ctx.modulus().clone());
        let t = dkg_params.plaintext();
        let n = dkg_params.degree() as u64;
        let q_mod_t = (&modulus_q % t)
            .to_u64()
            .ok_or_else(|| CircuitsErrors::Other("Failed to convert q_mod_t to u64".into()))?;
        let cyclo = cyclotomic_polynomial(n);

        let mut e0_mod_q = Polynomial::from_fhe_polynomial(e0);
        e0_mod_q.reverse();
        e0_mod_q.center(&modulus_q);

        let mut k1_u64 = plaintext_poly_u64(&pt)?;
        Modulus::new(t)
            .map_err(|e| CircuitsErrors::Fhe(fhe::Error::from(e)))?
            .scalar_mul_vec(&mut k1_u64, q_mod_t);

        let mut k1 = Polynomial::from_u64_vector(k1_u64);
        k1.reverse();
        k1.center(&BigInt::from(t));

        let mut message = Polynomial::from_u64_vector(plaintext_poly_u64(&pt)?);
        message.reverse();

        let mut u = CrtPolynomial::from_fhe_polynomial(u).limb(0).clone();
        let mut e1 = CrtPolynomial::from_fhe_polynomial(e1).limb(0).clone();

        u.center(&BigInt::from(moduli[0]));
        u.reverse();

        e1.center(&BigInt::from(moduli[0]));
        e1.reverse();

        let mut ct0 = CrtPolynomial::from_fhe_polynomial(&ct[0]);
        let mut ct1 = CrtPolynomial::from_fhe_polynomial(&ct[1]);
        let mut pk0 = CrtPolynomial::from_fhe_polynomial(&pk.c[0]);
        let mut pk1 = CrtPolynomial::from_fhe_polynomial(&pk.c[1]);
        let mut e0_crt = CrtPolynomial::from_fhe_polynomial(e0);

        ct0.reverse();
        ct1.reverse();
        pk0.reverse();
        pk1.reverse();
        e0_crt.reverse();

        ct0.center(moduli)?;
        ct1.center(moduli)?;
        pk0.center(moduli)?;
        pk1.center(moduli)?;
        e0_crt.center(moduli)?;

        let CrtPolynomial { limbs: ct0_limbs } = ct0;
        let CrtPolynomial { limbs: ct1_limbs } = ct1;
        let CrtPolynomial { limbs: pk0_limbs } = pk0;
        let CrtPolynomial { limbs: pk1_limbs } = pk1;
        let CrtPolynomial { limbs: e0_limbs } = e0_crt;

        let mut results: Vec<_> = izip!(
            ctx.moduli_operators(),
            ct0_limbs,
            ct1_limbs,
            pk0_limbs,
            pk1_limbs,
            e0_limbs,
        )
        .enumerate()
        .par_bridge()
        .map(|(i, (qi, ct0i, ct1i, pk0i, pk1i, e0i))| {
            let qi_bigint = BigInt::from(**qi);

            let diff = e0_mod_q.sub(&e0i);
            let qi_poly = Polynomial::constant(qi_bigint.clone());
            let (e0_quotient, remainder) = diff.div(&qi_poly).expect("CRT requires exact division");

            assert!(
                remainder.is_zero(),
                "e0 - e0i must be divisible by qi (CRT consistency)"
            );

            let k0qi = BigInt::from(qi.inv(qi.neg(t)).unwrap());
            let ki = k1.scalar_mul(&k0qi);

            let ct0i_hat = {
                let pk0i_u_times = pk0i.mul(&u);
                let e0_plus_ki = e0i.add(&ki);

                assert_eq!((pk0i_u_times.coefficients().len() as u64) - 1, 2 * (n - 1));
                assert_eq!((e0_plus_ki.coefficients().len() as u64) - 1, n - 1);

                pk0i_u_times.add(&e0_plus_ki)
            };

            assert_eq!((ct0i_hat.coefficients().len() as u64) - 1, 2 * (n - 1));

            let (r1i, r2i) = decompose_residue(&ct0i, &ct0i_hat, &qi_bigint, &cyclo, n);

            let ct1i_hat = {
                let pk1i_u_times = pk1i.mul(&u);

                assert_eq!((pk1i_u_times.coefficients().len() as u64) - 1, 2 * (n - 1));

                pk1i_u_times.add(&e1)
            };
            assert_eq!((ct1i_hat.coefficients().len() as u64) - 1, 2 * (n - 1));

            let (p1i, p2i) = decompose_residue(&ct1i, &ct1i_hat, &qi_bigint, &cyclo, n);

            (
                i,
                r2i,
                r1i,
                ct0i,
                ct1i,
                pk0i,
                pk1i,
                p1i,
                p2i,
                e0i,
                e0_quotient,
            )
        })
        .collect();

        results.sort_by_key(|(i, ..)| *i);

        let mut pk0is = Vec::with_capacity(results.len());
        let mut pk1is = Vec::with_capacity(results.len());
        let mut ct0is = Vec::with_capacity(results.len());
        let mut ct1is = Vec::with_capacity(results.len());
        let mut r1is = Vec::with_capacity(results.len());
        let mut r2is = Vec::with_capacity(results.len());
        let mut p1is = Vec::with_capacity(results.len());
        let mut p2is = Vec::with_capacity(results.len());
        let mut e0is = Vec::with_capacity(results.len());
        let mut e0_quotients = Vec::with_capacity(results.len());

        for (_, r2i, r1i, ct0i, ct1i, pk0i, pk1i, p1i, p2i, e0i, e0_quotient) in results {
            pk0is.push(pk0i);
            pk1is.push(pk1i);
            ct0is.push(ct0i);
            ct1is.push(ct1i);
            r1is.push(r1i);
            r2is.push(r2i);
            p1is.push(p1i);
            p2is.push(p2i);
            e0is.push(e0i);
            e0_quotients.push(e0_quotient);
        }

        let pk0is = CrtPolynomial::new(pk0is);
        let pk1is = CrtPolynomial::new(pk1is);
        let ct0is = CrtPolynomial::new(ct0is);
        let ct1is = CrtPolynomial::new(ct1is);
        let r1is = CrtPolynomial::new(r1is);
        let r2is = CrtPolynomial::new(r2is);
        let p1is = CrtPolynomial::new(p1is);
        let p2is = CrtPolynomial::new(p2is);
        let e0is = CrtPolynomial::new(e0is);
        let e0_quotients = CrtPolynomial::new(e0_quotients);

        let pk_bit = compute_modulus_bit(&dkg_params);
        let msg_bit = compute_msg_bit(&dkg_params);
        let pk_commitment = compute_dkg_pk_commitment(&pk0is, &pk1is, pk_bit);
        let msg_commitment = compute_share_encryption_commitment_from_message(&message, msg_bit);

        Ok(Inputs {
            pk0is,
            pk1is,
            ct0is,
            ct1is,
            r1is,
            r2is,
            p1is,
            p2is,
            e0is,
            e0_quotients,
            e0: e0_mod_q,
            e1,
            u,
            message,
            pk_commitment,
            msg_commitment,
        })
    }

    // Used as input for Nargo execution.
    fn to_json(&self) -> serde_json::Result<serde_json::Value> {
        let pk0is = crt_polynomial_to_toml_json(&self.pk0is);
        let pk1is = crt_polynomial_to_toml_json(&self.pk1is);
        let ct0is = crt_polynomial_to_toml_json(&self.ct0is);
        let ct1is = crt_polynomial_to_toml_json(&self.ct1is);
        let u = polynomial_to_toml_json(&self.u);
        let e0 = polynomial_to_toml_json(&self.e0);
        let e0is = crt_polynomial_to_toml_json(&self.e0is);
        let e0_quotients = crt_polynomial_to_toml_json(&self.e0_quotients);
        let e1 = polynomial_to_toml_json(&self.e1);
        let message = polynomial_to_toml_json(&self.message);
        let r1is = crt_polynomial_to_toml_json(&self.r1is);
        let r2is = crt_polynomial_to_toml_json(&self.r2is);
        let p1is = crt_polynomial_to_toml_json(&self.p1is);
        let p2is = crt_polynomial_to_toml_json(&self.p2is);
        let pk_commitment = self.pk_commitment.to_string();
        let msg_commitment = self.msg_commitment.to_string();

        let json = serde_json::json!({
            "pk0is": pk0is,
            "pk1is": pk1is,
            "ct0is": ct0is,
            "ct1is": ct1is,
            "u": u,
            "e0": e0,
            "e0is": e0is,
            "e0_quotients": e0_quotients,
            "e1": e1,
            "message": message,
            "r1is": r1is,
            "r2is": r2is,
            "p1is": p1is,
            "p2is": p2is,
            "expected_pk_commitment": pk_commitment,
            "expected_message_commitment": msg_commitment,
        });

        Ok(json)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::ciphernodes_committee::CiphernodesCommitteeSize;
    use crate::computation::DkgInputType;
    use e3_fhe_params::BfvPreset;

    #[test]
    fn test_bound_and_bits_computation_consistency() {
        let sd = BfvPreset::InsecureThreshold512.search_defaults().unwrap();
        let committee = CiphernodesCommitteeSize::Small.values();
        let sample = ShareEncryptionCircuitData::generate_sample(
            BfvPreset::InsecureThreshold512,
            committee,
            DkgInputType::SecretKey,
            sd.z,
        )
        .unwrap();

        let bounds = Bounds::compute(BfvPreset::InsecureThreshold512, &sample).unwrap();
        let bits = Bits::compute(BfvPreset::InsecureThreshold512, &bounds).unwrap();

        let max_pk_bound = bounds.pk_bounds.iter().max().unwrap();
        let expected_bits = calculate_bit_width(BigInt::from(max_pk_bound.clone()));

        assert_eq!(max_pk_bound.clone(), BigUint::from(1125899906777088u128));
        assert_eq!(bits.pk_bit, expected_bits);
    }

    #[test]
    fn test_constants_json_roundtrip() {
        let sd = BfvPreset::InsecureThreshold512.search_defaults().unwrap();
        let committee = CiphernodesCommitteeSize::Small.values();
        let sample = ShareEncryptionCircuitData::generate_sample(
            BfvPreset::InsecureThreshold512,
            committee,
            DkgInputType::SecretKey,
            sd.z,
        )
        .unwrap();
        let constants = Configs::compute(BfvPreset::InsecureThreshold512, &sample).unwrap();

        let json = constants.to_json().unwrap();
        let decoded: Configs = serde_json::from_value(json).unwrap();

        assert_eq!(decoded.t, constants.t);
        assert_eq!(decoded.q_mod_t, constants.q_mod_t);
        assert_eq!(decoded.moduli, constants.moduli);
        assert_eq!(decoded.k0is, constants.k0is);
        assert_eq!(decoded.bits, constants.bits);
        assert_eq!(decoded.bounds, constants.bounds);
    }

    #[test]
    fn test_input_message_consistency() {
        let sd = BfvPreset::InsecureThreshold512.search_defaults().unwrap();
        let committee = CiphernodesCommitteeSize::Small.values();
        let sample = ShareEncryptionCircuitData::generate_sample(
            BfvPreset::InsecureThreshold512,
            committee,
            DkgInputType::SecretKey,
            sd.z,
        )
        .unwrap();
        let inputs = Inputs::compute(BfvPreset::InsecureThreshold512, &sample).unwrap();

        // inputs.message is plaintext coefficients (reversed, as used in circuit)
        let expected_message =
            Polynomial::from_u64_vector(plaintext_poly_u64(&sample.plaintext).unwrap());
        let mut expected = expected_message;
        expected.reverse();

        assert_eq!(inputs.message.coefficients(), expected.coefficients());
    }
}
