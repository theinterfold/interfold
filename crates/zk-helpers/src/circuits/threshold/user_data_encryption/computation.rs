// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Computation types for the user data encryption circuit: constants, bounds, bit widths, and inputs.
//!
//! [`Configs`], [`Bounds`], [`Bits`], and [`Inputs`] are produced from BFV parameters
//! and (for input) a public key. They implement [`Computation`] and are used by codegen.

use crate::calculate_bit_width;
use crate::get_zkp_modulus;
use crate::math::compute_k0is;
use crate::math::{cyclotomic_polynomial, decompose_residue, plaintext_poly_u64};
use crate::threshold::user_data_encryption::circuit::UserDataEncryptionCircuit;
use crate::threshold::user_data_encryption::circuit::UserDataEncryptionCircuitData;
use crate::CircuitsErrors;
use crate::{CircuitComputation, Computation};
use e3_fhe_params::build_pair_for_preset;
use e3_fhe_params::BfvPreset;
use e3_polynomial::CrtPolynomial;
use e3_polynomial::Polynomial;
use fhe::bfv::SecretKey;
use fhe_math::zq::Modulus;
use fhe_traits::Serialize as FheSerialize;
use itertools::izip;
use num_bigint::BigInt;
use num_bigint::BigUint;
use num_bigint::ToBigInt;
use num_traits::Signed;
use num_traits::ToPrimitive;
use rayon::iter::ParallelIterator;
use rayon::prelude::ParallelBridge;
use serde::{Deserialize, Serialize};
/// Output of [`CircuitComputation::compute`] for [`UserDataEncryptionCircuit`]: bounds, bit widths, and inputs.
#[derive(Debug)]
pub struct UserDataEncryptionComputationOutput {
    pub bounds: Bounds,
    pub bits: Bits,
    pub inputs: Inputs,
}

/// Implementation of [`CircuitComputation`] for [`UserDataEncryptionCircuit`].
impl CircuitComputation for UserDataEncryptionCircuit {
    type Preset = BfvPreset;
    type Data = UserDataEncryptionCircuitData;
    type Output = UserDataEncryptionComputationOutput;
    type Error = CircuitsErrors;

    fn compute(preset: Self::Preset, data: &Self::Data) -> Result<Self::Output, Self::Error> {
        let bounds = Bounds::compute(preset, &())?;
        let bits = Bits::compute(preset, &bounds)?;
        let inputs = Inputs::compute(preset, data)?;

        Ok(UserDataEncryptionComputationOutput {
            bounds,
            bits,
            inputs,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Configs {
    pub n: usize,
    pub l: usize,
    pub moduli: Vec<u64>,
    pub k0is: Vec<u64>,
    pub bits: Bits,
    pub bounds: Bounds,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Bits {
    pub pk_bit: u32,
    pub ct_bit: u32,
    pub u_bit: u32,
    pub e0_bit: u32,
    pub e1_bit: u32,
    pub k_bit: u32,
    /// Width of ct0's reduction quotient `r`.
    pub ct0_r_bit: u32,
    /// Width of ct1's reduction quotient `r`.
    pub ct1_r_bit: u32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Bounds {
    pub pk_bounds: Vec<BigUint>,
    pub u_bound: BigUint,
    pub e0_bound: BigUint,
    pub e1_bound: BigUint,
    pub k1_low_bound: BigUint,
    pub k1_up_bound: BigUint,
    /// Bounds on ct0's reduction quotient `r`, per CRT basis.
    pub ct0_r_bounds: Vec<BigUint>,
    /// Bounds on ct1's reduction quotient `r`, per CRT basis.
    pub ct1_r_bounds: Vec<BigUint>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Inputs {
    pub pk0is: CrtPolynomial,
    pub pk1is: CrtPolynomial,
    pub ct0is: CrtPolynomial,
    pub ct1is: CrtPolynomial,
    /// ct0's reduction quotient, already reduced modulo `X^N + 1`.
    pub ct0_r: CrtPolynomial,
    /// ct1's reduction quotient, already reduced modulo `X^N + 1`.
    pub ct1_r: CrtPolynomial,
    pub e0: Polynomial,
    pub e1: Polynomial,
    pub u: Polynomial,
    pub k1: Polynomial,
    pub ciphertext: Vec<u8>,
}

impl Computation for Configs {
    type Preset = BfvPreset;
    type Data = ();
    type Error = CircuitsErrors;

    fn compute(preset: Self::Preset, _: &Self::Data) -> Result<Self, CircuitsErrors> {
        let (threshold_params, _) =
            build_pair_for_preset(preset).map_err(|e| CircuitsErrors::Sample(e.to_string()))?;

        let moduli = threshold_params.moduli().to_vec();
        let k0is = compute_k0is(threshold_params.moduli(), threshold_params.plaintext())?;

        let bounds = Bounds::compute(preset, &())?;
        let bits = Bits::compute(preset, &bounds)?;

        Ok(Configs {
            n: threshold_params.degree(),
            l: moduli.len(),
            k0is,
            moduli,
            bits,
            bounds,
        })
    }
}

impl Computation for Bits {
    type Preset = BfvPreset;
    type Data = Bounds;
    type Error = CircuitsErrors;

    fn compute(_: Self::Preset, data: &Self::Data) -> Result<Self, Self::Error> {
        let max_pk_bound = data.pk_bounds.iter().max().unwrap();

        let pk_bit = calculate_bit_width(BigInt::from(max_pk_bound.clone()));
        // We can safely assume that the ct bound is the same as the pk bound.
        let ct_bit = calculate_bit_width(BigInt::from(max_pk_bound.clone()));
        let u_bit = calculate_bit_width(BigInt::from(data.u_bound.clone()));
        let e0_bit = calculate_bit_width(BigInt::from(data.e0_bound.clone()));
        let e1_bit = calculate_bit_width(BigInt::from(data.e1_bound.clone()));

        // For k1, use the maximum of low and up bounds
        let k1_low_bit = calculate_bit_width(BigInt::from(data.k1_low_bound.clone()));
        let k1_up_bit = calculate_bit_width(BigInt::from(data.k1_up_bound.clone()));
        let k_bit = k1_low_bit.max(k1_up_bit);

        // Each `r` is two-sided, so take the widest bound across the CRT bases.
        let mut ct0_r_bit = 0;
        for bound in &data.ct0_r_bounds {
            ct0_r_bit = ct0_r_bit.max(calculate_bit_width(BigInt::from(bound.clone())));
        }
        let mut ct1_r_bit = 0;
        for bound in &data.ct1_r_bounds {
            ct1_r_bit = ct1_r_bit.max(calculate_bit_width(BigInt::from(bound.clone())));
        }

        Ok(Bits {
            pk_bit,
            ct_bit,
            u_bit,
            e0_bit,
            e1_bit,
            k_bit,
            ct0_r_bit,
            ct1_r_bit,
        })
    }
}

impl Computation for Bounds {
    type Preset = BfvPreset;
    type Data = ();
    type Error = CircuitsErrors;

    fn compute(preset: Self::Preset, _: &Self::Data) -> Result<Self, Self::Error> {
        let (threshold_params, _) =
            build_pair_for_preset(preset).map_err(|e| CircuitsErrors::Sample(e.to_string()))?;

        let n = BigInt::from(threshold_params.degree());
        let ctx = threshold_params.context_at_level(0)?;

        let t = BigInt::from(threshold_params.plaintext());

        // CBD bound
        let cbd_bound = (threshold_params.variance() * 2) as u64;
        // Uniform bound
        let uniform_bound = (threshold_params.get_error1_variance() * BigUint::from(3u32))
            .sqrt()
            .to_bigint()
            .ok_or_else(|| {
                CircuitsErrors::Other("Failed to convert uniform bound to BigInt".into())
            })?;

        let u_bound = SecretKey::sk_bound() as u128; // u_bound is the same as sk_bound

        // e0 = e1 in the fhe.rs
        let e0_bound: u128 = if threshold_params.get_error1_variance() <= &BigUint::from(16u32) {
            cbd_bound as u128
        } else {
            uniform_bound.to_u128().unwrap()
        };
        let e1_bound = cbd_bound; // e1 = e2 in the fhe.rs

        let ptxt_up_bound = (t.clone() - BigInt::from(1)) / BigInt::from(2);
        let ptxt_low_bound: BigInt = if (t.clone() % BigInt::from(2)) == BigInt::from(1) {
            -1 * ptxt_up_bound.clone()
        } else {
            -1 * ptxt_up_bound.clone() - BigInt::from(1)
        };

        let k1_low_bound: BigInt = BigInt::from(-1) * ptxt_low_bound.clone();
        let k1_up_bound: BigInt = ptxt_up_bound.clone();

        // Calculate bounds for each CRT basis
        let moduli: Vec<u64> = ctx.moduli_operators().iter().map(|q| **q).collect();
        let k0is = compute_k0is(&moduli, threshold_params.plaintext())?;

        let mut pk_bounds: Vec<BigInt> = Vec::new();
        let mut ct0_r_bounds: Vec<BigInt> = Vec::new();
        let mut ct1_r_bounds: Vec<BigInt> = Vec::new();

        for (i, qi) in ctx.moduli_operators().iter().enumerate() {
            let qi_bigint = BigInt::from(**qi);
            let qi_bound = (&qi_bigint - BigInt::from(1)) / BigInt::from(2);

            let k0qi = BigInt::from(k0is[i]);

            // PK bounds: centered magnitude (qi-1)/2; matches pk_aggregation / C1 commitment
            pk_bounds.push(qi_bound.clone());

            // `r` is the quotient of the mod-q reduction in the identity the circuit checks:
            //   ct = pk * u + e + k0 * k1 + q * r   (mod X^N + 1, over the integers)
            // so bounding each term on the right and dividing by q bounds `r`:
            //   |pk * u| <= n * (q-1)/2 (negacyclic convolution of n terms, |u| <= u_bound),
            //   |ct| <= (q-1)/2, |k0 * k1| <= |k0| * k1_bound, |e| <= e_bound.
            // Both sides are symmetric, so one bound covers the two-sided range check.
            //
            // ct0 takes the *lifted* `e0_bound`, not its residue at q_i: the reduced identity reads
            // the lifted `e0` directly now that the CRT split and `e0is` are gone.
            let k1_max = if k1_up_bound > (BigInt::from(-1) * &k1_low_bound) {
                k1_up_bound.clone()
            } else {
                BigInt::from(-1) * &k1_low_bound
            };
            let ct0_r_bound: BigInt = (&k1_max * k0qi.abs()
                + (&n * u_bound + BigInt::from(2)) * &qi_bound
                + BigInt::from(e0_bound))
                / &qi_bigint;
            ct0_r_bounds.push(ct0_r_bound);

            // ct1 has no `k0 * k1` term, so only the product, ciphertext and `e1` contribute.
            let ct1_r_bound: BigInt =
                ((&n * u_bound + BigInt::from(2)) * &qi_bound + e1_bound) / &qi_bigint;
            ct1_r_bounds.push(ct1_r_bound);
        }

        Ok(Bounds {
            pk_bounds: pk_bounds
                .iter()
                .map(|b| BigUint::from(b.to_u128().unwrap()))
                .collect(),
            u_bound: BigUint::from(u_bound as u64),
            e0_bound: BigUint::from(e0_bound),
            e1_bound: BigUint::from(e1_bound),
            k1_low_bound: BigUint::from(k1_low_bound.to_u128().unwrap()),
            k1_up_bound: BigUint::from(k1_up_bound.to_u128().unwrap()),
            ct0_r_bounds: ct0_r_bounds
                .iter()
                .map(|b| BigUint::from(b.to_u128().unwrap()))
                .collect(),
            ct1_r_bounds: ct1_r_bounds
                .iter()
                .map(|b| BigUint::from(b.to_u128().unwrap()))
                .collect(),
        })
    }
}

impl Computation for Inputs {
    type Preset = BfvPreset;
    type Data = UserDataEncryptionCircuitData;
    type Error = CircuitsErrors;

    fn compute(preset: Self::Preset, data: &Self::Data) -> Result<Self, Self::Error> {
        let (threshold_params, _) =
            build_pair_for_preset(preset).map_err(|e| CircuitsErrors::Sample(e.to_string()))?;

        let pk = data.public_key.clone();
        let pt = data.plaintext.clone();

        // Context and plaintext modulus (use same ctx for e0 reconstruction and loop).
        let ctx = threshold_params.context_at_level(0)?;

        #[allow(non_snake_case)]
        let modulus_q = BigInt::from(ctx.modulus().clone());
        let moduli = threshold_params.moduli();

        let t = threshold_params.plaintext();
        let n = threshold_params.degree() as u64;
        let q_mod_t = (&modulus_q % t)
            .to_u64()
            .ok_or_else(|| CircuitsErrors::Other("Failed to convert q_mod_t to u64".into()))?; // [q]_t
        let cyclo = cyclotomic_polynomial(n);

        // Encrypt using the provided public key to ensure ciphertext matches the key.
        let (ct, u, e0, e1) = data
            .public_key
            .try_encrypt_extended(&data.plaintext, &mut rand::rng())?;

        // Reconstruct e0 coefficients mod Q (CRT) for e0_quotient computation.
        let mut e0_mod_q = Polynomial::from_fhe_polynomial(&e0);

        e0_mod_q.reverse();
        e0_mod_q.center(&modulus_q);

        // Reconstruct k1 from plaintext polynomial.
        let mut k1_u64 = plaintext_poly_u64(&pt)?; // m

        Modulus::new(t)
            .map_err(|e| CircuitsErrors::Fhe(fhe::Error::from(e)))?
            .scalar_mul_vec(&mut k1_u64, q_mod_t); // k1 = [q*m]_t

        let mut k1 = Polynomial::from_u64_vector(k1_u64);

        k1.reverse();
        k1.center(&BigInt::from(t));

        // Reconstruct u and e1 as polynomials (only the first limb is needed)
        let mut u = CrtPolynomial::from_fhe_polynomial(&u).limb(0).clone();
        let mut e1 = CrtPolynomial::from_fhe_polynomial(&e1).limb(0).clone();

        u.center(&BigInt::from(moduli[0]));
        u.reverse();

        e1.center(&BigInt::from(moduli[0]));
        e1.reverse();

        let mut ct0 = CrtPolynomial::from_fhe_polynomial(&ct[0]);
        let mut ct1 = CrtPolynomial::from_fhe_polynomial(&ct[1]);
        let mut pk0 = CrtPolynomial::from_fhe_polynomial(&pk.c[0]);
        let mut pk1 = CrtPolynomial::from_fhe_polynomial(&pk.c[1]);
        let mut e0 = CrtPolynomial::from_fhe_polynomial(&e0);

        ct0.reverse();
        ct1.reverse();
        pk0.reverse();
        pk1.reverse();
        e0.reverse();

        ct0.center(moduli)?;
        ct1.center(moduli)?;

        pk0.center(moduli)?;
        pk1.center(moduli)?;

        e0.center(moduli)?;

        let CrtPolynomial { limbs: ct0_limbs } = ct0;
        let CrtPolynomial { limbs: ct1_limbs } = ct1;
        let CrtPolynomial { limbs: pk0_limbs } = pk0;
        let CrtPolynomial { limbs: pk1_limbs } = pk1;
        let CrtPolynomial { limbs: e0_limbs } = e0;

        // Perform the main computation logic
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

            // Compute e0_quotients[i] = (e0 - e0i) / qi for each coefficient
            // This is used for CRT consistency check: e0[j] = e0i[j] + e0_quotients[i][j] * qi
            // Polynomial div by constant yields coefficient-wise division.
            let diff = e0_mod_q.sub(&e0i);
            let qi_poly = Polynomial::constant(qi_bigint.clone());
            let (e0_quotient, remainder) = diff.div(&qi_poly).expect("CRT requires exact division");

            assert!(
                remainder.is_zero(),
                "e0 - e0i must be divisible by qi (CRT consistency)"
            );

            // k0qi = -t^{-1} mod qi
            let k0qi = BigInt::from(qi.inv(qi.neg(t)).unwrap());

            // ki = k1 * k0qi
            let ki = k1.scalar_mul(&k0qi);

            // Calculate ct0i_hat = pk0 * ui + e0i + ki
            let ct0i_hat = {
                let pk0i_u_times = pk0i.mul(&u);
                let e0_plus_ki = e0i.add(&ki);

                assert_eq!((pk0i_u_times.coefficients().len() as u64) - 1, 2 * (n - 1));
                assert_eq!((e0_plus_ki.coefficients().len() as u64) - 1, n - 1);

                pk0i_u_times.add(&e0_plus_ki)
            };

            assert_eq!((ct0i_hat.coefficients().len() as u64) - 1, 2 * (n - 1));

            // `r2i`, the cyclotomic quotient, is discarded: folding modulo X^N + 1 makes its term zero.
            let (r1i, _r2i) = decompose_residue(&ct0i, &ct0i_hat, &qi_bigint, &cyclo, n);

            // Calculate ct1i_hat = pk1i * ui + e1
            let ct1i_hat = {
                let pk1i_u_times = pk1i.mul(&u);

                assert_eq!((pk1i_u_times.coefficients().len() as u64) - 1, 2 * (n - 1));

                pk1i_u_times.add(&e1)
            };
            assert_eq!((ct1i_hat.coefficients().len() as u64) - 1, 2 * (n - 1));

            let (p1i, _p2i) = decompose_residue(&ct1i, &ct1i_hat, &qi_bigint, &cyclo, n);

            // Reduce the mod-q quotients modulo X^N + 1 so the circuit can check one degree-N
            // identity instead of the unreduced one.
            //
            // Two witnesses disappear into `r`. Folding makes the cyclotomic quotient's term
            // identically zero, which removes `r2i` / `p2i`. Substituting the CRT split
            // `e0 = e0i + e0_quotient * qi` into the ct0 equation removes `e0is`, leaving
            // `qi * (r1i - e0_quotient)`. So `r` carries what `e0is`, `r1i` and `r2i` carried
            // between them, and the circuit bounds it in their place.
            let ct0_r = r1i
                .reduce_by_cyclotomic(&cyclo)
                .expect("r1i must reduce modulo the cyclotomic")
                .sub(&e0_quotient);
            let ct1_r = p1i
                .reduce_by_cyclotomic(&cyclo)
                .expect("p1i must reduce modulo the cyclotomic");

            // Prove the reduced identities on the real witness rather than trusting the derivation:
            // a wrong fold or coefficient order fails here instead of inside the circuit.
            let ct0_reduced = pk0i
                .mul(&u)
                .reduce_by_cyclotomic(&cyclo)
                .expect("pk0i * u must reduce modulo the cyclotomic")
                .add(&e0_mod_q)
                .add(&ki)
                .add(&ct0_r.scalar_mul(&qi_bigint));
            assert!(
                ct0i.sub(&ct0_reduced).is_zero(),
                "reduced ct0 identity must hold: ct0i == pk0i * u + e0 + k0qi * k1 + qi * r (mod X^N + 1)"
            );

            let ct1_reduced = pk1i
                .mul(&u)
                .reduce_by_cyclotomic(&cyclo)
                .expect("pk1i * u must reduce modulo the cyclotomic")
                .add(&e1)
                .add(&ct1_r.scalar_mul(&qi_bigint));
            assert!(
                ct1i.sub(&ct1_reduced).is_zero(),
                "reduced ct1 identity must hold: ct1i == pk1i * u + e1 + qi * r (mod X^N + 1)"
            );

            (i, k0qi, ct0i, ct1i, pk0i, pk1i, ct0_r, ct1_r)
        })
        .collect();

        results.sort_by_key(|(i, ..)| *i);

        let mut pk0is = Vec::with_capacity(results.len());
        let mut pk1is = Vec::with_capacity(results.len());
        let mut ct0is = Vec::with_capacity(results.len());
        let mut ct1is = Vec::with_capacity(results.len());
        let mut ct0_r = Vec::with_capacity(results.len());
        let mut ct1_r = Vec::with_capacity(results.len());

        for (_, _, ct0i, ct1i, pk0i, pk1i, ct0_ri, ct1_ri) in results {
            pk0is.push(pk0i);
            pk1is.push(pk1i);
            ct0is.push(ct0i);
            ct1is.push(ct1i);
            ct0_r.push(ct0_ri);
            ct1_r.push(ct1_ri);
        }

        let pk0is = CrtPolynomial::new(pk0is);
        let pk1is = CrtPolynomial::new(pk1is);
        let ct0is = CrtPolynomial::new(ct0is);
        let ct1is = CrtPolynomial::new(ct1is);
        let ct0_r = CrtPolynomial::new(ct0_r);
        let ct1_r = CrtPolynomial::new(ct1_r);

        // e0 is mod Q (huge); reduce to zkp_modulus so it fits in the proof system field.
        let zkp_modulus = get_zkp_modulus();
        e0_mod_q.reduce(&zkp_modulus);

        Ok(Inputs {
            pk0is,
            pk1is,
            ct0is,
            ct1is,
            ct0_r,
            ct1_r,
            e0: e0_mod_q,
            e1,
            u,
            k1,
            ciphertext: ct.to_bytes(),
        })
    }

    // Used as input for Nargo execution. Coefficients are JSON numbers when they fit in i64, else strings.
    fn to_json(&self) -> serde_json::Result<serde_json::Value> {
        use crate::crt_polynomial_to_toml_json;
        use crate::polynomial_to_toml_json;

        let pk0is = crt_polynomial_to_toml_json(&self.pk0is);
        let pk1is = crt_polynomial_to_toml_json(&self.pk1is);
        let ct0is = crt_polynomial_to_toml_json(&self.ct0is);
        let ct1is = crt_polynomial_to_toml_json(&self.ct1is);
        let u = polynomial_to_toml_json(&self.u);
        let e0 = polynomial_to_toml_json(&self.e0);
        let e1 = polynomial_to_toml_json(&self.e1);
        let k1 = polynomial_to_toml_json(&self.k1);
        // ct0 and ct1 share one Prover.toml, so each reduction quotient needs its own key. Both feed
        // a circuit field named `r`.
        let r = crt_polynomial_to_toml_json(&self.ct0_r);
        let r_ct1 = crt_polynomial_to_toml_json(&self.ct1_r);

        let json = serde_json::json!({
            "pk0is": pk0is,
            "pk1is": pk1is,
            "ct0is": ct0is,
            "ct1is": ct1is,
            "u": u,
            "e0": e0,
            "e1": e1,
            "k1": k1,
            "r": r,
            "r_ct1": r_ct1,
        });

        Ok(json)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use e3_fhe_params::BfvPreset;

    #[test]
    fn test_bound_and_bits_computation_consistency() {
        let bounds = Bounds::compute(BfvPreset::InsecureThreshold512, &()).unwrap();
        let bits = Bits::compute(BfvPreset::InsecureThreshold512, &bounds).unwrap();

        let max_pk_bound = bounds.pk_bounds.iter().max().unwrap();
        let expected_bits = calculate_bit_width(BigInt::from(max_pk_bound.clone()));

        assert_eq!(max_pk_bound.clone(), BigUint::from(34359701504u64));
        assert_eq!(bits.pk_bit, expected_bits);
    }
}
