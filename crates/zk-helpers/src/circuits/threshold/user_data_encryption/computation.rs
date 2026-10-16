// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Computation types for the user data encryption circuit: constants, bounds, bit widths, and inputs.
//!
//! [`Configs`], [`Bounds`], [`Bits`], and [`Inputs`] are produced from BFV parameters
//! and (for input) a public key. They implement [`Computation`] and are used by codegen.

use crate::encoding::get_zkp_modulus;
use crate::negacyclic::negacyclic_mul_exact;
use crate::threshold::pk_generation::utils::deterministic_crp_crt_polynomial;

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
    pub r1_bit: u32,
    pub r2_bit: u32,
    pub p1_bit: u32,
    pub p2_bit: u32,
    /// Bit width for `e0_quotients` - the CRT quotient in `e0 == e0is[i] + e0_quotients[i] * qis[i]`.
    /// This MUST be range-checked: the equation holds in F_p, not Z, so an unconstrained
    /// quotient lets a prover pick any e0is (see the soundness note on `e0_quotient_bounds`).
    pub e0_quotient_bit: u32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Bounds {
    pub pk_bounds: Vec<BigUint>,
    pub u_bound: BigUint,
    pub e0_bound: BigUint,
    pub e1_bound: BigUint,
    pub k1_low_bound: BigUint,
    pub k1_up_bound: BigUint,
    pub r1_low_bounds: Vec<BigUint>,
    pub r1_up_bounds: Vec<BigUint>,
    pub r2_bounds: Vec<BigUint>,
    pub p1_bounds: Vec<BigUint>,
    pub p2_bounds: Vec<BigUint>,
    /// Per-limb bound on the honest `e0_quotients[i]` magnitude: `(e0_bound + qi_bound) / qi + 1`.
    /// Not a security parameter itself - it exists only to stop the CRT-consistency equation
    /// from being satisfiable in F_p for an arbitrary e0is. See the `check_e0_crt_consistency`
    /// callers: they must range-check `e0_quotients` to this bound, or the check is vacuous.
    pub e0_quotient_bounds: Vec<BigUint>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Inputs {
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

        // For r1, use the maximum of all low and up bounds
        let mut r1_bit = 0;
        for bound in data.r1_low_bounds.iter().chain(data.r1_up_bounds.iter()) {
            r1_bit = r1_bit.max(calculate_bit_width(BigInt::from(bound.clone())));
        }

        // For r2, use the maximum of all bounds
        let mut r2_bit = 0;
        for bound in &data.r2_bounds {
            r2_bit = r2_bit.max(calculate_bit_width(BigInt::from(bound.clone())));
        }

        // For p1, use the maximum of all bounds
        let mut p1_bit = 0;
        for bound in &data.p1_bounds {
            p1_bit = p1_bit.max(calculate_bit_width(BigInt::from(bound.clone())));
        }

        // For p2, use the maximum of all bounds
        let mut p2_bit = 0;
        for bound in &data.p2_bounds {
            p2_bit = p2_bit.max(calculate_bit_width(BigInt::from(bound.clone())));
        }

        // For e0_quotient, use the maximum of all per-limb bounds
        let mut e0_quotient_bit = 0;
        for bound in &data.e0_quotient_bounds {
            e0_quotient_bit = e0_quotient_bit.max(calculate_bit_width(BigInt::from(bound.clone())));
        }

        Ok(Bits {
            pk_bit,
            ct_bit,
            u_bit,
            e0_bit,
            e1_bit,
            k_bit,
            r1_bit,
            r2_bit,
            p1_bit,
            p2_bit,
            e0_quotient_bit,
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

        let error_bound = crate::utils::error_sampler_bound(threshold_params.get_error1_variance())
            .to_bigint()
            .ok_or_else(|| {
                CircuitsErrors::Other("Failed to convert error bound to BigInt".into())
            })?;

        let u_bound = SecretKey::sk_bound() as u128; // u_bound is the same as sk_bound

        // e0 = e1 in fhe.rs; e1 = e2 in fhe.rs.
        let e0_bound = error_bound.to_u128().unwrap();
        let e1_bound = (threshold_params.variance() * 2) as u64;

        // Plaintext coefficients are encoded in [0, t), not centered around zero.
        let ptxt_low_bound = BigInt::from(0);
        let ptxt_up_bound = t.clone() - BigInt::from(1);

        let k1_low_bound: BigInt = BigInt::from(-1) * ptxt_low_bound.clone();
        let k1_up_bound: BigInt = ptxt_up_bound.clone();

        // Calculate bounds for each CRT basis
        let moduli: Vec<u64> = ctx.moduli_operators().iter().map(|q| **q).collect();
        let k0is = compute_k0is(&moduli, threshold_params.plaintext())?;

        let mut pk_bounds: Vec<BigInt> = Vec::new();
        let mut r1_low_bounds: Vec<BigInt> = Vec::new();
        let mut r1_up_bounds: Vec<BigInt> = Vec::new();
        let mut r2_bounds: Vec<BigInt> = Vec::new();
        let mut p1_bounds: Vec<BigInt> = Vec::new();
        let mut p2_bounds: Vec<BigInt> = Vec::new();
        let mut e0_quotient_bounds: Vec<BigInt> = Vec::new();

        let e0_bound_bigint = BigInt::from(e0_bound);

        for (i, qi) in ctx.moduli_operators().iter().enumerate() {
            let qi_bigint = BigInt::from(**qi);
            let qi_bound = (&qi_bigint - BigInt::from(1)) / BigInt::from(2);

            let k0qi = BigInt::from(k0is[i]);

            // PK bounds: centered magnitude (qi-1)/2; matches pk_aggregation / C1 commitment
            pk_bounds.push(qi_bound.clone());
            r2_bounds.push(qi_bound.clone());

            let e0_bound_i = e0_bound % qi_bigint.clone();

            // R1 bounds (more complex calculation)
            let r1_residual_bound =
                (&n * u_bound + BigInt::from(2)) * &qi_bound + e0_bound_i.clone();
            let r1_low_numerator = &ptxt_up_bound * k0qi.abs() + &r1_residual_bound;
            let r1_low_magnitude = (&r1_low_numerator + &qi_bigint - BigInt::from(1)) / &qi_bigint;
            let r1_up = (&r1_residual_bound + &qi_bigint - BigInt::from(1)) / &qi_bigint;

            r1_low_bounds.push(r1_low_magnitude);
            r1_up_bounds.push(r1_up);

            // P1 and P2 bounds
            let p1_bound: BigInt =
                ((&n * u_bound + BigInt::from(2)) * &qi_bound + e1_bound) / &qi_bigint;
            p1_bounds.push(p1_bound.clone());
            p2_bounds.push(qi_bound.clone());

            // e0_quotients[i] = (e0 - e0is[i]) / qi. With e0 in [-e0_bound, e0_bound] and e0is[i]
            // centered in [-qi_bound, qi_bound], the honest quotient magnitude is bounded by
            // (e0_bound + qi_bound) / qi; +1 covers integer-division truncation. This bound MUST
            // be enforced with a range check on e0_quotients, or check_e0_crt_consistency's
            // equation (checked in F_p, not Z) is satisfiable for an arbitrary e0is.
            let e0_quotient_bound: BigInt =
                (&e0_bound_bigint + &qi_bound) / &qi_bigint + BigInt::from(1);
            e0_quotient_bounds.push(e0_quotient_bound);
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
            e0_quotient_bounds: e0_quotient_bounds
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

        ct0.reverse();
        ct1.reverse();
        pk0.reverse();
        pk1.reverse();

        ct0.center(moduli)?;
        ct1.center(moduli)?;

        pk0.center(moduli)?;
        pk1.center(moduli)?;

        // ct1 hard-codes the protocol CRS as `pk1`, as C5 does, so only keys built on it can be
        // proven. Committee keys always are; reject anything else here rather than in the prover.
        if pk1 != deterministic_crp_crt_polynomial(&threshold_params)? {
            return Err(CircuitsErrors::Other(
                "user-data encryption proofs need a public key whose second component is the \
                 protocol CRS (committee keys, or keys built with the default-seed CRP)"
                    .into(),
            ));
        }

        crate::utils::verify_crt_shapes(&[&ct0, &ct1, &pk0, &pk1, &e0], moduli.len(), n as usize)
            .map_err(|e| {
            CircuitsErrors::Other(format!("user-data-encryption CRT shape mismatch: {e}"))
        })?;

        let CrtPolynomial { limbs: ct0_limbs } = ct0;
        let CrtPolynomial { limbs: ct1_limbs } = ct1;
        let CrtPolynomial { limbs: pk0_limbs } = pk0;
        let CrtPolynomial { limbs: pk1_limbs } = pk1;

        // Perform the main computation logic
        let mut results: Vec<_> = izip!(
            ctx.moduli_operators(),
            ct0_limbs,
            ct1_limbs,
            pk0_limbs,
            pk1_limbs,
        )
        .enumerate()
        .par_bridge()
        .map(|(i, (qi, ct0i, ct1i, pk0i, pk1i))| {
            let qi_bigint = BigInt::from(**qi);

            // k0qi = -t^{-1} mod qi
            let k0qi = BigInt::from(qi.inv(qi.neg(t)).unwrap());

            // ki = k1 * k0qi
            let ki = k1.scalar_mul(&k0qi);

            // The circuit checks one degree-N identity per leg, reduced modulo X^N + 1, over the
            // integers and with the lifted `e0`:
            //   ct0i = (pk0i * u mod X^N + 1) + e0 + k0qi * k1 + qi * ct0_r
            //   ct1i = (pk1i * u mod X^N + 1) + e1            + qi * ct1_r
            // so each quotient is the leg's residual divided by qi. The reduced products are exact
            // integer products, taken by NTT in O(N log N).
            let pk0_u = negacyclic_mul_exact(&pk0i, &u, n as usize);
            let pk1_u = negacyclic_mul_exact(&pk1i, &u, n as usize);

            // Exact division rejects any coefficient that is not a multiple of qi, so a successful
            // division proves an integer quotient closes the reduced equation, and a wrong product
            // surfaces as a divisibility failure.
            let ct0_r = ct0i
                .sub(&pk0_u)
                .sub(&e0_mod_q)
                .sub(&ki)
                .div_exact(&qi_bigint)
                .expect("ct0i - (pk0i * u + e0 + k0qi * k1 mod X^N + 1) must be divisible by qi");

            let ct1_r = ct1i
                .sub(&pk1_u)
                .sub(&e1)
                .div_exact(&qi_bigint)
                .expect("ct1i - (pk1i * u + e1 mod X^N + 1) must be divisible by qi");

            (i, k0qi, ct0i, ct1i, pk0i, pk1i, ct0_r, ct1_r)
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

        for (_, r2i, r1i, _, ct0i, ct1i, pk0i, pk1i, p1i, p2i, e0i, e0_quotient) in results {
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

        // e0 is mod Q (huge); reduce to zkp_modulus so it fits in the proof system field.
        let zkp_modulus = get_zkp_modulus();
        e0_mod_q.reduce(&zkp_modulus);

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
            k1,
            ciphertext: ct.to_bytes(),
        })
    }

    // Used as input for Nargo execution. Coefficients are JSON numbers when they fit in i64, else strings.
    // `pk1is` is not an input: ct1 hard-codes the CRS it must equal.
    fn to_json(&self) -> serde_json::Result<serde_json::Value> {
        use crate::crt_polynomial_to_toml_json;
        use crate::polynomial_to_toml_json;

        let pk0is = crt_polynomial_to_toml_json(&self.pk0is);
        let ct0is = crt_polynomial_to_toml_json(&self.ct0is);
        let ct1is = crt_polynomial_to_toml_json(&self.ct1is);
        let u = polynomial_to_toml_json(&self.u);
        let e0 = polynomial_to_toml_json(&self.e0);
        let e0is = crt_polynomial_to_toml_json(&self.e0is);
        let e0_quotients = crt_polynomial_to_toml_json(&self.e0_quotients);
        let e1 = polynomial_to_toml_json(&self.e1);
        let k1 = polynomial_to_toml_json(&self.k1);
        let r1is = crt_polynomial_to_toml_json(&self.r1is);
        let r2is = crt_polynomial_to_toml_json(&self.r2is);
        let p1is = crt_polynomial_to_toml_json(&self.p1is);
        let p2is = crt_polynomial_to_toml_json(&self.p2is);

        let json = serde_json::json!({
            "pk0is": pk0is,
            "ct0is": ct0is,
            "ct1is": ct1is,
            "u": u,
            "e0": e0,
            "e0is": e0is,
            "e0_quotients": e0_quotients,
            "e1": e1,
            "k1": k1,
            "r1is": r1is,
            "r2is": r2is,
            "p1is": p1is,
            "p2is": p2is,
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
        let bounds = Bounds::compute(BfvPreset::InsecureThreshold, &()).unwrap();
        let bits = Bits::compute(BfvPreset::InsecureThreshold, &bounds).unwrap();

        let max_pk_bound = bounds.pk_bounds.iter().max().unwrap();
        let expected_bits = calculate_bit_width(BigInt::from(max_pk_bound.clone()));

        assert_eq!(max_pk_bound.clone(), BigUint::from(36028797018956544u64));
        assert_eq!(bits.pk_bit, expected_bits);
    }

    /// The insecure set's error1 variance (50471587840) is above 16, so e0 takes the uniform
    /// sampler's bound `sqrt(3 * variance)`.
    #[test]
    fn insecure_e0_bound_matches_error1_sampler() {
        let preset = BfvPreset::InsecureThreshold;
        let bounds = Bounds::compute(preset, &()).unwrap();
        let bits = Bits::compute(preset, &bounds).unwrap();

        assert_eq!(bounds.e0_bound, BigUint::from(389120u32));
        assert_eq!(bounds.e1_bound, BigUint::from(20u32));
        assert_eq!(bits.e0_bit, 19);
    }

    /// ct1 hard-codes the CRS, so a key with a random `a` cannot be proven; say so up front.
    #[test]
    fn keys_off_the_protocol_crs_are_rejected() {
        use fhe_traits::FheEncoder;

        let preset = BfvPreset::InsecureThreshold;
        let (threshold_params, _) = build_pair_for_preset(preset).unwrap();
        let mut rng = rand::rng();
        let secret_key = SecretKey::random(&threshold_params, &mut rng);
        let sample = UserDataEncryptionCircuitData {
            public_key: fhe::bfv::PublicKey::new(&secret_key, &mut rng),
            plaintext: fhe::bfv::Plaintext::try_encode(
                &[1u64],
                Encoding::poly(),
                &threshold_params,
            )
            .unwrap(),
        };

        let error = Inputs::compute(preset, &sample).unwrap_err();
        assert!(error.to_string().contains("protocol CRS"), "{error}");
    }

    #[test]
    fn encryption_witness_respects_ct0_r_bounds() {
        for preset in [BfvPreset::InsecureThreshold, BfvPreset::SecureThreshold8192] {
            let sample = UserDataEncryptionCircuitData::generate_sample(preset).unwrap();
            let bounds = Bounds::compute(preset, &()).unwrap();
            let inputs = Inputs::compute(preset, &sample).unwrap();
            for (i, limb) in inputs.ct0_r.limbs.iter().enumerate() {
                let bound = BigInt::from(bounds.ct0_r_bounds[i].clone());
                for (j, coefficient) in limb.coefficients().iter().enumerate() {
                    assert!(
                        coefficient.abs() <= bound,
                        "{preset:?} ct0_r[{i}][{j}] = {coefficient} exceeds {bound}"
                    );
                }
            }
        }
    }

    #[test]
    fn test_constants_json_roundtrip() {
        let constants = Configs::compute(BfvPreset::InsecureThreshold, &()).unwrap();

        let json = constants.to_json().unwrap();
        let decoded: Configs = serde_json::from_value(json).unwrap();

        assert_eq!(decoded.n, constants.n);
        assert_eq!(decoded.l, constants.l);
        assert_eq!(decoded.moduli, constants.moduli);
        assert_eq!(decoded.bits, constants.bits);
        assert_eq!(decoded.bounds, constants.bounds);
    }
}
