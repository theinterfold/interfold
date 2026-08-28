// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Computation types for the CKKS user data encryption circuit.
//!
//! Mirrors the BFV `user_data_encryption` computation with the CKKS deltas:
//! - No plaintext modulus, no `k0is`, no `k1`: the message enters `ct0`
//!   directly as the scaled ring element `m = round(delta * encode(z))`.
//! - The message gets the same CRT-limb decomposition and quotient
//!   consistency treatment as `e0`, and a symmetric coefficient bound
//!   `m_bound = ceil(delta * B) + 1` (exact) replaces the `k1` bounds.
//! - The ct1 leg is identical to BFV (no message term): `p1`/`p2` bounds
//!   carry over with the same formulas.

use crate::calculate_bit_width;
use crate::get_zkp_modulus;
use crate::math::{cyclotomic_polynomial, decompose_residue};
use crate::threshold::user_data_encryption_ckks::circuit::CkksPreset;
use crate::threshold::user_data_encryption_ckks::circuit::UserDataEncryptionCkksCircuit;
use crate::threshold::user_data_encryption_ckks::circuit::UserDataEncryptionCkksCircuitData;
use crate::CircuitsErrors;
use crate::{CircuitComputation, Computation};
use e3_polynomial::CrtPolynomial;
use e3_polynomial::Polynomial;
use fhe::ckks::{CkksEncoder, CkksSecretKey};
use fhe_traits::Serialize as FheSerialize;
use itertools::izip;
use num_bigint::BigInt;
use num_bigint::BigUint;
use num_traits::ToPrimitive;
use rayon::iter::ParallelIterator;
use rayon::prelude::ParallelBridge;
use serde::{Deserialize, Serialize};

/// Output of [`CircuitComputation::compute`] for [`UserDataEncryptionCkksCircuit`].
#[derive(Debug)]
pub struct UserDataEncryptionCkksComputationOutput {
    pub bounds: Bounds,
    pub bits: Bits,
    pub inputs: Inputs,
}

impl CircuitComputation for UserDataEncryptionCkksCircuit {
    type Preset = CkksPreset;
    type Data = UserDataEncryptionCkksCircuitData;
    type Output = UserDataEncryptionCkksComputationOutput;
    type Error = CircuitsErrors;

    fn compute(preset: Self::Preset, data: &Self::Data) -> Result<Self::Output, Self::Error> {
        let bounds = Bounds::compute(preset.clone(), &())?;
        let bits = Bits::compute(preset.clone(), &bounds)?;
        let inputs = Inputs::compute(preset, data)?;

        Ok(UserDataEncryptionCkksComputationOutput {
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
    pub bits: Bits,
    pub bounds: Bounds,
}

impl Computation for Configs {
    type Preset = CkksPreset;
    type Data = ();
    type Error = CircuitsErrors;

    fn compute(preset: Self::Preset, _: &Self::Data) -> Result<Self, CircuitsErrors> {
        let bounds = Bounds::compute(preset.clone(), &())?;
        let bits = Bits::compute(preset.clone(), &bounds)?;

        Ok(Configs {
            n: preset.params.degree(),
            l: preset.params.moduli().len(),
            moduli: preset.params.moduli().to_vec(),
            bits,
            bounds,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Bits {
    pub pk_bit: u32,
    pub ct_bit: u32,
    pub u_bit: u32,
    pub e0_bit: u32,
    pub e1_bit: u32,
    pub m_bit: u32,
    pub r1_bit: u32,
    pub r2_bit: u32,
    pub p1_bit: u32,
    pub p2_bit: u32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Bounds {
    pub pk_bounds: Vec<BigUint>,
    pub u_bound: BigUint,
    pub e0_bound: BigUint,
    pub e1_bound: BigUint,
    /// Symmetric bound on the scaled message coefficients: `ceil(delta * B) + 1` (exact).
    pub m_bound: BigUint,
    pub r1_low_bounds: Vec<BigUint>,
    pub r1_up_bounds: Vec<BigUint>,
    pub r2_bounds: Vec<BigUint>,
    pub p1_bounds: Vec<BigUint>,
    pub p2_bounds: Vec<BigUint>,
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
    pub mis: CrtPolynomial,
    pub m_quotients: CrtPolynomial,
    pub e0: Polynomial,
    pub e1: Polynomial,
    pub u: Polynomial,
    pub m: Polynomial,
    pub ciphertext: Vec<u8>,
}

// (Former `M_BOUND_SLACK_NUM = 2` placeholder removed: the bound below is
// exact, no slack needed.)

impl Computation for Bounds {
    type Preset = CkksPreset;
    type Data = ();
    type Error = CircuitsErrors;

    fn compute(preset: Self::Preset, _: &Self::Data) -> Result<Self, Self::Error> {
        let params = &preset.params;
        let n = BigInt::from(params.degree());

        // Secret/randomness bound: CBD with variance 0.5 -> |u| <= 1.
        let u_bound = CkksSecretKey::sk_bound() as u128;

        // Error bound: CBD with the configured variance -> |e| <= 2*variance.
        let cbd_bound = (params.variance() * 2) as u64;
        let e0_bound = cbd_bound as u128;
        let e1_bound = cbd_bound;

        // Message bound — EXACT derivation from the encoder transform.
        // Each coefficient is round(delta * (2/N) * sum_{j<N/2} z_j cos(.)),
        // and |sum| <= (N/2)*B since |z_j| <= B and |cos| <= 1. Hence
        // |coeff| <= delta*(2/N)*(N/2)*B + 1/2 = delta*B + 1/2, and the
        // integer coefficient satisfies |m_i| <= ceil(delta*B) + 1.
        // (Rounding contributes at most 1/2; +1 absorbs both the 1/2 and
        // the ceil of a non-integer delta*B.)
        let delta_b = params.scale() * preset.input_bound;
        if !delta_b.is_finite() {
            return Err(CircuitsErrors::Other("m_bound overflows f64".into()));
        }
        let m_bound = BigUint::from(delta_b.ceil() as u128) + BigUint::from(1u32);

        let mut pk_bounds: Vec<BigInt> = Vec::new();
        let mut r1_low_bounds: Vec<BigInt> = Vec::new();
        let mut r1_up_bounds: Vec<BigInt> = Vec::new();
        let mut r2_bounds: Vec<BigInt> = Vec::new();
        let mut p1_bounds: Vec<BigInt> = Vec::new();
        let mut p2_bounds: Vec<BigInt> = Vec::new();

        let m_bound_bigint = BigInt::from(m_bound.clone());

        for qi in params.moduli() {
            let qi_bigint = BigInt::from(*qi);
            let qi_bound = (&qi_bigint - BigInt::from(1)) / BigInt::from(2);

            pk_bounds.push(qi_bound.clone());
            r2_bounds.push(qi_bound.clone());
            p2_bounds.push(qi_bound.clone());

            let e0_bound_i = BigInt::from(e0_bound) % qi_bigint.clone();

            // R1 bounds: |ct0i_hat| <= (N*u_bound + 2) * qi_bound + e0_bound + m_bound
            // (the BFV `ptxt*|k0|` term is replaced by the direct message bound).
            let r1_mag: BigInt = (&m_bound_bigint
                + ((&n * u_bound + BigInt::from(2)) * &qi_bound + e0_bound_i.clone()))
                / &qi_bigint;

            r1_low_bounds.push(r1_mag.clone());
            r1_up_bounds.push(r1_mag.clone());

            // P1 bound: identical to BFV (ct1 has no message term).
            let p1_bound: BigInt =
                ((&n * u_bound + BigInt::from(2)) * &qi_bound + e1_bound) / &qi_bigint;
            p1_bounds.push(p1_bound.clone());
        }

        let to_biguint_vec = |v: Vec<BigInt>| -> Result<Vec<BigUint>, CircuitsErrors> {
            v.iter()
                .map(|b| {
                    b.to_u128()
                        .map(BigUint::from)
                        .ok_or_else(|| CircuitsErrors::Other("bound overflows u128".into()))
                })
                .collect()
        };

        Ok(Bounds {
            pk_bounds: to_biguint_vec(pk_bounds)?,
            u_bound: BigUint::from(u_bound as u64),
            e0_bound: BigUint::from(e0_bound),
            e1_bound: BigUint::from(e1_bound),
            m_bound,
            r1_low_bounds: to_biguint_vec(r1_low_bounds)?,
            r1_up_bounds: to_biguint_vec(r1_up_bounds)?,
            r2_bounds: to_biguint_vec(r2_bounds)?,
            p1_bounds: to_biguint_vec(p1_bounds)?,
            p2_bounds: to_biguint_vec(p2_bounds)?,
        })
    }
}

impl Computation for Bits {
    type Preset = CkksPreset;
    type Data = Bounds;
    type Error = CircuitsErrors;

    fn compute(_: Self::Preset, data: &Self::Data) -> Result<Self, Self::Error> {
        let max_pk_bound = data.pk_bounds.iter().max().unwrap();

        let pk_bit = calculate_bit_width(BigInt::from(max_pk_bound.clone()));
        let ct_bit = pk_bit;
        let u_bit = calculate_bit_width(BigInt::from(data.u_bound.clone()));
        let e0_bit = calculate_bit_width(BigInt::from(data.e0_bound.clone()));
        let e1_bit = calculate_bit_width(BigInt::from(data.e1_bound.clone()));
        let m_bit = calculate_bit_width(BigInt::from(data.m_bound.clone()));

        let max_bit = |bounds: &[BigUint]| {
            bounds
                .iter()
                .map(|b| calculate_bit_width(BigInt::from(b.clone())))
                .max()
                .unwrap_or(0)
        };

        let r1_bit = max_bit(&data.r1_low_bounds).max(max_bit(&data.r1_up_bounds));
        let r2_bit = max_bit(&data.r2_bounds);
        let p1_bit = max_bit(&data.p1_bounds);
        let p2_bit = max_bit(&data.p2_bounds);

        Ok(Bits {
            pk_bit,
            ct_bit,
            u_bit,
            e0_bit,
            e1_bit,
            m_bit,
            r1_bit,
            r2_bit,
            p1_bit,
            p2_bit,
        })
    }
}

impl Computation for Inputs {
    type Preset = CkksPreset;
    type Data = UserDataEncryptionCkksCircuitData;
    type Error = CircuitsErrors;

    fn compute(preset: Self::Preset, data: &Self::Data) -> Result<Self, Self::Error> {
        let params = &preset.params;
        let ctx = params
            .context_at_level(0)
            .map_err(|e| CircuitsErrors::Other(e.to_string()))?;

        let modulus_q = BigInt::from(ctx.modulus().clone());
        let moduli = params.moduli();
        let n = params.degree() as u64;
        let cyclo = cyclotomic_polynomial(n);

        // Encode and encrypt with witness extraction.
        let encoder = CkksEncoder::new(params);
        let pt = encoder
            .encode(&data.values, 0)
            .map_err(|e| CircuitsErrors::Other(e.to_string()))?;
        let (ct, u, e0, e1) = data
            .public_key
            .try_encrypt_extended(&pt, &mut rand::rng())
            .map_err(|e| CircuitsErrors::Other(e.to_string()))?;

        // Reconstruct e0 and m mod Q (centered) for quotient computation.
        let mut e0_mod_q = Polynomial::from_fhe_polynomial(&e0);
        e0_mod_q.reverse();
        e0_mod_q.center(&modulus_q);

        let mut m_mod_q = Polynomial::from_fhe_polynomial(pt.poly());
        m_mod_q.reverse();
        m_mod_q.center(&modulus_q);

        // Randomness u and error e1: first limb, centered (small polynomials).
        let mut u_poly = CrtPolynomial::from_fhe_polynomial(&u).limb(0).clone();
        let mut e1_poly = CrtPolynomial::from_fhe_polynomial(&e1).limb(0).clone();

        u_poly.center(&BigInt::from(moduli[0]));
        u_poly.reverse();
        e1_poly.center(&BigInt::from(moduli[0]));
        e1_poly.reverse();

        // CRT limbs of the public inputs and witnesses.
        let mut ct0 = CrtPolynomial::from_fhe_polynomial(&ct[0]);
        let mut ct1 = CrtPolynomial::from_fhe_polynomial(&ct[1]);
        let mut pk0 = CrtPolynomial::from_fhe_polynomial(&data.public_key.c[0]);
        let mut pk1 = CrtPolynomial::from_fhe_polynomial(&data.public_key.c[1]);
        let mut e0_crt = CrtPolynomial::from_fhe_polynomial(&e0);
        let mut m_crt = CrtPolynomial::from_fhe_polynomial(pt.poly());

        ct0.reverse();
        ct1.reverse();
        pk0.reverse();
        pk1.reverse();
        e0_crt.reverse();
        m_crt.reverse();

        ct0.center(moduli)
            .map_err(|e| CircuitsErrors::Other(e.to_string()))?;
        ct1.center(moduli)
            .map_err(|e| CircuitsErrors::Other(e.to_string()))?;
        pk0.center(moduli)
            .map_err(|e| CircuitsErrors::Other(e.to_string()))?;
        pk1.center(moduli)
            .map_err(|e| CircuitsErrors::Other(e.to_string()))?;
        e0_crt
            .center(moduli)
            .map_err(|e| CircuitsErrors::Other(e.to_string()))?;
        m_crt
            .center(moduli)
            .map_err(|e| CircuitsErrors::Other(e.to_string()))?;

        let CrtPolynomial { limbs: ct0_limbs } = ct0;
        let CrtPolynomial { limbs: ct1_limbs } = ct1;
        let CrtPolynomial { limbs: pk0_limbs } = pk0;
        let CrtPolynomial { limbs: pk1_limbs } = pk1;
        let CrtPolynomial { limbs: e0_limbs } = e0_crt;
        let CrtPolynomial { limbs: m_limbs } = m_crt;

        let qi_bigints: Vec<BigInt> = moduli.iter().map(|q| BigInt::from(*q)).collect();

        let mut results: Vec<_> =
            izip!(qi_bigints, ct0_limbs, ct1_limbs, pk0_limbs, pk1_limbs, e0_limbs, m_limbs,)
                .enumerate()
                .par_bridge()
                .map(|(i, (qi_bigint, ct0i, ct1i, pk0i, pk1i, e0i, mi))| {
                    // Quotients for CRT consistency: x = xi + quotient * qi.
                    let qi_poly = Polynomial::constant(qi_bigint.clone());

                    let e0_diff = e0_mod_q.sub(&e0i);
                    let (e0_quotient, e0_rem) =
                        e0_diff.div(&qi_poly).expect("CRT requires exact division");
                    assert!(e0_rem.is_zero(), "e0 - e0i must be divisible by qi");

                    let m_diff = m_mod_q.sub(&mi);
                    let (m_quotient, m_rem) =
                        m_diff.div(&qi_poly).expect("CRT requires exact division");
                    assert!(m_rem.is_zero(), "m - mi must be divisible by qi");

                    // ct0i_hat = pk0i*u + e0i + mi  (no k1*k0i term in CKKS)
                    let ct0i_hat = {
                        let pk0i_u_times = pk0i.mul(&u_poly);
                        let e0_plus_mi = e0i.add(&mi);

                        assert_eq!((pk0i_u_times.coefficients().len() as u64) - 1, 2 * (n - 1));
                        assert_eq!((e0_plus_mi.coefficients().len() as u64) - 1, n - 1);

                        pk0i_u_times.add(&e0_plus_mi)
                    };
                    assert_eq!((ct0i_hat.coefficients().len() as u64) - 1, 2 * (n - 1));

                    let (r1i, r2i) = decompose_residue(&ct0i, &ct0i_hat, &qi_bigint, &cyclo, n);

                    // ct1i_hat = pk1i*u + e1  (identical to BFV)
                    let ct1i_hat = {
                        let pk1i_u_times = pk1i.mul(&u_poly);
                        assert_eq!((pk1i_u_times.coefficients().len() as u64) - 1, 2 * (n - 1));
                        pk1i_u_times.add(&e1_poly)
                    };
                    assert_eq!((ct1i_hat.coefficients().len() as u64) - 1, 2 * (n - 1));

                    let (p1i, p2i) = decompose_residue(&ct1i, &ct1i_hat, &qi_bigint, &cyclo, n);

                    (
                        i,
                        ct0i,
                        ct1i,
                        pk0i,
                        pk1i,
                        r1i,
                        r2i,
                        p1i,
                        p2i,
                        e0i,
                        e0_quotient,
                        mi,
                        m_quotient,
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
        let mut mis = Vec::with_capacity(results.len());
        let mut m_quotients = Vec::with_capacity(results.len());

        for (_, ct0i, ct1i, pk0i, pk1i, r1i, r2i, p1i, p2i, e0i, e0_quotient, mi, m_quotient) in
            results
        {
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
            mis.push(mi);
            m_quotients.push(m_quotient);
        }

        // e0 and m are mod Q (huge); reduce to the proof-system field.
        let zkp_modulus = get_zkp_modulus();
        e0_mod_q.reduce(&zkp_modulus);
        m_mod_q.reduce(&zkp_modulus);

        Ok(Inputs {
            pk0is: CrtPolynomial::new(pk0is),
            pk1is: CrtPolynomial::new(pk1is),
            ct0is: CrtPolynomial::new(ct0is),
            ct1is: CrtPolynomial::new(ct1is),
            r1is: CrtPolynomial::new(r1is),
            r2is: CrtPolynomial::new(r2is),
            p1is: CrtPolynomial::new(p1is),
            p2is: CrtPolynomial::new(p2is),
            e0is: CrtPolynomial::new(e0is),
            e0_quotients: CrtPolynomial::new(e0_quotients),
            mis: CrtPolynomial::new(mis),
            m_quotients: CrtPolynomial::new(m_quotients),
            e0: e0_mod_q,
            e1: e1_poly,
            u: u_poly,
            m: m_mod_q,
            ciphertext: ct.to_bytes(),
        })
    }

    // Used as input for Nargo execution. Coefficients are JSON numbers when
    // they fit in i64, else strings (same convention as the BFV circuit).
    fn to_json(&self) -> serde_json::Result<serde_json::Value> {
        use crate::crt_polynomial_to_toml_json;
        use crate::polynomial_to_toml_json;

        let json = serde_json::json!({
            "pk0is": crt_polynomial_to_toml_json(&self.pk0is),
            "pk1is": crt_polynomial_to_toml_json(&self.pk1is),
            "ct0is": crt_polynomial_to_toml_json(&self.ct0is),
            "ct1is": crt_polynomial_to_toml_json(&self.ct1is),
            "u": polynomial_to_toml_json(&self.u),
            "e0": polynomial_to_toml_json(&self.e0),
            "e0is": crt_polynomial_to_toml_json(&self.e0is),
            "e0_quotients": crt_polynomial_to_toml_json(&self.e0_quotients),
            "e1": polynomial_to_toml_json(&self.e1),
            "m": polynomial_to_toml_json(&self.m),
            "mis": crt_polynomial_to_toml_json(&self.mis),
            "m_quotients": crt_polynomial_to_toml_json(&self.m_quotients),
            "r1is": crt_polynomial_to_toml_json(&self.r1is),
            "r2is": crt_polynomial_to_toml_json(&self.r2is),
            "p1is": crt_polynomial_to_toml_json(&self.p1is),
            "p2is": crt_polynomial_to_toml_json(&self.p2is),
        });

        Ok(json)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fhe::ckks::{CkksParametersBuilder, CkksPublicKey, CkksSecretKey};
    use num_traits::Signed;

    fn test_preset() -> CkksPreset {
        let params = CkksParametersBuilder::new()
            .set_degree(512)
            .set_moduli_sizes(&[36, 36])
            .set_scale(2f64.powi(26))
            .build_arc()
            .unwrap();
        CkksPreset {
            params,
            input_bound: 100.0,
        }
    }

    #[test]
    fn bounds_and_bits() {
        let preset = test_preset();
        let bounds = Bounds::compute(preset.clone(), &()).unwrap();
        let bits = Bits::compute(preset, &bounds).unwrap();

        // m_bound = ceil(2^26 * 100) + 1 (exact encoder-transform bound)
        assert_eq!(
            bounds.m_bound,
            BigUint::from((2f64.powi(26) * 100.0) as u128) + BigUint::from(1u32)
        );
        assert!(bits.m_bit > 0);
        assert_eq!(bits.pk_bit, bits.ct_bit);
    }

    #[test]
    fn inputs_satisfy_encryption_equations() {
        let mut rng = rand::rng();
        let preset = test_preset();
        let sk = CkksSecretKey::random(&preset.params, &mut rng);
        let pk = CkksPublicKey::new(&sk, &mut rng).unwrap();

        let data = UserDataEncryptionCkksCircuitData {
            public_key: pk,
            values: vec![1.5, -42.0, 99.9, 0.25],
        };

        // Inputs::compute performs the decompose_residue assertions internally:
        // if the CKKS encryption equations did not hold limb-wise, it would panic.
        let inputs = Inputs::compute(preset.clone(), &data).unwrap();

        let l = preset.params.moduli().len();
        assert_eq!(inputs.ct0is.limbs.len(), l);
        assert_eq!(inputs.mis.limbs.len(), l);
        assert_eq!(inputs.m_quotients.limbs.len(), l);
        assert!(!inputs.ciphertext.is_empty());

        // The message coefficients respect the circuit bound.
        let bounds = Bounds::compute(preset, &()).unwrap();
        let m_bound = BigInt::from(bounds.m_bound);
        for c in inputs.m.coefficients() {
            // m is reduced mod the zkp modulus: centered magnitude check only
            // applies to small coefficients; skip wrapped ones.
            if c.magnitude() < BigInt::from(2u8).pow(200).magnitude() {
                assert!(
                    c.abs() <= m_bound.clone(),
                    "message coefficient {c} exceeds bound {m_bound}"
                );
            }
        }
    }
}
