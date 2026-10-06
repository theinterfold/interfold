// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Computation types for the threshold share decryption circuit: constants, bounds, bit widths, and inputs.
//!
//! [`Configs`], [`Bounds`], [`Bits`], and [`Inputs`] are produced from BFV parameters
//! and (for input) ciphertext plus aggregated shares (s, e, d_share). They implement
//! [`Computation`] and are used by codegen.

use crate::calculate_bit_width;
use crate::circuits::commitments::{
    compute_aggregated_shares_commitment, compute_ciphertext_commitment,
};
use crate::circuits::threshold::decrypted_shares_aggregation::MAX_MSG_NON_ZERO_COEFFS;
use crate::compute_modulus_bit;
use crate::compute_native_crt_coeff_bit;
use crate::crt_polynomial_to_toml_json;
use crate::math::fold_negacyclic;
use crate::threshold::share_decryption::circuit::ShareDecryptionCircuit;
use crate::threshold::share_decryption::circuit::ShareDecryptionCircuitData;
use crate::CircuitsErrors;
use crate::{CircuitComputation, Computation};
use e3_fhe_params::build_pair_for_preset;
use e3_fhe_params::BfvPreset;
use e3_polynomial::CrtPolynomial;
use e3_polynomial::Polynomial;
use itertools::izip;
use num_bigint::BigInt;
use num_bigint::BigUint;
use num_traits::{ToPrimitive, Zero};
use rayon::iter::ParallelBridge;
use rayon::iter::ParallelIterator;
use serde::{Deserialize, Serialize};

/// Low-degree native \([0, q)\) CRT limbs for `d_commitment`, matching C7's `from_fhe` truncation.
/// In each limb, `d` is reversed+centered (witness layout); native coeff `j` is `uncenter(d[N-1-j])`.
fn d_native_trunc_from_centered_d(
    d: &CrtPolynomial,
    moduli: &[u64],
    degree: usize,
    max_k: usize,
) -> CrtPolynomial {
    let mut limbs = Vec::with_capacity(d.limbs.len());
    for (limb_idx, limb) in d.limbs.iter().enumerate() {
        let q = BigInt::from(moduli[limb_idx]);
        let coeffs = limb.coefficients();
        let mut asc = Vec::with_capacity(max_k);
        for j in 0..max_k {
            let w = &coeffs[degree - 1 - j];
            let u = if w < &BigInt::zero() {
                w + &q
            } else {
                w.clone()
            };
            asc.push(u);
        }
        limbs.push(Polynomial::new(asc));
    }
    CrtPolynomial::new(limbs)
}

/// Output of [`CircuitComputation::compute`] for [`ShareDecryptionCircuit`]: bounds, bit widths, and inputs.
#[derive(Debug)]
pub struct ShareDecryptionComputationOutput {
    pub bounds: Bounds,
    pub bits: Bits,
    pub inputs: Inputs,
}

/// Implementation of [`CircuitComputation`] for [`ShareDecryptionCircuit`].
impl CircuitComputation for ShareDecryptionCircuit {
    type Preset = BfvPreset;
    type Data = ShareDecryptionCircuitData;
    type Output = ShareDecryptionComputationOutput;
    type Error = CircuitsErrors;

    fn compute(preset: Self::Preset, data: &Self::Data) -> Result<Self::Output, Self::Error> {
        let bounds = Bounds::compute(preset, &())?;
        let bits = Bits::compute(preset, &bounds)?;
        let inputs = Inputs::compute(preset, data)?;

        Ok(ShareDecryptionComputationOutput {
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

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Bits {
    pub ct_bit: u32,
    pub sk_bit: u32,
    pub e_sm_bit: u32,
    pub r_bit: u32,
    /// Centered `d` coefficient bound (payload flatten / Fiat–Shamir).
    pub d_bit: u32,
    /// Native \([0, q)\) limb width for `d_native_trunc` / C7 share commitments.
    pub d_native_bit: u32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Bounds {
    pub r_bounds: Vec<BigUint>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Inputs {
    pub ct0: CrtPolynomial,
    pub ct1: CrtPolynomial,
    pub sk: CrtPolynomial,
    pub e_sm: CrtPolynomial,
    pub r: CrtPolynomial,
    pub d: CrtPolynomial,
    /// Native truncated `d` per limb (C7-compatible); hashed for public `d_commitment`.
    pub d_native_trunc: CrtPolynomial,
    pub expected_sk_commitment: BigInt,
    pub expected_e_sm_commitment: BigInt,
    pub ct_commitment: BigInt,
    pub domain_hi: BigInt,
    pub domain_lo: BigInt,
}

impl Computation for Configs {
    type Preset = BfvPreset;
    type Data = ();
    type Error = CircuitsErrors;

    fn compute(preset: Self::Preset, _: &Self::Data) -> Result<Self, CircuitsErrors> {
        let (threshold_params, _) =
            build_pair_for_preset(preset).map_err(|e| CircuitsErrors::Other(e.to_string()))?;

        let moduli = threshold_params.moduli().to_vec();

        let bounds = Bounds::compute(preset, &())?;
        let bits = Bits::compute(preset, &bounds)?;

        Ok(Configs {
            n: threshold_params.degree(),
            l: moduli.len(),
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

    fn compute(preset: Self::Preset, data: &Self::Data) -> Result<Self, Self::Error> {
        // One width covers every limb's `r`, so take the widest bound.
        let mut r_bit = 0;
        for bound in data.r_bounds.iter() {
            r_bit = r_bit.max(calculate_bit_width(BigInt::from(bound.clone())));
        }

        let (threshold_params, _) =
            build_pair_for_preset(preset).map_err(|e| CircuitsErrors::Other(e.to_string()))?;
        let d_native_bit = compute_native_crt_coeff_bit(threshold_params.moduli());

        // `ct`, `sk`, `e_sm` and `d` are centered residues, so they share the modulus width. This
        // used to piggyback on the `r2` bound, which was `(max(q) - 1) / 2` for exactly that reason;
        // with `r2` gone the width comes from the moduli directly.
        let modulus_bit = crate::compute_modulus_bit(&threshold_params);

        Ok(Bits {
            ct_bit: modulus_bit,
            sk_bit: modulus_bit,
            e_sm_bit: modulus_bit,
            r_bit,
            d_bit: modulus_bit,
            d_native_bit,
        })
    }
}

impl Computation for Bounds {
    type Preset = BfvPreset;
    type Data = ();
    type Error = CircuitsErrors;

    fn compute(preset: Self::Preset, _: &Self::Data) -> Result<Self, Self::Error> {
        let (threshold_params, _) =
            build_pair_for_preset(preset).map_err(|e| CircuitsErrors::Other(e.to_string()))?;

        let n = BigInt::from(threshold_params.degree());
        // Get cyclotomic degree and context at provided level
        let ctx = threshold_params.context_at_level(0)?;

        // Calculate bounds for each CRT basis
        let mut r_bounds: Vec<BigInt> = Vec::new();
        let mut moduli: Vec<u64> = Vec::new();

        for qi in ctx.moduli_operators() {
            let qi_bigint = BigInt::from(**qi);
            let qi_bound = (&qi_bigint - BigInt::from(1)) / BigInt::from(2);

            moduli.push(**qi);

            // `r` is the mod-q quotient of the identity reduced modulo X^N + 1:
            //   d = ct0 + (ct1 * sk mod X^N + 1) + e_sm + q * r
            // so bounding the other terms and dividing by q bounds `r`. The negacyclic product of n
            // terms contributes n * ((q-1)/2)^2 and each of `d`, `ct0`, `e_sm` contributes (q-1)/2.
            // The 4 rather than 3 keeps the margin the unreduced `r1` bound carried, which also
            // means the reduced quotient is no wider -- the width stays 69 (43 insecure).
            r_bounds.push(
                (&qi_bound.clone() * &qi_bound.clone() * &n + BigInt::from(4) * &qi_bound.clone())
                    / &qi_bigint,
            );
        }

        let bounds = Bounds {
            r_bounds: r_bounds
                .iter()
                .map(|b| BigUint::from(b.to_u128().unwrap()))
                .collect(),
        };

        Ok(bounds)
    }
}

impl Computation for Inputs {
    type Preset = BfvPreset;
    type Data = ShareDecryptionCircuitData;
    type Error = CircuitsErrors;

    fn compute(preset: Self::Preset, data: &Self::Data) -> Result<Self, Self::Error> {
        let (threshold_params, _) =
            build_pair_for_preset(preset).map_err(|e| CircuitsErrors::Other(e.to_string()))?;

        let moduli: Vec<BigInt> = threshold_params
            .moduli()
            .iter()
            .copied()
            .map(BigInt::from)
            .collect();
        let n = threshold_params.degree() as u64;

        // Extract and convert ciphertext polynomials
        let ct0 = CrtPolynomial::from_fhe_polynomial(&data.ciphertext[0]);
        let ct1 = CrtPolynomial::from_fhe_polynomial(&data.ciphertext[1]);

        // Create cyclotomic polynomial x^N + 1
        let mut cyclo = vec![BigInt::from(0u64); (n + 1) as usize];
        cyclo[0] = BigInt::from(1u64); // constant (x^0) term
        cyclo[n as usize] = BigInt::from(1u64); // x^N term

        // Perform the main computation logic
        #[allow(clippy::type_complexity)]
        let mut results: Vec<(
            usize,
            Polynomial,
            Polynomial,
            Polynomial,
            Polynomial,
            Polynomial,
            Polynomial,
        )> = izip!(
            moduli.clone(),
            ct0.limbs.clone(),
            ct1.limbs.clone(),
            data.s.limbs.clone(),
            data.e.limbs.clone(),
            data.d_share.limbs.clone(),
        )
        .enumerate()
        .par_bridge()
        .map(|(i, (qi, mut ct0, mut ct1, mut s, mut e, mut d_share))| {
            ct0.reverse();
            ct0.center(&qi);

            ct1.reverse();
            ct1.center(&qi);

            s.reverse();
            s.center(&qi);

            e.reverse();
            e.center(&qi);

            d_share.reverse();
            d_share.center(&qi);

            // Compute d_share_hat = ct0 + ct1 * s + e
            // This is the expected value before lifting to Z
            let d_share_hat = {
                // ct1 * s (degree 2*(n-1))
                let ct1_s_times = ct1.mul(&s);
                assert_eq!((ct1_s_times.coefficients().len() as u64) - 1, 2 * (n - 1));

                // ct0 + ct1 * s + e
                ct0.add(&ct1_s_times).add(&e)
            };
            assert_eq!((d_share_hat.coefficients().len() as u64) - 1, 2 * (n - 1));

            // The circuit checks the identity reduced modulo X^N + 1, so the cyclotomic
            // quotient's term is identically zero and `r2` is gone. `r` is then pinned by the
            // identity itself:
            //   d = (ct0 + ct1 * s + e mod X^N + 1) + q * r
            // so folding the `d_share_hat` already computed above and dividing by q gives it.
            //
            // All O(N). Going via `decompose_residue` and `reduce_by_cyclotomic` would recompute the
            // ct1 * s product and run generic long division over a divisor whose N-1 interior
            // coefficients are zero -- see 9a35e2e1, where that cost C1 5.09s against 0.92s.
            let reduced_hat = fold_negacyclic(&d_share_hat, n as usize);

            // Exact division is the identity: `div` rejects any coefficient of `d - reduced_hat`
            // that is not a multiple of qi, so a successful division proves an integer `r` closes
            // the reduced equation, and a wrong fold surfaces as a divisibility failure.
            let (r, remainder) = d_share
                .sub(&reduced_hat)
                .div(&Polynomial::constant(qi.clone()))
                .expect("d - (ct0 + ct1 * s + e mod X^N + 1) must be divisible by qi");
            assert!(
                remainder.is_zero(),
                "reduced decryption-share identity must divide exactly by qi"
            );

            // Restate the identity on the derived witness. Cheap at O(N), independent of `div`.
            assert!(
                d_share.sub(&reduced_hat.add(&r.scalar_mul(&qi))).is_zero(),
                "reduced identity must hold: d == ct0 + ct1 * sk + e_sm + qi * r (mod X^N + 1)"
            );

            (i, ct0, ct1, s, e, d_share, r)
        })
        .collect();

        results.sort_by_key(|(i, _, _, _, _, _, _)| *i);

        let mut ct0 = CrtPolynomial::new(vec![]);
        let mut ct1 = CrtPolynomial::new(vec![]);
        let mut sk = CrtPolynomial::new(vec![]);
        let mut e_sm = CrtPolynomial::new(vec![]);
        let mut r = CrtPolynomial::new(vec![]);
        let mut d = CrtPolynomial::new(vec![]);

        for (_i, ct0i, ct1i, si, ei, d_sharei, ri) in results {
            ct0.add_limb(ct0i);
            ct1.add_limb(ct1i);
            sk.add_limb(si);
            e_sm.add_limb(ei);
            r.add_limb(ri);
            d.add_limb(d_sharei);
        }

        // Compute commitments to s and e (matches circuit's commitment functions)
        let modulus_bit = compute_modulus_bit(&threshold_params);
        let expected_sk_commitment = compute_aggregated_shares_commitment(&sk, modulus_bit);
        let expected_e_sm_commitment = compute_aggregated_shares_commitment(&e_sm, modulus_bit);

        let bounds = Bounds::compute(preset, &())?;
        let bits = Bits::compute(preset, &bounds)?;
        let ct_commitment = compute_ciphertext_commitment(&ct0, &ct1, bits.ct_bit);

        let moduli_u64: Vec<u64> = threshold_params.moduli().to_vec();
        let d_native_trunc =
            d_native_trunc_from_centered_d(&d, &moduli_u64, n as usize, MAX_MSG_NON_ZERO_COEFFS);

        Ok(Inputs {
            ct0,
            ct1,
            sk,
            e_sm,
            r,
            d,
            d_native_trunc,
            expected_sk_commitment,
            expected_e_sm_commitment,
            ct_commitment,
            domain_hi: BigInt::from(data.domain_hi),
            domain_lo: BigInt::from(data.domain_lo),
        })
    }

    fn to_json(&self) -> serde_json::Result<serde_json::Value> {
        let ct0 = crt_polynomial_to_toml_json(&self.ct0);
        let ct1 = crt_polynomial_to_toml_json(&self.ct1);
        let sk = crt_polynomial_to_toml_json(&self.sk);
        let e_sm = crt_polynomial_to_toml_json(&self.e_sm);
        let r = crt_polynomial_to_toml_json(&self.r);
        let d = crt_polynomial_to_toml_json(&self.d);
        let d_native_trunc = crt_polynomial_to_toml_json(&self.d_native_trunc);
        let expected_sk_commitment = self.expected_sk_commitment.to_string();
        let expected_e_sm_commitment = self.expected_e_sm_commitment.to_string();
        let ct_commitment = self.ct_commitment.to_string();
        let domain_hi = self.domain_hi.to_string();
        let domain_lo = self.domain_lo.to_string();

        let json = serde_json::json!({
            "ct0": ct0,
            "ct1": ct1,
            "sk": sk,
            "e_sm": e_sm,
            "r": r,
            "d": d,
            "d_native_trunc": d_native_trunc,
            "expected_sk_commitment": expected_sk_commitment,
            "expected_e_sm_commitment": expected_e_sm_commitment,
            "ct_commitment": ct_commitment,
            "domain_hi": domain_hi,
            "domain_lo": domain_lo,
        });

        Ok(json)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use e3_fhe_params::DEFAULT_BFV_PRESET;

    /// `ct`, `sk`, `e_sm` and `d` are centered residues, so they all carry the modulus width.
    ///
    /// This used to assert against the `r2` bound, which happened to equal `(max(q) - 1) / 2`. With
    /// `r2` removed by the reduced identity, the expectation is derived from the moduli instead --
    /// the independent source, rather than another generated value that merely coincided.
    #[test]
    fn test_bound_and_bits_computation_consistency() {
        let (threshold_params, _) = build_pair_for_preset(DEFAULT_BFV_PRESET).unwrap();
        let bounds = Bounds::compute(DEFAULT_BFV_PRESET, &()).unwrap();
        let bits = Bits::compute(DEFAULT_BFV_PRESET, &bounds).unwrap();

        let max_q = *threshold_params.moduli().iter().max().unwrap();
        let expected_bit = calculate_bit_width((BigInt::from(max_q) - BigInt::from(1)) / 2);

        assert_eq!(bits.d_bit, expected_bit);
        assert_eq!(bits.ct_bit, expected_bit);
        assert_eq!(bits.sk_bit, expected_bit);
        assert_eq!(bits.e_sm_bit, expected_bit);
    }

    #[test]
    fn test_d_native_bit_matches_moduli_and_covers_centered_d_bit() {
        let (threshold_params, _) = build_pair_for_preset(DEFAULT_BFV_PRESET).unwrap();
        let bounds = Bounds::compute(DEFAULT_BFV_PRESET, &()).unwrap();
        let bits = Bits::compute(DEFAULT_BFV_PRESET, &bounds).unwrap();
        assert_eq!(
            bits.d_native_bit,
            crate::compute_native_crt_coeff_bit(threshold_params.moduli())
        );
        assert!(bits.d_native_bit >= bits.d_bit);
    }

    /// `d_commitment` matches C7: hash of native truncated `from_fhe` limbs, via `d_native_trunc`.
    #[test]
    fn test_d_commitment_matches_inputs_compute() {
        use crate::circuits::commitments::compute_threshold_decryption_share_commitment;
        use crate::threshold::share_decryption::ShareDecryptionCircuitData;
        use crate::CiphernodesCommitteeSize;
        use fhe_math::rq::{Poly, PowerBasis};
        use fhe_traits::{DeserializeWithContext, Serialize as FheSer};
        use num_traits::ToPrimitive;

        let preset = DEFAULT_BFV_PRESET;
        let committee = CiphernodesCommitteeSize::Small.values();
        let sample = ShareDecryptionCircuitData::generate_sample(preset, committee).unwrap();
        let (threshold_params, _) = build_pair_for_preset(preset).unwrap();
        let bounds = Bounds::compute(preset, &()).unwrap();
        let bits = Bits::compute(preset, &bounds).unwrap();

        let inputs = Inputs::compute(preset, &sample).unwrap();
        let from_d_native = compute_threshold_decryption_share_commitment(
            &inputs.d_native_trunc,
            bits.d_native_bit,
            MAX_MSG_NON_ZERO_COEFFS,
        );
        let from_raw_share = compute_threshold_decryption_share_commitment(
            &sample.d_share,
            bits.d_native_bit,
            MAX_MSG_NON_ZERO_COEFFS,
        );
        assert_eq!(from_d_native, from_raw_share);

        // Bytes round-trip: Poly → to_bytes → from_bytes → from_fhe_polynomial
        let raw: Vec<Vec<u64>> = sample
            .d_share
            .limbs
            .iter()
            .map(|l| {
                l.coefficients()
                    .iter()
                    .map(|c| c.to_u64().unwrap())
                    .collect()
            })
            .collect();
        let n = raw[0].len();
        let mut arr = ndarray::Array2::<u64>::zeros((raw.len(), n));
        for (i, limb) in raw.iter().enumerate() {
            for (j, &v) in limb.iter().enumerate() {
                arr[[i, j]] = v;
            }
        }
        let ctx = threshold_params.context_at_level(0).unwrap();
        let mut poly = Poly::<PowerBasis>::zero(ctx);
        poly.set_coefficients(arr);
        let poly_rt = Poly::<PowerBasis>::from_bytes(&poly.to_bytes(), ctx).unwrap();
        let crt_rt = CrtPolynomial::from_fhe_polynomial(&poly_rt);
        let from_bytes = compute_threshold_decryption_share_commitment(
            &crt_rt,
            bits.d_native_bit,
            MAX_MSG_NON_ZERO_COEFFS,
        );
        assert_eq!(from_d_native, from_bytes);
    }
}
