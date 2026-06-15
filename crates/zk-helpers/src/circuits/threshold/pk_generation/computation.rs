// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Computation types for the public key generation circuit: constants, bounds, bit widths, and inputs.
//!
//! [`Configs`], [`Bounds`], [`Bits`], and [`Inputs`] are produced from BFV parameters
//! and (for input) a public key. They implement [`Computation`] and are used by codegen.

use crate::calculate_bit_width;
use crate::ciphernodes_committee::CiphernodesCommittee;
use crate::crt_polynomial_to_toml_json;
use crate::math::{cyclotomic_polynomial, decompose_residue};
use crate::polynomial_to_toml_json;
use crate::threshold::pk_generation::circuit::PkGenerationCircuit;
use crate::threshold::pk_generation::circuit::PkGenerationCircuitData;
use crate::threshold::pk_generation::utils::deterministic_crp_crt_polynomial;
use crate::CircuitsErrors;
use crate::{CircuitComputation, Computation};
use e3_fhe_params::build_pair_for_preset;
use e3_fhe_params::BfvPreset;
use e3_polynomial::CrtPolynomial;
use e3_polynomial::Polynomial;
use fhe::bfv::SecretKey;
use fhe::trbfv::SmudgingBoundCalculator;
use fhe::trbfv::SmudgingBoundCalculatorConfig;
use itertools::izip;
use num_bigint::BigInt;
use num_bigint::BigUint;
use num_traits::ToPrimitive;
use rayon::iter::ParallelBridge;
use rayon::iter::ParallelIterator;
use serde::{Deserialize, Serialize};

/// Output of [`CircuitComputation::compute`] for [`PkGenerationCircuit`]: bounds, bit widths, and input.
#[derive(Debug)]
pub struct PkGenerationComputationOutput {
    pub bounds: Bounds,
    pub bits: Bits,
    pub inputs: Inputs,
}

/// Implementation of [`CircuitComputation`] for [`PkGenerationCircuit`].
impl CircuitComputation for PkGenerationCircuit {
    type Preset = BfvPreset;
    type Data = PkGenerationCircuitData;
    type Output = PkGenerationComputationOutput;
    type Error = CircuitsErrors;

    fn compute(preset: Self::Preset, data: &Self::Data) -> Result<Self::Output, Self::Error> {
        let bounds = Bounds::compute(preset, &data.committee)?;
        let bits = Bits::compute(preset, &bounds)?;
        let inputs = Inputs::compute(preset, data)?;

        Ok(PkGenerationComputationOutput {
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
    pub eek_bit: u32,
    pub sk_bit: u32,
    pub e_sm_bit: u32,
    pub r1_bit: u32,
    pub r2_bit: u32,
    pub pk_bit: u32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Bounds {
    pub eek_bound: BigUint,
    pub sk_bound: BigUint,
    pub e_sm_bound: BigUint,
    pub r1_bounds: Vec<BigUint>,
    pub r2_bounds: Vec<BigUint>,
    pub pk_bound: BigUint,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Inputs {
    pub eek: Polynomial,
    pub sk: Polynomial,
    pub e_sm: CrtPolynomial,
    pub r1is: CrtPolynomial,
    pub r2is: CrtPolynomial,
    pub pk0is: CrtPolynomial,
}

impl Computation for Configs {
    type Preset = BfvPreset;
    type Data = CiphernodesCommittee;
    type Error = CircuitsErrors;

    fn compute(preset: Self::Preset, committee: &Self::Data) -> Result<Self, CircuitsErrors> {
        let (threshold_params, _) =
            build_pair_for_preset(preset).map_err(|e| CircuitsErrors::Other(e.to_string()))?;

        let moduli = threshold_params.moduli().to_vec();

        let bounds = Bounds::compute(preset, committee)?;
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
        // Calculate bit widths for each bound type
        let eek_bit = calculate_bit_width(BigInt::from(data.eek_bound.clone()));
        let sk_bit = calculate_bit_width(BigInt::from(data.sk_bound.clone()));
        let e_sm_bit = calculate_bit_width(BigInt::from(data.e_sm_bound.clone()));

        // pk_bit: centered representation uses (max(qi) - 1) / 2 as the bound,
        // matching compute_modulus_bit() used in C5 (pk_aggregation).
        let (threshold_params, _) =
            build_pair_for_preset(preset).map_err(|e| CircuitsErrors::Other(e.to_string()))?;
        let pk_bit = crate::compute_modulus_bit(&threshold_params);

        // For r1, use the maximum of all low and up bounds
        let mut r1_bit = 0;
        for bound in &data.r1_bounds {
            r1_bit = r1_bit.max(calculate_bit_width(BigInt::from(bound.clone())));
        }

        // For r2, use the maximum of all bounds
        let mut r2_bit = 0;
        for bound in &data.r2_bounds {
            r2_bit = r2_bit.max(calculate_bit_width(BigInt::from(bound.clone())));
        }

        Ok(Bits {
            eek_bit,
            sk_bit,
            e_sm_bit,
            r1_bit,
            r2_bit,
            pk_bit,
        })
    }
}

impl Computation for Bounds {
    type Preset = BfvPreset;
    type Data = CiphernodesCommittee;
    type Error = CircuitsErrors;

    fn compute(preset: Self::Preset, committee: &Self::Data) -> Result<Self, Self::Error> {
        let (threshold_params, _) =
            build_pair_for_preset(preset).map_err(|e| CircuitsErrors::Other(e.to_string()))?;

        let committee = crate::ciphernodes_committee::canonical_committee_for_circuit(committee)
            .map_err(|e| CircuitsErrors::Other(e.to_string()))?;
        let committee_n = committee.n;

        let n = BigInt::from(threshold_params.degree());
        let ctx = threshold_params.context_at_level(0)?;

        let cbd_bound = (threshold_params.variance() * 2) as u64;

        let sk_bound = SecretKey::sk_bound();
        let eek_bound = cbd_bound;

        let sd = preset
            .search_defaults()
            .ok_or_else(|| CircuitsErrors::Other("missing search defaults".to_string()))?;

        // Lambda is secure or insecure depending on the preset's security tier.
        let lambda = preset
            .lambda()
            .map_err(|e| CircuitsErrors::Other(e.to_string()))?;
        let smudging_config = SmudgingBoundCalculatorConfig::new(
            threshold_params.clone(),
            committee_n,
            sd.z as usize,
            lambda,
        );
        let smudging_calculator = SmudgingBoundCalculator::new(smudging_config);
        let e_sm_bound = smudging_calculator.calculate_sm_bound().map_err(|e| {
            CircuitsErrors::Other(format!("Failed to calculate smudging bound: {:?}", e))
        })?;

        // Calculate bounds for each CRT basis
        let num_moduli = ctx.moduli().len();
        let mut r2_bounds = vec![BigInt::from(0); num_moduli];
        let mut r1_bounds = vec![BigInt::from(0); num_moduli];
        let mut moduli = Vec::new();
        let mut pk_bound_max = BigInt::from(0);

        for (i, qi) in ctx.moduli_operators().iter().enumerate() {
            let qi_bigint = BigInt::from(**qi);
            let qi_bound = (&qi_bigint - 1u32) / 2u32;

            moduli.push(**qi);

            r2_bounds[i] = qi_bound.clone();

            // Compute asymmetric range for r1 bounds per modulus
            r1_bounds[i] = ((&n + 2u32) * &qi_bound + eek_bound) / &qi_bigint;

            // Track maximum pk bound across all moduli
            // We don't need to store them as we only need the maximum bound to compute the commitment bit width
            if qi_bound > pk_bound_max {
                pk_bound_max = qi_bound;
            }
        }

        let bounds = Bounds {
            eek_bound: BigUint::from(eek_bound),
            sk_bound: BigUint::from(sk_bound as u128),
            e_sm_bound,
            r1_bounds: r1_bounds
                .iter()
                .map(|b| BigUint::from(b.to_u128().unwrap()))
                .collect(),
            r2_bounds: r2_bounds
                .iter()
                .map(|b| BigUint::from(b.to_u128().unwrap()))
                .collect(),
            pk_bound: BigUint::from(pk_bound_max.to_u128().unwrap()),
        };

        Ok(bounds)
    }
}

impl Computation for Inputs {
    type Preset = BfvPreset;
    type Data = PkGenerationCircuitData;
    type Error = CircuitsErrors;

    fn compute(preset: Self::Preset, data: &Self::Data) -> Result<Self, Self::Error> {
        let (threshold_params, _) =
            build_pair_for_preset(preset).map_err(|e| CircuitsErrors::Other(e.to_string()))?;

        let a = deterministic_crp_crt_polynomial(&threshold_params)?;

        let moduli: Vec<BigInt> = threshold_params
            .moduli()
            .iter()
            .copied()
            .map(BigInt::from)
            .collect();
        let n = threshold_params.degree() as u64;
        let cyclo = cyclotomic_polynomial(n);

        // Perform the main computation logic
        let mut results: Vec<(usize, Polynomial, Polynomial, Polynomial, Polynomial)> = izip!(
            moduli.clone(),
            data.pk0_share.limbs.clone(),
            a.limbs.clone(),
            data.eek.limbs.clone(),
            data.e_sm.limbs.clone(),
            data.sk.limbs.clone(),
        )
        .enumerate()
        .par_bridge()
        .map(|(i, (qi, mut pk0_share, a, mut eek, mut e_sm, mut sk))| {
            pk0_share.reverse();
            pk0_share.center(&qi);

            eek.reverse();
            eek.center(&qi);

            e_sm.reverse();
            e_sm.center(&qi);

            sk.reverse();
            sk.center(&qi);

            // Calculate pk0_share_hat = -a * sk + eek
            let pk0_share_hat = {
                let mut exp = a.neg();
                exp = exp.mul(&sk);

                assert_eq!((exp.coefficients().len() as u64) - 1, 2 * (n - 1));

                exp.add(&eek)
            };

            assert_eq!((pk0_share_hat.coefficients().len() as u64) - 1, 2 * (n - 1));

            let (r1, r2) = decompose_residue(&pk0_share, &pk0_share_hat, &qi, &cyclo, n);

            (i, r2, r1, pk0_share.clone(), e_sm.clone())
        })
        .collect();

        results.sort_by_key(|(i, _, _, _, _)| *i);

        let mut r2 = CrtPolynomial::new(vec![]);
        let mut r1 = CrtPolynomial::new(vec![]);
        let mut pk0_share = CrtPolynomial::new(vec![]);
        let mut e_sm = CrtPolynomial::new(vec![]);

        let mut sk = data.sk.limbs[0].clone();
        let mut eek = data.eek.limbs[0].clone();

        sk.reverse();
        sk.center(&moduli[0]);
        eek.reverse();
        eek.center(&moduli[0]);

        for (_i, r2i, r1i, pk0_sharei, e_smi) in results {
            r2.add_limb(r2i);
            r1.add_limb(r1i);
            pk0_share.add_limb(pk0_sharei);
            e_sm.add_limb(e_smi);
        }

        Ok(Inputs {
            eek,
            sk,
            e_sm,
            r1is: r1,
            r2is: r2,
            pk0is: pk0_share,
        })
    }

    fn to_json(&self) -> serde_json::Result<serde_json::Value> {
        let pk0is = crt_polynomial_to_toml_json(&self.pk0is);
        let e = polynomial_to_toml_json(&self.eek);
        let sk = polynomial_to_toml_json(&self.sk);
        let e_sm = crt_polynomial_to_toml_json(&self.e_sm);
        let r1is = crt_polynomial_to_toml_json(&self.r1is);
        let r2is = crt_polynomial_to_toml_json(&self.r2is);

        let json = serde_json::json!({
            "pk0is": pk0is,
            "eek": e,
            "sk": sk,
            "e_sm": e_sm,
            "r1is": r1is,
            "r2is": r2is,
        });

        Ok(json)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CiphernodesCommittee;
    use e3_fhe_params::BfvPreset;

    #[test]
    fn bounds_compute_rejects_non_canonical_committee_h() {
        let preset = BfvPreset::InsecureThreshold512;
        let bad = CiphernodesCommittee {
            n: 3,
            h: 8,
            threshold: 1,
        };
        let err = Bounds::compute(preset, &bad).unwrap_err();
        assert!(
            format!("{err:?}").contains("committee.h=8"),
            "expected h mismatch error, got {err:?}"
        );
    }

    #[test]
    fn bounds_compute_rejects_unknown_threshold_pair() {
        let preset = BfvPreset::InsecureThreshold512;
        let bad = CiphernodesCommittee {
            n: 5,
            h: 5,
            threshold: 1,
        };
        assert!(Bounds::compute(preset, &bad).is_err());
    }

    #[test]
    fn test_bound_and_bits_computation_consistency() {
        let preset = BfvPreset::InsecureThreshold512;
        use crate::ciphernodes_committee::CiphernodesCommitteeSize;
        let committee = CiphernodesCommitteeSize::Micro.values();
        let bounds = Bounds::compute(preset, &committee).unwrap();
        let bits = Bits::compute(preset, &bounds).unwrap();

        // pk_bit uses compute_modulus_bit: (max(qi) - 1) / 2 for centered representation
        let (threshold_params, _) = build_pair_for_preset(preset).unwrap();
        let expected_bit = crate::compute_modulus_bit(&threshold_params);

        assert_eq!(bits.pk_bit, expected_bit);
    }

    #[test]
    fn test_constants_json_roundtrip() {
        let committee = crate::ciphernodes_committee::CiphernodesCommitteeSize::Micro.values();
        let constants = Configs::compute(BfvPreset::InsecureThreshold512, &committee).unwrap();

        let json = constants.to_json().unwrap();
        let decoded: Configs = serde_json::from_value(json).unwrap();

        assert_eq!(decoded.n, constants.n);
        assert_eq!(decoded.l, constants.l);
        assert_eq!(decoded.moduli, constants.moduli);
        assert_eq!(decoded.bits, constants.bits);
        assert_eq!(decoded.bounds, constants.bounds);
    }
}
