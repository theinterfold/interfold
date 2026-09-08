// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Conversion of l-BFV relinearization-key rows into Noir witnesses.

use crate::math::{cyclotomic_polynomial, decompose_residue};
use crate::utils::{validate_crt_shape, verify_crt_shapes};
use crate::{
    calculate_bit_width, crt_polynomial_to_toml_json, polynomial_to_toml_json, Artifacts,
    CiphernodesCommittee, Circuit, CircuitCodegen, CircuitComputation, CircuitsErrors,
    CodegenConfigs, CodegenToml, Computation,
};
use e3_fhe_params::{build_pair_for_preset, lbfv_crs_seed, lbfv_urs_seed, BfvPreset};
use e3_polynomial::{CrtPolynomial, Polynomial, ToPowerBasisPoly};
use fhe::bfv::{BfvParameters, CommonRandomPolyVec, SecretKey};
use fhe::trlbfv::{PublicKeyShare, RelinKeyShare, RlkWitness};
use fhe_math::rns::RnsContext;
use fhe_math::rq::{traits::TryConvertFrom, Context, Ntt, NttShoup, Poly, PowerBasis};
use num_bigint::{BigInt, BigUint};
use std::sync::Arc;
use zeroize::Zeroize;

/// Row-level l-BFV relinearization-key generation circuit.
#[derive(Debug)]
pub struct RlkGenerationCircuit;

impl Circuit for RlkGenerationCircuit {
    const NAME: &'static str = "rlk-generation";
    const PREFIX: &'static str = "RLK_GENERATION";
    const SUPPORTED_PARAMETER: e3_fhe_params::ParameterType =
        e3_fhe_params::ParameterType::THRESHOLD;
    const DKG_INPUT_TYPE: Option<crate::computation::DkgInputType> = None;
}

/// Inputs for one row of the l-BFV RLK generation circuit.
pub struct RlkGenerationCircuitData {
    /// Committee values used to select the circuit bounds.
    pub committee: CiphernodesCommittee,
    /// Gadget-row index proved by the circuit.
    pub row_index: u32,
    /// Secret key shared with the matching C1 proof.
    pub sk: Polynomial,
    /// Ephemeral RLK secret polynomial.
    pub r: Polynomial,
    /// Error polynomial for the `d0` equation.
    pub e0: Polynomial,
    /// Error polynomial for the `d2` equation.
    pub e2: Polynomial,
    /// Modulus-switching quotients for the `d0` equation.
    pub r1_d0: CrtPolynomial,
    /// Cyclotomic-reduction quotients for the `d0` equation.
    pub r2_d0: CrtPolynomial,
    /// Modulus-switching quotients for the `d2` equation.
    pub r1_d2: CrtPolynomial,
    /// Cyclotomic-reduction quotients for the `d2` equation.
    pub r2_d2: CrtPolynomial,
    /// Secret-dependent `d0` row in CRT form.
    pub d0: CrtPolynomial,
    /// Secret-dependent `d2` row in CRT form.
    pub d2: CrtPolynomial,
}

/// Complete RLK circuit computation output.
pub struct RlkGenerationComputationOutput {
    pub bounds: RlkGenerationBounds,
    pub bits: RlkGenerationBits,
    pub inputs: RlkGenerationInputs,
}

/// Generated RLK constants for one preset and committee.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RlkGenerationConfigs {
    pub n: usize,
    pub l: usize,
    pub moduli: Vec<u64>,
    pub bits: RlkGenerationBits,
    pub bounds: RlkGenerationBounds,
}

/// Bit widths used by the RLK generation circuit.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct RlkGenerationBits {
    pub r_bit: u32,
    pub sk_bit: u32,
    pub e0_bit: u32,
    pub e2_bit: u32,
    pub r1_d0_bit: u32,
    pub r2_d0_bit: u32,
    pub r1_d2_bit: u32,
    pub r2_d2_bit: u32,
    pub d_bit: u32,
}

/// Coefficient bounds used by the RLK generation circuit.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct RlkGenerationBounds {
    pub r_bound: BigUint,
    pub sk_bound: BigUint,
    pub e0_bound: BigUint,
    pub e2_bound: BigUint,
    pub r1_d0_bounds: Vec<BigUint>,
    pub r2_d0_bounds: Vec<BigUint>,
    pub r1_d2_bounds: Vec<BigUint>,
    pub r2_d2_bounds: Vec<BigUint>,
}

/// Prover inputs for one RLK gadget row.
#[derive(serde::Serialize, serde::Deserialize)]
pub struct RlkGenerationInputs {
    pub row_index: u32,
    pub sk: Polynomial,
    pub r: Polynomial,
    pub e0: Polynomial,
    pub e2: Polynomial,
    pub r1_d0: CrtPolynomial,
    pub r2_d0: CrtPolynomial,
    pub r1_d2: CrtPolynomial,
    pub r2_d2: CrtPolynomial,
    pub d0: CrtPolynomial,
    pub d2: CrtPolynomial,
}

impl CircuitComputation for RlkGenerationCircuit {
    type Preset = BfvPreset;
    type Data = RlkGenerationCircuitData;
    type Output = RlkGenerationComputationOutput;
    type Error = CircuitsErrors;

    fn compute(preset: Self::Preset, data: &Self::Data) -> Result<Self::Output, Self::Error> {
        let bounds = RlkGenerationBounds::compute(preset, &data.committee)?;
        let bits = RlkGenerationBits::compute(preset, &bounds)?;
        let inputs = RlkGenerationInputs::compute(preset, data)?;
        Ok(RlkGenerationComputationOutput {
            bounds,
            bits,
            inputs,
        })
    }
}

impl Computation for RlkGenerationConfigs {
    type Preset = BfvPreset;
    type Data = CiphernodesCommittee;
    type Error = CircuitsErrors;

    fn compute(preset: Self::Preset, committee: &Self::Data) -> Result<Self, Self::Error> {
        let (params, _) = build_pair_for_preset(preset)
            .map_err(|error| CircuitsErrors::Other(error.to_string()))?;
        let bounds = RlkGenerationBounds::compute(preset, committee)?;
        let bits = RlkGenerationBits::compute(preset, &bounds)?;
        Ok(Self {
            n: params.degree(),
            l: params.moduli().len(),
            moduli: params.moduli().to_vec(),
            bits,
            bounds,
        })
    }
}

impl Computation for RlkGenerationBounds {
    type Preset = BfvPreset;
    type Data = CiphernodesCommittee;
    type Error = CircuitsErrors;

    fn compute(preset: Self::Preset, committee: &Self::Data) -> Result<Self, Self::Error> {
        if lbfv_crs_seed(preset).is_none() || lbfv_urs_seed(preset).is_none() {
            return Err(CircuitsErrors::Other(format!(
                "l-BFV RLK generation is not enabled for {preset:?}"
            )));
        }
        let (params, _) = build_pair_for_preset(preset)
            .map_err(|error| CircuitsErrors::Other(error.to_string()))?;
        let pk_bounds = crate::threshold::pk_generation::Bounds::compute(preset, committee)?;
        let rns = RnsContext::new(params.moduli())
            .map_err(|error| CircuitsErrors::Other(error.to_string()))?;
        let max_garner = (0..params.moduli().len())
            .map(|index| {
                rns.get_garner(index).cloned().ok_or_else(|| {
                    CircuitsErrors::Other(format!("missing Garner coefficient at index {index}"))
                })
            })
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .max()
            .ok_or_else(|| CircuitsErrors::Other("l-BFV has no Garner coefficients".to_string()))?;

        let n = BigUint::from(params.degree());
        let sk_bound = pk_bounds.sk_bound;
        let error_bound = pk_bounds.eek_bound;
        let mut r1_bounds = Vec::with_capacity(params.moduli().len());
        let mut r2_bounds = Vec::with_capacity(params.moduli().len());
        for modulus in params.moduli() {
            let modulus = BigUint::from(*modulus);
            let centered_bound = (&modulus - 1u32) / 2u32;
            let numerator = &n * &centered_bound * &sk_bound
                + &error_bound
                + &max_garner * &sk_bound
                + 2u32 * &centered_bound;
            r1_bounds.push(numerator / &modulus);
            r2_bounds.push(centered_bound);
        }

        Ok(Self {
            r_bound: sk_bound.clone(),
            sk_bound,
            e0_bound: error_bound.clone(),
            e2_bound: error_bound,
            r1_d0_bounds: r1_bounds.clone(),
            r2_d0_bounds: r2_bounds.clone(),
            r1_d2_bounds: r1_bounds,
            r2_d2_bounds: r2_bounds,
        })
    }
}

impl Computation for RlkGenerationBits {
    type Preset = BfvPreset;
    type Data = RlkGenerationBounds;
    type Error = CircuitsErrors;

    fn compute(preset: Self::Preset, bounds: &Self::Data) -> Result<Self, Self::Error> {
        let (params, _) = build_pair_for_preset(preset)
            .map_err(|error| CircuitsErrors::Other(error.to_string()))?;
        let max_bit = |values: &[BigUint]| {
            values
                .iter()
                .map(|value| calculate_bit_width(BigInt::from(value.clone())))
                .max()
                .unwrap_or(0)
        };
        let r1_bit = max_bit(&bounds.r1_d0_bounds);
        let r2_bit = max_bit(&bounds.r2_d0_bounds);
        Ok(Self {
            r_bit: calculate_bit_width(BigInt::from(bounds.r_bound.clone())),
            sk_bit: calculate_bit_width(BigInt::from(bounds.sk_bound.clone())),
            e0_bit: calculate_bit_width(BigInt::from(bounds.e0_bound.clone())),
            e2_bit: calculate_bit_width(BigInt::from(bounds.e2_bound.clone())),
            r1_d0_bit: r1_bit,
            r2_d0_bit: r2_bit,
            r1_d2_bit: r1_bit,
            r2_d2_bit: r2_bit,
            d_bit: crate::compute_modulus_bit(&params),
        })
    }
}

impl Computation for RlkGenerationInputs {
    type Preset = BfvPreset;
    type Data = RlkGenerationCircuitData;
    type Error = CircuitsErrors;

    fn compute(preset: Self::Preset, data: &Self::Data) -> Result<Self, Self::Error> {
        let (params, _) = build_pair_for_preset(preset)
            .map_err(|error| CircuitsErrors::Other(error.to_string()))?;
        RlkGenerationAdapter::new(preset)?.crs_row(data.row_index)?;
        let l = params.moduli().len();
        let n = params.degree();
        verify_crt_shapes(&[&data.d0, &data.d2], l, n)
            .map_err(|error| CircuitsErrors::Other(format!("RLK CRT shape mismatch: {error}")))?;
        for (name, polynomial, degree) in [
            ("r1_d0", &data.r1_d0, 2 * n - 1),
            ("r2_d0", &data.r2_d0, n - 1),
            ("r1_d2", &data.r1_d2, 2 * n - 1),
            ("r2_d2", &data.r2_d2, n - 1),
        ] {
            validate_crt_shape(polynomial, l, degree).map_err(|error| {
                CircuitsErrors::Other(format!("invalid RLK {name} shape: {error}"))
            })?;
        }
        for (name, polynomial) in [
            ("sk", &data.sk),
            ("r", &data.r),
            ("e0", &data.e0),
            ("e2", &data.e2),
        ] {
            if polynomial.coefficients().len() != n {
                return Err(CircuitsErrors::Other(format!(
                    "RLK {name} has {} coefficients; expected {n}",
                    polynomial.coefficients().len()
                )));
            }
        }

        Ok(Self {
            row_index: data.row_index,
            sk: data.sk.clone(),
            r: data.r.clone(),
            e0: data.e0.clone(),
            e2: data.e2.clone(),
            r1_d0: data.r1_d0.clone(),
            r2_d0: data.r2_d0.clone(),
            r1_d2: data.r1_d2.clone(),
            r2_d2: data.r2_d2.clone(),
            d0: data.d0.clone(),
            d2: data.d2.clone(),
        })
    }

    fn to_json(&self) -> serde_json::Result<serde_json::Value> {
        Ok(serde_json::json!({
            "row_index": self.row_index,
            "sk": polynomial_to_toml_json(&self.sk),
            "r": polynomial_to_toml_json(&self.r),
            "e0": polynomial_to_toml_json(&self.e0),
            "e2": polynomial_to_toml_json(&self.e2),
            "r1_d0": crt_polynomial_to_toml_json(&self.r1_d0),
            "r2_d0": crt_polynomial_to_toml_json(&self.r2_d0),
            "r1_d2": crt_polynomial_to_toml_json(&self.r1_d2),
            "r2_d2": crt_polynomial_to_toml_json(&self.r2_d2),
            "d0": crt_polynomial_to_toml_json(&self.d0),
            "d2": crt_polynomial_to_toml_json(&self.d2),
        }))
    }
}

impl CircuitCodegen for RlkGenerationCircuit {
    type Preset = BfvPreset;
    type Data = RlkGenerationCircuitData;
    type Error = CircuitsErrors;

    fn codegen(&self, preset: Self::Preset, data: &Self::Data) -> Result<Artifacts, Self::Error> {
        let inputs = RlkGenerationInputs::compute(preset, data)?;
        let configs = RlkGenerationConfigs::compute(preset, &data.committee)?;
        Ok(Artifacts {
            toml: generate_toml(inputs)?,
            configs: generate_configs(&configs),
        })
    }
}

/// Serialize one RLK row as `Prover.toml`.
pub fn generate_toml(inputs: RlkGenerationInputs) -> Result<CodegenToml, CircuitsErrors> {
    Ok(toml::to_string(&inputs.to_json()?)?)
}

/// Generate standalone Noir constants for the RLK generation circuit.
pub fn generate_configs(configs: &RlkGenerationConfigs) -> CodegenConfigs {
    let prefix = <RlkGenerationCircuit as Circuit>::PREFIX;
    let moduli = crate::utils::join_display(&configs.moduli, ", ");
    let r1_d0 = crate::utils::join_display(&configs.bounds.r1_d0_bounds, ", ");
    let r2_d0 = crate::utils::join_display(&configs.bounds.r2_d0_bounds, ", ");
    let r1_d2 = crate::utils::join_display(&configs.bounds.r1_d2_bounds, ", ");
    let r2_d2 = crate::utils::join_display(&configs.bounds.r2_d2_bounds, ", ");

    format!(
        r#"use crate::core::threshold::rlk_generation::Configs as RlkGenerationConfigs;

pub global N: u32 = {};
pub global L: u32 = {};
pub global QIS: [Field; L] = [{}];

pub global {}_BIT_R: u32 = {};
pub global {}_BIT_SK: u32 = {};
pub global {}_BIT_E0: u32 = {};
pub global {}_BIT_E2: u32 = {};
pub global {}_BIT_R1_D0: u32 = {};
pub global {}_BIT_R2_D0: u32 = {};
pub global {}_BIT_R1_D2: u32 = {};
pub global {}_BIT_R2_D2: u32 = {};
pub global {}_BIT_D: u32 = {};

pub global {}_R_BOUND: Field = {};
pub global {}_SK_BOUND: Field = {};
pub global {}_E0_BOUND: Field = {};
pub global {}_E2_BOUND: Field = {};
pub global {}_R1_D0_BOUNDS: [Field; L] = [{}];
pub global {}_R2_D0_BOUNDS: [Field; L] = [{}];
pub global {}_R1_D2_BOUNDS: [Field; L] = [{}];
pub global {}_R2_D2_BOUNDS: [Field; L] = [{}];

pub global {}_CONFIGS: RlkGenerationConfigs<N, L> = RlkGenerationConfigs::new(
    QIS,
    {}_R_BOUND,
    {}_SK_BOUND,
    {}_E0_BOUND,
    {}_E2_BOUND,
    {}_R1_D0_BOUNDS,
    {}_R2_D0_BOUNDS,
    {}_R1_D2_BOUNDS,
    {}_R2_D2_BOUNDS,
);
"#,
        configs.n,
        configs.l,
        moduli,
        prefix,
        configs.bits.r_bit,
        prefix,
        configs.bits.sk_bit,
        prefix,
        configs.bits.e0_bit,
        prefix,
        configs.bits.e2_bit,
        prefix,
        configs.bits.r1_d0_bit,
        prefix,
        configs.bits.r2_d0_bit,
        prefix,
        configs.bits.r1_d2_bit,
        prefix,
        configs.bits.r2_d2_bit,
        prefix,
        configs.bits.d_bit,
        prefix,
        configs.bounds.r_bound,
        prefix,
        configs.bounds.sk_bound,
        prefix,
        configs.bounds.e0_bound,
        prefix,
        configs.bounds.e2_bound,
        prefix,
        r1_d0,
        prefix,
        r2_d0,
        prefix,
        r1_d2,
        prefix,
        r2_d2,
        prefix,
        prefix,
        prefix,
        prefix,
        prefix,
        prefix,
        prefix,
        prefix,
        prefix,
    )
}

/// Converts l-BFV key-share rows and their private witness into circuit inputs.
///
/// The adapter reconstructs the canonical CRS and URS from the preset seeds once. Call
/// [`Self::row_data`] for each gadget row generated from the same RLK share and witness.
pub struct RlkGenerationAdapter {
    context: Arc<Context>,
    moduli: Vec<u64>,
    degree: usize,
    d1_rows: Vec<CrtPolynomial>,
    a_rows: Vec<CrtPolynomial>,
    garner: Vec<BigInt>,
    cyclotomic: Vec<BigInt>,
}

impl RlkGenerationAdapter {
    /// Build an adapter for a preset with an enabled l-BFV RLK path.
    pub fn new(preset: BfvPreset) -> Result<Self, CircuitsErrors> {
        let (params, _) = build_pair_for_preset(preset)
            .map_err(|error| CircuitsErrors::Other(error.to_string()))?;
        let crs_seed = lbfv_crs_seed(preset).ok_or_else(|| {
            CircuitsErrors::Other(format!("l-BFV CRS is not enabled for {preset:?}"))
        })?;
        let urs_seed = lbfv_urs_seed(preset).ok_or_else(|| {
            CircuitsErrors::Other(format!("l-BFV URS is not enabled for {preset:?}"))
        })?;
        let crp_d1 = CommonRandomPolyVec::from_seed(&params, urs_seed)?;
        let crp_a = CommonRandomPolyVec::from_seed(&params, crs_seed)?;

        Self::from_rows(&params, &crp_d1, &crp_a)
    }

    /// Number of gadget rows in the canonical l-BFV key-switching vectors.
    #[must_use]
    pub fn row_count(&self) -> usize {
        self.d1_rows.len()
    }

    fn crs_row(&self, row_index: u32) -> Result<&CrtPolynomial, CircuitsErrors> {
        let row = usize::try_from(row_index)
            .map_err(|_| CircuitsErrors::Other("RLK row index does not fit usize".to_string()))?;
        self.a_rows.get(row).ok_or_else(|| {
            CircuitsErrors::Other(format!(
                "RLK row index {row_index} is out of range for {} rows",
                self.row_count()
            ))
        })
    }

    /// Convert one public RLK share row to the circuit's centered CRT representation.
    pub fn share_row_components(
        &self,
        row_index: u32,
        share: &RelinKeyShare,
    ) -> Result<(CrtPolynomial, CrtPolynomial), CircuitsErrors> {
        let row = usize::try_from(row_index)
            .map_err(|_| CircuitsErrors::Other("RLK row index does not fit usize".to_string()))?;
        if row >= self.row_count() {
            return Err(CircuitsErrors::Other(format!(
                "RLK row index {row_index} is out of range for {} rows",
                self.row_count()
            )));
        }
        if share.ciphertext_level() != 0 || share.key_level() != 0 {
            return Err(CircuitsErrors::Other(format!(
                "RLK levels ({}, {}) are unsupported; only level 0 is supported",
                share.ciphertext_level(),
                share.key_level()
            )));
        }
        if share.d0_components().len() != self.row_count()
            || share.d2_components().len() != self.row_count()
        {
            return Err(CircuitsErrors::Other(format!(
                "RLK share row counts must equal {}",
                self.row_count()
            )));
        }

        let d0_component = &share.d0_components()[row];
        let d2_component = &share.d2_components()[row];
        validate_component_context(d0_component, &self.context, &self.moduli, "d0")?;
        validate_component_context(d2_component, &self.context, &self.moduli, "d2")?;

        Ok((
            centered_crt(d0_component, &self.moduli, self.degree)?,
            centered_crt(d2_component, &self.moduli, self.degree)?,
        ))
    }

    /// Convert one generated RLK row into Noir circuit inputs.
    pub fn row_data(
        &self,
        committee: CiphernodesCommittee,
        row_index: u32,
        sk: &SecretKey,
        share: &RelinKeyShare,
        witness: &RlkWitness,
    ) -> Result<RlkGenerationCircuitData, CircuitsErrors> {
        let row = usize::try_from(row_index)
            .map_err(|_| CircuitsErrors::Other("RLK row index does not fit usize".to_string()))?;
        let expected_rows = self.row_count();
        if witness.errors_d0.len() != expected_rows || witness.errors_d2.len() != expected_rows {
            return Err(CircuitsErrors::Other(format!(
                "RLK witness row counts must equal {expected_rows}"
            )));
        }

        let error_d0 = witness
            .errors_d0
            .get(row)
            .ok_or_else(|| CircuitsErrors::Other("RLK d0 error row is missing".to_string()))?;
        let error_d2 = witness
            .errors_d2
            .get(row)
            .ok_or_else(|| CircuitsErrors::Other("RLK d2 error row is missing".to_string()))?;

        for (name, component) in [("e0", error_d0), ("e2", error_d2)] {
            validate_component_context(component, &self.context, &self.moduli, name)?;
        }

        let (d0, d2) = self.share_row_components(row_index, share)?;
        let e0_crt = centered_crt(error_d0, &self.moduli, self.degree)?;
        let e2_crt = centered_crt(error_d2, &self.moduli, self.degree)?;
        let sk_crt = secret_key_to_centered_crt(sk, &self.context, &self.moduli, self.degree)?;
        let r_crt =
            secret_key_to_centered_crt(&witness.r, &self.context, &self.moduli, self.degree)?;

        verify_crt_shapes(
            &[&d0, &d2, &e0_crt, &e2_crt, &sk_crt, &r_crt],
            self.moduli.len(),
            self.degree,
        )
        .map_err(|error| CircuitsErrors::Other(format!("RLK CRT shape mismatch: {error}")))?;

        let sk = sk_crt.limb(0).clone();
        let r = r_crt.limb(0).clone();
        let e0 = e0_crt.limb(0).clone();
        let e2 = e2_crt.limb(0).clone();

        let mut r1_d0 = Vec::with_capacity(self.moduli.len());
        let mut r2_d0 = Vec::with_capacity(self.moduli.len());
        let mut r1_d2 = Vec::with_capacity(self.moduli.len());
        let mut r2_d2 = Vec::with_capacity(self.moduli.len());

        for (i, qi) in self.moduli.iter().enumerate() {
            let d0_hat = self.d1_rows[row]
                .limb(i)
                .neg()
                .mul(&sk)
                .add(&e0)
                .add(&r.scalar_mul(&self.garner[row]));
            let (r1, r2) = decompose_residue(
                d0.limb(i),
                &d0_hat,
                &BigInt::from(*qi),
                &self.cyclotomic,
                self.degree as u64,
            );
            r1_d0.push(r1);
            r2_d0.push(r2);

            let d2_hat = self.a_rows[row]
                .limb(i)
                .mul(&r)
                .add(&e2)
                .add(&sk.scalar_mul(&self.garner[row]));
            let (r1, r2) = decompose_residue(
                d2.limb(i),
                &d2_hat,
                &BigInt::from(*qi),
                &self.cyclotomic,
                self.degree as u64,
            );
            r1_d2.push(r1);
            r2_d2.push(r2);
        }

        Ok(RlkGenerationCircuitData {
            committee,
            row_index,
            sk,
            r,
            e0,
            e2,
            r1_d0: CrtPolynomial::new(r1_d0),
            r2_d0: CrtPolynomial::new(r2_d0),
            r1_d2: CrtPolynomial::new(r1_d2),
            r2_d2: CrtPolynomial::new(r2_d2),
            d0,
            d2,
        })
    }

    /// Convert every RLK row and clear the private FHE witness after conversion.
    pub fn all_rows_data(
        &self,
        committee: CiphernodesCommittee,
        sk: &SecretKey,
        share: &RelinKeyShare,
        witness: RlkWitness,
    ) -> Result<Vec<RlkGenerationCircuitData>, CircuitsErrors> {
        let witness = RlkWitnessGuard::new(witness);
        (0..self.row_count())
            .map(|row_index| {
                self.row_data(
                    committee.clone(),
                    row_index as u32,
                    sk,
                    share,
                    witness.as_ref(),
                )
            })
            .collect()
    }

    /// Validate that a public-key share uses the CRS rows fixed by this adapter.
    pub fn validate_public_key_crs(
        &self,
        public_key: &PublicKeyShare,
    ) -> Result<(), CircuitsErrors> {
        let a_components = public_key.a_components()?;
        if a_components.len() != self.row_count() {
            return Err(CircuitsErrors::Other(format!(
                "public-key CRS has {} rows; expected {}",
                a_components.len(),
                self.row_count()
            )));
        }

        for (row, component) in a_components.iter().enumerate() {
            validate_public_key_component_context(component, &self.context, &self.moduli)?;
            let actual = centered_crt(component, &self.moduli, self.degree)?;
            if actual != self.a_rows[row] {
                return Err(CircuitsErrors::Other(format!(
                    "public-key CRS row {row} does not match the RLK CRS"
                )));
            }
        }

        Ok(())
    }

    fn from_rows(
        params: &Arc<BfvParameters>,
        crp_d1: &CommonRandomPolyVec,
        crp_a: &CommonRandomPolyVec,
    ) -> Result<Self, CircuitsErrors> {
        let moduli = params.moduli().to_vec();
        let degree = params.degree();
        if crp_d1.len() != crp_a.len() || crp_d1.len() != moduli.len() {
            return Err(CircuitsErrors::Other(
                "l-BFV CRP row counts must match each other and the modulus count".to_string(),
            ));
        }

        let d1_rows = crp_d1
            .to_polys()
            .iter()
            .map(|poly| centered_crt(poly, &moduli, degree))
            .collect::<Result<Vec<_>, _>>()?;
        let a_rows = crp_a
            .to_polys()
            .iter()
            .map(|poly| centered_crt(poly, &moduli, degree))
            .collect::<Result<Vec<_>, _>>()?;

        let rns =
            RnsContext::new(&moduli).map_err(|error| CircuitsErrors::Other(error.to_string()))?;
        let garner = (0..moduli.len())
            .map(|index| {
                rns.get_garner(index)
                    .cloned()
                    .map(BigInt::from)
                    .ok_or_else(|| {
                        CircuitsErrors::Other(format!(
                            "missing Garner coefficient at index {index}"
                        ))
                    })
            })
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Self {
            context: params
                .context_at_level(0)
                .map_err(|error| CircuitsErrors::Other(error.to_string()))?
                .clone(),
            moduli,
            degree,
            d1_rows,
            a_rows,
            garner,
            cyclotomic: cyclotomic_polynomial(degree as u64),
        })
    }
}

struct RlkWitnessGuard {
    witness: RlkWitness,
}

impl RlkWitnessGuard {
    fn new(witness: RlkWitness) -> Self {
        Self { witness }
    }
}

impl AsRef<RlkWitness> for RlkWitnessGuard {
    fn as_ref(&self) -> &RlkWitness {
        &self.witness
    }
}

impl Drop for RlkWitnessGuard {
    fn drop(&mut self) {
        self.witness.errors_d0.zeroize();
        self.witness.errors_d2.zeroize();
    }
}

impl RlkGenerationCircuitData {
    /// Generate row zero for codegen and prover tests.
    pub fn generate_sample(
        preset: BfvPreset,
        committee: CiphernodesCommittee,
    ) -> Result<Self, CircuitsErrors> {
        Self::generate_sample_for_row(preset, committee, 0)
    }

    /// Generate one valid RLK row for codegen and prover tests.
    pub fn generate_sample_for_row(
        preset: BfvPreset,
        committee: CiphernodesCommittee,
        row_index: u32,
    ) -> Result<Self, CircuitsErrors> {
        let (params, _) = build_pair_for_preset(preset)
            .map_err(|error| CircuitsErrors::Sample(error.to_string()))?;
        let crs_seed = lbfv_crs_seed(preset).ok_or_else(|| {
            CircuitsErrors::Sample(format!("l-BFV CRS is not enabled for {preset:?}"))
        })?;
        let urs_seed = lbfv_urs_seed(preset).ok_or_else(|| {
            CircuitsErrors::Sample(format!("l-BFV URS is not enabled for {preset:?}"))
        })?;
        let crp_d1 = CommonRandomPolyVec::from_seed(&params, urs_seed)?;
        let crp_a = CommonRandomPolyVec::from_seed(&params, crs_seed)?;
        let mut rng = rand::rng();
        let sk = SecretKey::random(&params, &mut rng);
        let (share, witness) =
            RelinKeyShare::contribution_with_crp_extended(&sk, &crp_d1, &crp_a, 0, 0, &mut rng)?;
        let adapter = RlkGenerationAdapter::new(preset)?;
        let witness = RlkWitnessGuard::new(witness);
        adapter.row_data(committee, row_index, &sk, &share, witness.as_ref())
    }
}

fn centered_crt(
    poly: &impl ToPowerBasisPoly,
    moduli: &[u64],
    degree: usize,
) -> Result<CrtPolynomial, CircuitsErrors> {
    let mut crt = CrtPolynomial::from_fhe_polynomial(poly);
    crt.reverse();
    crt.center(moduli)?;
    validate_crt_shape(&crt, moduli.len(), degree)
        .map_err(|error| CircuitsErrors::Other(format!("invalid FHE polynomial shape: {error}")))?;
    Ok(crt)
}

fn validate_component_context(
    poly: &Poly<NttShoup>,
    context: &Context,
    moduli: &[u64],
    name: &str,
) -> Result<(), CircuitsErrors> {
    if poly.ctx().degree != context.degree || poly.ctx().moduli() != moduli {
        return Err(CircuitsErrors::Other(format!(
            "RLK {name} component context does not match the adapter"
        )));
    }
    Ok(())
}

fn validate_public_key_component_context(
    poly: &Poly<Ntt>,
    context: &Context,
    moduli: &[u64],
) -> Result<(), CircuitsErrors> {
    if poly.ctx().degree != context.degree || poly.ctx().moduli() != moduli {
        return Err(CircuitsErrors::Other(
            "public-key CRS component context does not match the adapter".to_string(),
        ));
    }
    Ok(())
}

fn secret_key_to_centered_crt(
    secret_key: &SecretKey,
    context: &Arc<Context>,
    moduli: &[u64],
    degree: usize,
) -> Result<CrtPolynomial, CircuitsErrors> {
    if secret_key.coeffs.len() != degree {
        return Err(CircuitsErrors::Other(format!(
            "secret key has {} coefficients; expected {degree}",
            secret_key.coeffs.len()
        )));
    }
    let poly = Poly::<PowerBasis>::try_convert_from(secret_key.coeffs.as_ref(), context, false)
        .map_err(|error| CircuitsErrors::Other(error.to_string()))?;
    centered_crt(&poly, moduli, degree)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CiphernodesCommitteeSize;
    use fhe::aggregate::AggregateIter;
    use fhe::bfv::{BfvParametersBuilder, Encoding, Plaintext};
    use fhe::trlbfv::{
        aggregate_relinearization_key, AggregatedPublicKey, ContributionBinding, ParticipantSet,
        PublicKeyShare,
    };
    use fhe_traits::{
        DeserializeParametrized, FheDecoder, FheDecrypter, FheEncoder, FheEncrypter, Serialize,
    };
    use rand::rng;

    #[test]
    fn row_data_reconstructs_each_rlk_equation() -> Result<(), CircuitsErrors> {
        let mut rng = rng();
        let params = BfvParametersBuilder::new()
            .set_degree(8)
            .set_plaintext_modulus(1153)
            .set_moduli_sizes(&[62; 6])
            .build_arc()
            .map_err(|error| CircuitsErrors::Other(error.to_string()))?;
        let crp_d1 = CommonRandomPolyVec::new(&params, &mut rng)?;
        let crp_a = CommonRandomPolyVec::new(&params, &mut rng)?;
        let adapter = RlkGenerationAdapter::from_rows(&params, &crp_d1, &crp_a)?;
        let secret_key = SecretKey::random(&params, &mut rng);
        let (share, witness) = RelinKeyShare::contribution_with_crp_extended(
            &secret_key,
            &crp_d1,
            &crp_a,
            0,
            0,
            &mut rng,
        )?;
        let committee = CiphernodesCommitteeSize::Minimum.values();

        let rows = adapter.all_rows_data(committee, &secret_key, &share, witness)?;
        for (row_index, data) in rows.iter().enumerate() {
            assert_eq!(data.row_index, row_index as u32);
            assert_eq!(data.d0.limbs.len(), params.moduli().len());
            assert_eq!(data.d2.limbs.len(), params.moduli().len());
            assert_eq!(data.r1_d0.limbs.len(), params.moduli().len());
            assert_eq!(data.r2_d0.limbs.len(), params.moduli().len());
            assert_eq!(data.r1_d2.limbs.len(), params.moduli().len());
            assert_eq!(data.r2_d2.limbs.len(), params.moduli().len());

            for (i, qi) in params.moduli().iter().enumerate() {
                let qi_poly = Polynomial::new(vec![BigInt::from(*qi)]);
                let cyclo_poly = Polynomial::new(adapter.cyclotomic.clone());

                let d0_hat = adapter.d1_rows[row_index]
                    .limb(i)
                    .neg()
                    .mul(&data.sk)
                    .add(&data.e0)
                    .add(&data.r.scalar_mul(&adapter.garner[row_index]));
                let d0_calculated = d0_hat
                    .add(&data.r1_d0.limb(i).mul(&qi_poly))
                    .add(&data.r2_d0.limb(i).mul(&cyclo_poly))
                    .trim_leading_zeros();
                assert_eq!(&d0_calculated, data.d0.limb(i));

                let d2_hat = adapter.a_rows[row_index]
                    .limb(i)
                    .mul(&data.r)
                    .add(&data.e2)
                    .add(&data.sk.scalar_mul(&adapter.garner[row_index]));
                let d2_calculated = d2_hat
                    .add(&data.r1_d2.limb(i).mul(&qi_poly))
                    .add(&data.r2_d2.limb(i).mul(&cyclo_poly))
                    .trim_leading_zeros();
                assert_eq!(&d2_calculated, data.d2.limb(i));
            }
        }

        Ok(())
    }

    #[test]
    fn adapter_rejects_presets_without_lbfv() {
        assert!(RlkGenerationAdapter::new(BfvPreset::InsecureThreshold512).is_err());
        assert!(RlkGenerationAdapter::new(BfvPreset::SecureThreshold8192).is_err());
    }

    #[test]
    fn secure_bounds_include_the_garner_term() -> Result<(), CircuitsErrors> {
        let preset = BfvPreset::SecureThreshold16384;
        let committee = CiphernodesCommitteeSize::Minimum.values();
        let bounds = RlkGenerationBounds::compute(preset, &committee)?;
        let pk_bounds = crate::threshold::pk_generation::Bounds::compute(preset, &committee)?;
        let bits = RlkGenerationBits::compute(preset, &bounds)?;

        assert!(bounds
            .r1_d0_bounds
            .iter()
            .zip(pk_bounds.r1_bounds.iter())
            .all(|(rlk, pk)| rlk > pk));
        assert_eq!(bounds.r1_d0_bounds, bounds.r1_d2_bounds);
        assert_eq!(bounds.r2_d0_bounds, bounds.r2_d2_bounds);
        assert!(bits.r1_d0_bit > bits.r2_d0_bit);
        Ok(())
    }

    #[test]
    fn standalone_configs_use_derived_rlk_bounds() -> Result<(), CircuitsErrors> {
        let preset = BfvPreset::SecureThreshold16384;
        let committee = CiphernodesCommitteeSize::Minimum.values();
        let configs = RlkGenerationConfigs::compute(preset, &committee)?;
        let noir = generate_configs(&configs);

        assert!(noir.contains("RLK_GENERATION_R1_D0_BOUNDS"));
        assert!(noir.contains(&configs.bounds.r1_d0_bounds[0].to_string()));
        Ok(())
    }

    #[test]
    fn public_key_crs_matches_rlk_rows() -> Result<(), CircuitsErrors> {
        let mut rng = rng();
        let params = BfvParametersBuilder::new()
            .set_degree(8)
            .set_plaintext_modulus(1153)
            .set_moduli_sizes(&[62; 6])
            .build_arc()
            .map_err(|error| CircuitsErrors::Other(error.to_string()))?;
        let crp_d1 = CommonRandomPolyVec::new(&params, &mut rng)?;
        let crp_a = CommonRandomPolyVec::new(&params, &mut rng)?;
        let adapter = RlkGenerationAdapter::from_rows(&params, &crp_d1, &crp_a)?;
        let secret_key = SecretKey::random(&params, &mut rng);

        let public_key = PublicKeyShare::contribute_with_crp(&secret_key, &crp_a, &mut rng)?;
        adapter.validate_public_key_crs(&public_key)?;

        let other_crp = CommonRandomPolyVec::new(&params, &mut rng)?;
        let other_public_key =
            PublicKeyShare::contribute_with_crp(&secret_key, &other_crp, &mut rng)?;
        assert!(adapter.validate_public_key_crs(&other_public_key).is_err());

        Ok(())
    }

    #[test]
    fn share_roundtrip_relinearizes_with_matching_public_key() -> Result<(), CircuitsErrors> {
        let mut rng = rng();
        let params = BfvParametersBuilder::new()
            .set_degree(8)
            .set_plaintext_modulus(1153)
            .set_moduli_sizes(&[62; 6])
            .build_arc()
            .map_err(|error| CircuitsErrors::Other(error.to_string()))?;
        let crp_d1 = CommonRandomPolyVec::new(&params, &mut rng)?;
        let crp_a = CommonRandomPolyVec::new(&params, &mut rng)?;
        let secret_key = SecretKey::random(&params, &mut rng);
        let participant_set = ParticipantSet::new([9u8; 32], vec![1])
            .map_err(|error| CircuitsErrors::Other(error.to_string()))?;
        let binding = ContributionBinding::new(participant_set, 1)
            .map_err(|error| CircuitsErrors::Other(error.to_string()))?;
        let (share, _) = RelinKeyShare::contribution_with_crp_and_binding_extended(
            &secret_key,
            &crp_d1,
            &crp_a,
            binding.clone(),
            0,
            0,
            &mut rng,
        )?;

        let restored = RelinKeyShare::from_bytes(&share.to_bytes(), &params)
            .map_err(|error| CircuitsErrors::Other(error.to_string()))?;
        assert_eq!(restored.d0_components(), share.d0_components());
        assert_eq!(restored.d2_components(), share.d2_components());
        assert_eq!(restored.ciphertext_level(), 0);
        assert_eq!(restored.key_level(), 0);

        let public_key = PublicKeyShare::contribute_with_crp_and_binding(
            &secret_key,
            &crp_a,
            binding,
            &mut rng,
        )?;
        let aggregated_public_key: AggregatedPublicKey = [public_key].into_iter().aggregate()?;
        let relin_key = aggregate_relinearization_key(&[restored], &aggregated_public_key)?;

        let plaintext = Plaintext::try_encode(&[3u64], Encoding::poly(), &params)?;
        let ciphertext = aggregated_public_key
            .operational()
            .try_encrypt(&plaintext, &mut rng)?;
        let mut square = &ciphertext * &ciphertext;
        relin_key.relinearizes(&mut square)?;
        let decoded = Vec::<u64>::try_decode(&secret_key.try_decrypt(&square)?, Encoding::poly())?;
        assert_eq!(decoded.first(), Some(&9));

        Ok(())
    }
}
