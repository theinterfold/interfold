// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Conversion of l-BFV relinearization-key rows into Noir witnesses.

use crate::math::{
    exact_quotient, fhe_poly_to_crt_centered_checked, fhe_secret_key_to_crt_centered,
    negacyclic_mul, validate_fhe_poly_context,
};
use crate::threshold::lbfv_proof_domain::{
    lbfv_proof_session, sample_lbfv_proof_domain, validate_lbfv_generation_party_id,
};
use crate::utils::{validate_crt_shape, verify_crt_shapes};
use crate::{
    calculate_bit_width, crt_polynomial_to_toml_json, polynomial_to_toml_json, Artifacts,
    CiphernodesCommittee, Circuit, CircuitCodegen, CircuitComputation, CircuitsErrors,
    CodegenConfigs, CodegenToml, Computation,
};
use e3_committee_hash::LbfvProofDomainContext;
use e3_fhe_params::{build_pair_for_preset, lbfv_crs_seed, lbfv_urs_seed, BfvPreset};
use e3_polynomial::{CrtPolynomial, Polynomial};
use fhe::bfv::{BfvParameters, CommonRandomPolyVec, SecretKey};
use fhe::trlbfv::{PublicKeyShare, RelinKeyShare, RlkWitness};
use fhe_math::rq::Context;
use num_bigint::{BigInt, BigUint};
use std::sync::Arc;
use zeroize::Zeroize;

/// l-BFV relinearization-key generation for one row, all CRT limbs in one proof.
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
    /// Protocol context used to derive the public proof-session identifier.
    pub proof_domain: LbfvProofDomainContext,
    /// Zero-based party ID in the finalized committee.
    pub party_id: u32,
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
    /// Per-limb quotients of the reduced `d0` identity, `N` coefficients each.
    pub rd0: CrtPolynomial,
    /// Per-limb quotients of the reduced `d2` identity, `N` coefficients each.
    pub rd2: CrtPolynomial,
    /// Secret-dependent `d0` row in CRT form.
    pub d0: CrtPolynomial,
    /// Secret-dependent `d2` row in CRT form.
    pub d2: CrtPolynomial,
}

/// Computed values for one RLK row proof.
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
    pub rd0_bit: u32,
    pub rd2_bit: u32,
    pub d_bit: u32,
}

/// Coefficient bounds used by the RLK generation circuit.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct RlkGenerationBounds {
    pub r_bound: BigUint,
    pub sk_bound: BigUint,
    pub e0_bound: BigUint,
    pub e2_bound: BigUint,
    pub rd0_bounds: Vec<BigUint>,
    pub rd2_bounds: Vec<BigUint>,
}

/// Prover inputs for one RLK gadget row.
#[derive(serde::Serialize, serde::Deserialize)]
pub struct RlkGenerationInputs {
    pub session_id_hi: u128,
    pub session_id_lo: u128,
    pub party_id: u32,
    pub row_index: u32,
    pub sk: Polynomial,
    pub r: Polynomial,
    pub e0: Polynomial,
    pub e2: Polynomial,
    /// Per-limb quotients of the reduced `d0` identity, `N` coefficients each.
    pub rd0: CrtPolynomial,
    /// Per-limb quotients of the reduced `d2` identity, `N` coefficients each.
    pub rd2: CrtPolynomial,
    pub d0: CrtPolynomial,
    pub d2: CrtPolynomial,
    /// Fixed URS row `d1` in centered circuit form.
    pub urs: CrtPolynomial,
    /// Fixed CRS row `a` in centered circuit form.
    pub crs: CrtPolynomial,
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

        let n = BigUint::from(params.degree());
        let sk_bound = pk_bounds.sk_bound;
        let r_bound = sk_bound.clone();
        let error_bound = pk_bounds.eek_bound;
        // The circuit checks, over the integers and per CRT limb,
        //   d0 = -(d1 * sk mod X^N + 1) + e0 + delta * r  + q_i * rd0
        //   d2 =  (a  * r  mod X^N + 1) + e2 + delta * sk + q_i * rd2
        // with delta in {0, 1}. With qb = (q_i - 1) / 2 and m = max(sk_bound, r_bound):
        // |d| <= qb, |d1|, |a| <= qb (stored centered), so each negacyclic product is at most
        // N * qb * m, |e| <= error_bound and |delta * r|, |delta * sk| <= m. Dividing by q_i bounds
        // `rd`; the `+ 2` keeps one qb of margin, as C1's `r` bound does. Both identities share
        // the same term bounds, so one bound serves `rd0` and `rd2`.
        let m = std::cmp::max(&sk_bound, &r_bound).clone();
        let rd_bounds = params
            .moduli()
            .iter()
            .map(|modulus| {
                let modulus = BigUint::from(*modulus);
                let centered_bound = (&modulus - 1u32) / 2u32;
                ((&n * &m + 2u32) * &centered_bound + &error_bound + &m) / &modulus
            })
            .collect::<Vec<_>>();

        Ok(Self {
            r_bound,
            sk_bound,
            e0_bound: error_bound.clone(),
            e2_bound: error_bound,
            rd0_bounds: rd_bounds.clone(),
            rd2_bounds: rd_bounds,
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

        Ok(Self {
            r_bit: calculate_bit_width(BigInt::from(bounds.r_bound.clone())),
            sk_bit: calculate_bit_width(BigInt::from(bounds.sk_bound.clone())),
            e0_bit: calculate_bit_width(BigInt::from(bounds.e0_bound.clone())),
            e2_bit: calculate_bit_width(BigInt::from(bounds.e2_bound.clone())),
            rd0_bit: max_bit(&bounds.rd0_bounds),
            rd2_bit: max_bit(&bounds.rd2_bounds),
            d_bit: crate::compute_modulus_bit(&params),
        })
    }
}

impl Computation for RlkGenerationInputs {
    type Preset = BfvPreset;
    type Data = RlkGenerationCircuitData;
    type Error = CircuitsErrors;

    fn compute(preset: Self::Preset, data: &Self::Data) -> Result<Self, Self::Error> {
        RlkGenerationAdapter::new(preset)?.row_inputs(data)
    }

    fn to_json(&self) -> serde_json::Result<serde_json::Value> {
        Ok(serde_json::json!({
            "session_id_hi": self.session_id_hi.to_string(),
            "session_id_lo": self.session_id_lo.to_string(),
            "party_id": self.party_id,
            "row_index": self.row_index,
            "sk": polynomial_to_toml_json(&self.sk),
            "r": polynomial_to_toml_json(&self.r),
            "e0": polynomial_to_toml_json(&self.e0),
            "e2": polynomial_to_toml_json(&self.e2),
            "rd0": crt_polynomial_to_toml_json(&self.rd0),
            "rd2": crt_polynomial_to_toml_json(&self.rd2),
            "d0": crt_polynomial_to_toml_json(&self.d0),
            "d2": crt_polynomial_to_toml_json(&self.d2),
            "urs": crt_polynomial_to_toml_json(&self.urs),
            "crs": crt_polynomial_to_toml_json(&self.crs),
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
    let rd0 = crate::utils::join_display(&configs.bounds.rd0_bounds, ", ");
    let rd2 = crate::utils::join_display(&configs.bounds.rd2_bounds, ", ");

    format!(
        r#"use crate::core::threshold::rlk_generation::Configs as RlkGenerationConfigs;

pub global N: u32 = {};
pub global L: u32 = {};
pub global QIS: [Field; L] = [{}];

pub global {prefix}_BIT_R: u32 = {};
pub global {prefix}_BIT_SK: u32 = {};
pub global {prefix}_BIT_E0: u32 = {};
pub global {prefix}_BIT_E2: u32 = {};
pub global {prefix}_BIT_RD0: u32 = {};
pub global {prefix}_BIT_RD2: u32 = {};
pub global {prefix}_BIT_D: u32 = {};

pub global {prefix}_R_BOUND: Field = {};
pub global {prefix}_SK_BOUND: Field = {};
pub global {prefix}_E0_BOUND: Field = {};
pub global {prefix}_E2_BOUND: Field = {};
pub global {prefix}_RD0_BOUNDS: [Field; L] = [{}];
pub global {prefix}_RD2_BOUNDS: [Field; L] = [{}];

pub global {prefix}_CONFIGS: RlkGenerationConfigs<N, L> = RlkGenerationConfigs::new(
    QIS,
    {prefix}_R_BOUND,
    {prefix}_SK_BOUND,
    {prefix}_E0_BOUND,
    {prefix}_E2_BOUND,
    {prefix}_RD0_BOUNDS,
    {prefix}_RD2_BOUNDS,
);
"#,
        configs.n,
        configs.l,
        moduli,
        configs.bits.r_bit,
        configs.bits.sk_bit,
        configs.bits.e0_bit,
        configs.bits.e2_bit,
        configs.bits.rd0_bit,
        configs.bits.rd2_bit,
        configs.bits.d_bit,
        configs.bounds.r_bound,
        configs.bounds.sk_bound,
        configs.bounds.e0_bound,
        configs.bounds.e2_bound,
        rd0,
        rd2,
        prefix = prefix,
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
        validate_fhe_poly_context(d0_component, &self.context, "RLK d0 component")?;
        validate_fhe_poly_context(d2_component, &self.context, "RLK d2 component")?;

        Ok((
            fhe_poly_to_crt_centered_checked(d0_component, &self.moduli, self.degree)?,
            fhe_poly_to_crt_centered_checked(d2_component, &self.moduli, self.degree)?,
        ))
    }

    /// Convert one generated RLK row into Noir circuit inputs.
    pub fn row_data(
        &self,
        committee: CiphernodesCommittee,
        proof_domain: LbfvProofDomainContext,
        party_id: u32,
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

        validate_fhe_poly_context(error_d0, &self.context, "RLK e0 component")?;
        validate_fhe_poly_context(error_d2, &self.context, "RLK e2 component")?;

        let (d0, d2) = self.share_row_components(row_index, share)?;
        let e0_crt = fhe_poly_to_crt_centered_checked(error_d0, &self.moduli, self.degree)?;
        let e2_crt = fhe_poly_to_crt_centered_checked(error_d2, &self.moduli, self.degree)?;
        let sk_crt = fhe_secret_key_to_crt_centered(sk, &self.context, &self.moduli, self.degree)?;
        let r_crt =
            fhe_secret_key_to_crt_centered(&witness.r, &self.context, &self.moduli, self.degree)?;

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

        let mut rd0 = Vec::with_capacity(self.moduli.len());
        let mut rd2 = Vec::with_capacity(self.moduli.len());

        for (i, qi) in self.moduli.iter().enumerate() {
            let (d0_hat, d2_hat) = self.reduced_limb_terms(row, i, &sk, &r, &e0, &e2)?;
            let qi = BigInt::from(*qi);
            rd0.push(exact_quotient(
                &d0.limb(i).sub(&d0_hat),
                &qi,
                "RLK d0 reduced identity",
            )?);
            rd2.push(exact_quotient(
                &d2.limb(i).sub(&d2_hat),
                &qi,
                "RLK d2 reduced identity",
            )?);
        }

        Ok(RlkGenerationCircuitData {
            committee,
            proof_domain,
            party_id,
            row_index,
            sk,
            r,
            e0,
            e2,
            rd0: CrtPolynomial::new(rd0),
            rd2: CrtPolynomial::new(rd2),
            d0,
            d2,
        })
    }

    /// Validate one RLK row and attach the fixed URS and CRS rows the circuit opens.
    pub fn row_inputs(
        &self,
        data: &RlkGenerationCircuitData,
    ) -> Result<RlkGenerationInputs, CircuitsErrors> {
        validate_lbfv_generation_party_id(data.party_id, &data.committee)?;
        let session = lbfv_proof_session(data.proof_domain)?;
        let l = self.moduli.len();
        let n = self.degree;
        let row = usize::try_from(data.row_index)
            .map_err(|_| CircuitsErrors::Other("RLK row index does not fit usize".to_string()))?;
        if row >= self.row_count() {
            return Err(CircuitsErrors::Other(format!(
                "RLK row index {} is out of range for {} rows",
                data.row_index,
                self.row_count()
            )));
        }
        verify_crt_shapes(&[&data.d0, &data.d2], l, n)
            .map_err(|error| CircuitsErrors::Other(format!("RLK CRT shape mismatch: {error}")))?;
        for (name, polynomial) in [("rd0", &data.rd0), ("rd2", &data.rd2)] {
            validate_crt_shape(polynomial, l, n).map_err(|error| {
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

        Ok(RlkGenerationInputs {
            session_id_hi: session.session_id_hi,
            session_id_lo: session.session_id_lo,
            party_id: data.party_id,
            row_index: data.row_index,
            sk: data.sk.clone(),
            r: data.r.clone(),
            e0: data.e0.clone(),
            e2: data.e2.clone(),
            rd0: data.rd0.clone(),
            rd2: data.rd2.clone(),
            d0: data.d0.clone(),
            d2: data.d2.clone(),
            urs: self.d1_rows[row].clone(),
            crs: self.a_rows[row].clone(),
        })
    }

    /// The right-hand sides of both reduced identities at one limb, before the `q_i` quotient:
    ///   `-(d1 * sk mod X^N + 1) + e0 + delta * r` and `(a * r mod X^N + 1) + e2 + delta * sk`
    /// where `delta = (row == limb)` is the row's Garner coefficient reduced modulo `q_limb`.
    fn reduced_limb_terms(
        &self,
        row: usize,
        limb: usize,
        sk: &Polynomial,
        r: &Polynomial,
        e0: &Polynomial,
        e2: &Polynomial,
    ) -> Result<(Polynomial, Polynomial), CircuitsErrors> {
        let mut d0_hat = negacyclic_mul(self.d1_rows[row].limb(limb), sk, self.degree)?
            .neg()
            .add(e0);
        let mut d2_hat = negacyclic_mul(self.a_rows[row].limb(limb), r, self.degree)?.add(e2);
        if row == limb {
            d0_hat = d0_hat.add(r);
            d2_hat = d2_hat.add(sk);
        }
        Ok((d0_hat, d2_hat))
    }

    /// Convert every RLK row and clear the private FHE witness after conversion.
    pub fn all_rows_data(
        &self,
        committee: CiphernodesCommittee,
        proof_domain: LbfvProofDomainContext,
        party_id: u32,
        sk: &SecretKey,
        share: &RelinKeyShare,
        witness: RlkWitness,
    ) -> Result<Vec<RlkGenerationCircuitData>, CircuitsErrors> {
        let witness = RlkWitnessGuard::new(witness);
        (0..self.row_count())
            .map(|row_index| {
                self.row_data(
                    committee.clone(),
                    proof_domain,
                    party_id,
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
            validate_fhe_poly_context(component, &self.context, "public-key CRS component")?;
            let actual = fhe_poly_to_crt_centered_checked(component, &self.moduli, self.degree)?;
            if actual != self.a_rows[row] {
                return Err(CircuitsErrors::Other(format!(
                    "public-key CRS row {row} does not match the RLK CRS"
                )));
            }
        }

        Ok(())
    }

    pub(crate) fn from_rows(
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
            .map(|poly| fhe_poly_to_crt_centered_checked(poly, &moduli, degree))
            .collect::<Result<Vec<_>, _>>()?;
        let a_rows = crp_a
            .to_polys()
            .iter()
            .map(|poly| fhe_poly_to_crt_centered_checked(poly, &moduli, degree))
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
        let adapter = RlkGenerationAdapter::from_rows(&params, &crp_d1, &crp_a)?;
        let witness = RlkWitnessGuard::new(witness);
        adapter.row_data(
            committee,
            sample_lbfv_proof_domain(),
            0,
            row_index,
            &sk,
            &share,
            witness.as_ref(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CiphernodesCommitteeSize;
    use fhe::aggregate::AggregateIter;
    use fhe::bfv::{BfvParametersBuilder, Encoding, Plaintext};
    use fhe::trlbfv::{aggregate_relinearization_key, LBFVPublicKey, PublicKeyShare};
    use fhe_traits::{
        DeserializeParametrized, FheDecoder, FheDecrypter, FheEncoder, FheEncrypter, Serialize,
    };
    use num_traits::Signed;
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
        let cyclotomic = crate::math::cyclotomic_polynomial(params.degree() as u64);

        let rows = adapter.all_rows_data(
            committee,
            sample_lbfv_proof_domain(),
            0,
            &secret_key,
            &share,
            witness,
        )?;
        for (row_index, data) in rows.iter().enumerate() {
            assert_eq!(data.row_index, row_index as u32);
            assert_eq!(data.d0.limbs.len(), params.moduli().len());
            assert_eq!(data.d2.limbs.len(), params.moduli().len());
            assert_eq!(data.rd0.limbs.len(), params.moduli().len());
            assert_eq!(data.rd2.limbs.len(), params.moduli().len());

            for (i, qi) in params.moduli().iter().enumerate() {
                let qi = BigInt::from(*qi);
                let delta = BigInt::from(u8::from(row_index == i));
                assert_eq!(data.rd0.limb(i).coefficients().len(), params.degree());
                assert_eq!(data.rd2.limb(i).coefficients().len(), params.degree());

                // The reduced identities the circuit checks, restated with the generic
                // cyclotomic reduction rather than the fold the witness uses. `d0`/`d2` come from
                // the FHE share, which applies the full Garner coefficient, so this also checks
                // that `delta` reproduces it modulo q_i.
                let d0_expected = adapter.d1_rows[row_index]
                    .limb(i)
                    .mul(&data.sk)
                    .reduce_by_cyclotomic(&cyclotomic)
                    .map_err(|error| CircuitsErrors::Other(error.to_string()))?
                    .neg()
                    .add(&data.e0)
                    .add(&data.r.scalar_mul(&delta))
                    .add(&data.rd0.limb(i).scalar_mul(&qi));
                assert!(data.d0.limb(i).sub(&d0_expected).is_zero());

                let d2_expected = adapter.a_rows[row_index]
                    .limb(i)
                    .mul(&data.r)
                    .reduce_by_cyclotomic(&cyclotomic)
                    .map_err(|error| CircuitsErrors::Other(error.to_string()))?
                    .add(&data.e2)
                    .add(&data.sk.scalar_mul(&delta))
                    .add(&data.rd2.limb(i).scalar_mul(&qi));
                assert!(data.d2.limb(i).sub(&d2_expected).is_zero());
            }
        }

        Ok(())
    }

    #[test]
    fn adapter_rejects_presets_without_lbfv() {
        assert!(RlkGenerationAdapter::new(BfvPreset::SecureThreshold8192).is_err());
    }

    /// The circuit replaces the row's gadget scalar, the Garner coefficient `g_row`, by
    /// `delta = (row == limb)`. That is sound only because `g_row` is the CRT unit vector:
    /// `1 mod q_row` and `0 mod q_j` for every other modulus.
    #[test]
    fn garner_coefficient_is_the_crt_unit_vector() -> Result<(), CircuitsErrors> {
        for preset in [
            BfvPreset::InsecureThresholdLbfv,
            BfvPreset::SecureThreshold16384,
        ] {
            let (params, _) = build_pair_for_preset(preset)
                .map_err(|error| CircuitsErrors::Other(error.to_string()))?;
            let rns = fhe_math::rns::RnsContext::new(params.moduli())
                .map_err(|error| CircuitsErrors::Other(error.to_string()))?;
            for row in 0..params.moduli().len() {
                let garner = rns.get_garner(row).ok_or_else(|| {
                    CircuitsErrors::Other(format!("missing Garner coefficient at index {row}"))
                })?;
                for (limb, modulus) in params.moduli().iter().enumerate() {
                    let expected = BigUint::from(u8::from(row == limb));
                    assert_eq!(
                        garner % BigUint::from(*modulus),
                        expected,
                        "{preset:?}: Garner coefficient {row} mod q_{limb}"
                    );
                }
            }
        }
        Ok(())
    }

    /// The reduced identity needs one quotient bound for both equations, and with the 0/1
    /// gadget scalar it is the same order as the public-key limb's `r` bound, not the product of
    /// a full-width Garner coefficient.
    #[test]
    fn secure_rd_bounds_track_the_public_key_bound() -> Result<(), CircuitsErrors> {
        let preset = BfvPreset::SecureThreshold16384;
        let committee = CiphernodesCommitteeSize::Minimum.values();
        let bounds = RlkGenerationBounds::compute(preset, &committee)?;
        let pk_bounds = crate::threshold::pk_generation::Bounds::compute(preset, &committee)?;
        let pk_r_bounds = crate::threshold::pk_generation::lbfv_limb_quotient_bounds(
            preset,
            &pk_bounds.sk_bound,
            &pk_bounds.eek_bound,
        )?;
        let bits = RlkGenerationBits::compute(preset, &bounds)?;

        assert_eq!(bounds.rd0_bounds, bounds.rd2_bounds);
        for (rlk, pk) in bounds.rd0_bounds.iter().zip(&pk_r_bounds) {
            assert!(rlk >= pk && rlk - pk <= BigUint::from(1u8));
        }
        assert_eq!(bits.rd0_bit, bits.rd2_bit);
        assert!(bits.rd0_bit < 32);
        Ok(())
    }

    /// The circuit range-checks `rd0`/`rd2` against these bounds, so honest diagonal and
    /// off-diagonal limbs must fit them.
    #[test]
    fn sample_quotients_fit_the_limb_bounds() -> Result<(), CircuitsErrors> {
        let preset = BfvPreset::InsecureThresholdLbfv;
        let committee = CiphernodesCommitteeSize::Minimum.values();
        let bounds = RlkGenerationBounds::compute(preset, &committee)?;
        let row = RlkGenerationCircuitData::generate_sample(preset, committee)?;
        let fits = |polynomial: &Polynomial, bound: &BigUint| {
            let bound = BigInt::from(bound.clone());
            polynomial.coefficients().iter().all(|c| c.abs() <= bound)
        };

        let inputs = RlkGenerationInputs::compute(preset, &row)?;
        for (limb_index, (rd0, rd2)) in inputs.rd0.limbs.iter().zip(&inputs.rd2.limbs).enumerate() {
            assert!(fits(rd0, &bounds.rd0_bounds[limb_index]));
            assert!(fits(rd2, &bounds.rd2_bounds[limb_index]));
        }
        Ok(())
    }

    #[test]
    fn standalone_configs_use_derived_rlk_bounds() -> Result<(), CircuitsErrors> {
        let preset = BfvPreset::SecureThreshold16384;
        let committee = CiphernodesCommitteeSize::Minimum.values();
        let configs = RlkGenerationConfigs::compute(preset, &committee)?;
        let noir = generate_configs(&configs);

        assert!(noir.contains("RLK_GENERATION_RD0_BOUNDS"));
        assert!(noir.contains(&configs.bounds.rd0_bounds[0].to_string()));
        Ok(())
    }

    #[test]
    fn row_inputs_carry_the_fixed_urs_and_crs_rows() -> Result<(), CircuitsErrors> {
        let preset = BfvPreset::InsecureThresholdLbfv;
        let committee = CiphernodesCommitteeSize::Minimum.values();
        let adapter = RlkGenerationAdapter::new(preset)?;
        let row_index = 1;
        let mut row =
            RlkGenerationCircuitData::generate_sample_for_row(preset, committee, row_index)?;
        let inputs = adapter.row_inputs(&row)?;

        assert_eq!(inputs.row_index, row_index);
        assert_eq!(inputs.urs, adapter.d1_rows[row_index as usize]);
        assert_eq!(inputs.crs, adapter.a_rows[row_index as usize]);
        assert_eq!(inputs.d0, row.d0);
        let toml = generate_toml(inputs)?;
        for key in ["rd0", "rd2", "d0", "d2", "urs", "crs"] {
            assert!(toml.contains(&format!("[[{key}]]")), "missing {key}");
        }

        row.row_index = adapter.row_count() as u32;
        assert!(adapter.row_inputs(&row).is_err());
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
        let (share, _) = RelinKeyShare::contribution_with_crp_extended(
            &secret_key,
            &crp_d1,
            &crp_a,
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

        let public_key = PublicKeyShare::contribute_with_crp(&secret_key, &crp_a, &mut rng)?;
        let aggregated_public_key: LBFVPublicKey = [public_key].into_iter().aggregate()?;
        let relin_key = aggregate_relinearization_key(&[restored], &aggregated_public_key)?;

        let plaintext = Plaintext::try_encode(&[3u64], Encoding::poly(), &params)?;
        let ciphertext = aggregated_public_key.try_encrypt(&plaintext, &mut rng)?;
        let mut square = &ciphertext * &ciphertext;
        relin_key.relinearizes(&mut square)?;
        let decoded = Vec::<u64>::try_decode(&secret_key.try_decrypt(&square)?, Encoding::poly())?;
        assert_eq!(decoded.first(), Some(&9));

        Ok(())
    }
}
