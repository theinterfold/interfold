// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Conversion of l-BFV public-key rows into Noir witnesses.

use crate::math::{
    cyclotomic_polynomial, decompose_residue, fhe_poly_to_crt_centered_checked,
    fhe_secret_key_to_crt_centered, validate_fhe_poly_context,
};
use crate::utils::verify_crt_shapes;
use crate::{
    crt_polynomial_to_toml_json, polynomial_to_toml_json, Artifacts, CiphernodesCommittee, Circuit,
    CircuitCodegen, CircuitComputation, CircuitsErrors, CodegenToml, Computation,
};
use e3_fhe_params::{build_pair_for_preset, lbfv_crs_seed, BfvPreset};
use e3_polynomial::{CrtPolynomial, Polynomial};
use fhe::bfv::{BfvParameters, CommonRandomPolyVec, SecretKey};
use fhe::trlbfv::PublicKeyShare;
use fhe_math::rq::Context;
use num_bigint::BigInt;
use std::sync::Arc;

/// Row-level l-BFV public-key generation circuit.
#[derive(Debug)]
pub struct LbfvPkGenerationCircuit;

impl Circuit for LbfvPkGenerationCircuit {
    const NAME: &'static str = "lbfv-pk-generation";
    const PREFIX: &'static str = "LBFV_PK_GENERATION";
    const SUPPORTED_PARAMETER: e3_fhe_params::ParameterType =
        e3_fhe_params::ParameterType::THRESHOLD;
    const DKG_INPUT_TYPE: Option<crate::computation::DkgInputType> = None;
}

/// Circuit-ready values for one l-BFV public-key row.
#[derive(Debug, Clone)]
pub struct LbfvPkGenerationCircuitData {
    /// Committee values used by the matching circuit configuration.
    pub committee: CiphernodesCommittee,
    /// Gadget-row index proved by the circuit.
    pub row_index: u32,
    /// Secret-dependent `b` row in centered circuit form.
    pub pk0_share: CrtPolynomial,
    /// Concrete CRS `a` row in centered circuit form.
    pub a: CrtPolynomial,
    /// Error polynomial recovered from `b + a * sk` in the ring.
    pub eek: Polynomial,
    /// Secret-key polynomial in centered circuit form.
    pub sk: Polynomial,
}

/// Computed values for one l-BFV public-key row proof.
pub struct LbfvPkGenerationComputationOutput {
    pub bounds: super::Bounds,
    pub bits: super::Bits,
    pub inputs: LbfvPkGenerationInputs,
}

/// Prover inputs for one l-BFV public-key row.
#[derive(serde::Serialize, serde::Deserialize)]
pub struct LbfvPkGenerationInputs {
    pub row_index: u32,
    pub eek: Polynomial,
    pub sk: Polynomial,
    pub r1is: CrtPolynomial,
    pub r2is: CrtPolynomial,
    pub pk0is: CrtPolynomial,
}

impl CircuitComputation for LbfvPkGenerationCircuit {
    type Preset = BfvPreset;
    type Data = LbfvPkGenerationCircuitData;
    type Output = LbfvPkGenerationComputationOutput;
    type Error = CircuitsErrors;

    fn compute(preset: Self::Preset, data: &Self::Data) -> Result<Self::Output, Self::Error> {
        let bounds = super::Bounds::compute(preset, &data.committee)?;
        let bits = super::Bits::compute(preset, &bounds)?;
        let inputs = LbfvPkGenerationInputs::compute(preset, data)?;
        Ok(LbfvPkGenerationComputationOutput {
            bounds,
            bits,
            inputs,
        })
    }
}

impl Computation for LbfvPkGenerationInputs {
    type Preset = BfvPreset;
    type Data = LbfvPkGenerationCircuitData;
    type Error = CircuitsErrors;

    fn compute(preset: Self::Preset, data: &Self::Data) -> Result<Self, Self::Error> {
        let adapter = LbfvPkGenerationAdapter::new(preset)?;
        let (params, _) = build_pair_for_preset(preset)
            .map_err(|error| CircuitsErrors::Other(error.to_string()))?;
        compute_inputs(&params, &adapter, data)
    }

    fn to_json(&self) -> serde_json::Result<serde_json::Value> {
        Ok(serde_json::json!({
            "row_index": self.row_index,
            "eek": polynomial_to_toml_json(&self.eek),
            "sk": polynomial_to_toml_json(&self.sk),
            "r1is": crt_polynomial_to_toml_json(&self.r1is),
            "r2is": crt_polynomial_to_toml_json(&self.r2is),
            "pk0is": crt_polynomial_to_toml_json(&self.pk0is),
        }))
    }
}

fn compute_inputs(
    params: &BfvParameters,
    adapter: &LbfvPkGenerationAdapter,
    data: &LbfvPkGenerationCircuitData,
) -> Result<LbfvPkGenerationInputs, CircuitsErrors> {
    if adapter.crs_row(data.row_index)? != data.a {
        return Err(CircuitsErrors::Other(
            "l-BFV public-key row does not match the fixed CRS".to_string(),
        ));
    }

    let l = params.moduli().len();
    let n = params.degree();
    verify_crt_shapes(&[&data.pk0_share, &data.a], l, n).map_err(|error| {
        CircuitsErrors::Other(format!("l-BFV public-key CRT shape mismatch: {error}"))
    })?;
    for (name, polynomial) in [("eek", &data.eek), ("sk", &data.sk)] {
        if polynomial.coefficients().len() != n {
            return Err(CircuitsErrors::Other(format!(
                "l-BFV public-key {name} has {} coefficients; expected {n}",
                polynomial.coefficients().len()
            )));
        }
    }

    let cyclotomic = cyclotomic_polynomial(n as u64);
    let mut r1is = Vec::with_capacity(l);
    let mut r2is = Vec::with_capacity(l);
    for (index, modulus) in params.moduli().iter().enumerate() {
        let expected = data.a.limb(index).neg().mul(&data.sk).add(&data.eek);
        let (r1, r2) = decompose_residue(
            data.pk0_share.limb(index),
            &expected,
            &BigInt::from(*modulus),
            &cyclotomic,
            n as u64,
        );
        r1is.push(r1);
        r2is.push(r2);
    }

    Ok(LbfvPkGenerationInputs {
        row_index: data.row_index,
        eek: data.eek.clone(),
        sk: data.sk.clone(),
        r1is: CrtPolynomial::new(r1is),
        r2is: CrtPolynomial::new(r2is),
        pk0is: data.pk0_share.clone(),
    })
}

impl CircuitCodegen for LbfvPkGenerationCircuit {
    type Preset = BfvPreset;
    type Data = LbfvPkGenerationCircuitData;
    type Error = CircuitsErrors;

    fn codegen(&self, preset: Self::Preset, data: &Self::Data) -> Result<Artifacts, Self::Error> {
        let inputs = LbfvPkGenerationInputs::compute(preset, data)?;
        let configs = super::Configs::compute(preset, &data.committee)?;
        Ok(Artifacts {
            toml: generate_lbfv_pk_toml(inputs)?,
            configs: super::codegen::generate_configs(preset, &configs)?,
        })
    }
}

/// Serialize one l-BFV public-key row as `Prover.toml`.
pub fn generate_lbfv_pk_toml(
    inputs: LbfvPkGenerationInputs,
) -> Result<CodegenToml, CircuitsErrors> {
    Ok(toml::to_string(&inputs.to_json()?)?)
}

/// Converts a concrete l-BFV public-key share into row-level circuit inputs.
pub struct LbfvPkGenerationAdapter {
    context: Arc<Context>,
    moduli: Vec<u64>,
    degree: usize,
    a_rows: Vec<CrtPolynomial>,
    cyclotomic: Vec<BigInt>,
}

impl LbfvPkGenerationAdapter {
    /// Build an adapter for a preset with an enabled l-BFV public-key path.
    pub fn new(preset: BfvPreset) -> Result<Self, CircuitsErrors> {
        let (params, _) = build_pair_for_preset(preset)
            .map_err(|error| CircuitsErrors::Other(error.to_string()))?;
        let crs_seed = lbfv_crs_seed(preset).ok_or_else(|| {
            CircuitsErrors::Other(format!("l-BFV CRS is not enabled for {preset:?}"))
        })?;
        let crp = CommonRandomPolyVec::from_seed(&params, crs_seed)?;

        Self::from_crp(&params, &crp)
    }

    /// Number of fixed l-BFV public-key rows.
    #[must_use]
    pub fn row_count(&self) -> usize {
        self.a_rows.len()
    }

    /// Return one fixed l-BFV CRS row in circuit representation.
    pub fn crs_row(&self, row_index: u32) -> Result<CrtPolynomial, CircuitsErrors> {
        let row = usize::try_from(row_index)
            .map_err(|_| CircuitsErrors::Other("l-BFV row index does not fit usize".to_string()))?;
        self.a_rows.get(row).cloned().ok_or_else(|| {
            CircuitsErrors::Other(format!(
                "l-BFV row index {row_index} is out of range for {} rows",
                self.row_count()
            ))
        })
    }

    /// Convert one concrete public-key row into circuit inputs.
    pub fn row_data(
        &self,
        committee: CiphernodesCommittee,
        row_index: u32,
        secret_key: &SecretKey,
        public_key: &PublicKeyShare,
    ) -> Result<LbfvPkGenerationCircuitData, CircuitsErrors> {
        let (a, pk0_share) = self.share_row_components(row_index, public_key)?;

        let sk_crt =
            fhe_secret_key_to_crt_centered(secret_key, &self.context, &self.moduli, self.degree)?;
        verify_crt_shapes(&[&a, &pk0_share, &sk_crt], self.moduli.len(), self.degree)
            .map_err(|error| CircuitsErrors::Other(format!("l-BFV CRT shape mismatch: {error}")))?;

        let sk = sk_crt.limb(0).clone();
        if sk_crt.limbs.iter().any(|limb| limb != &sk) {
            return Err(CircuitsErrors::Other(
                "secret-key CRT limbs do not represent one common polynomial".to_string(),
            ));
        }

        let mut eek_limbs = Vec::with_capacity(self.moduli.len());
        for (index, qi) in self.moduli.iter().enumerate() {
            let product = a
                .limb(index)
                .mul(&sk)
                .reduce_by_cyclotomic(&self.cyclotomic)
                .map_err(|error| CircuitsErrors::Other(error.to_string()))?;
            let mut eek = pk0_share.limb(index).add(&product);
            eek.reduce(&BigInt::from(*qi));
            eek.center(&BigInt::from(*qi));
            eek_limbs.push(eek);
        }

        let eek = eek_limbs.first().cloned().ok_or_else(|| {
            CircuitsErrors::Other("l-BFV public key has no CRT limbs".to_string())
        })?;
        if eek_limbs.iter().any(|limb| limb != &eek) {
            return Err(CircuitsErrors::Other(
                "l-BFV public-key errors differ across CRT limbs".to_string(),
            ));
        }

        Ok(LbfvPkGenerationCircuitData {
            committee,
            row_index,
            pk0_share,
            a,
            eek,
            sk,
        })
    }

    /// Extract one centered public-key row after validating all fixed CRS rows.
    pub fn share_row_components(
        &self,
        row_index: u32,
        public_key: &PublicKeyShare,
    ) -> Result<(CrtPolynomial, CrtPolynomial), CircuitsErrors> {
        let row = usize::try_from(row_index)
            .map_err(|_| CircuitsErrors::Other("l-BFV row index does not fit usize".to_string()))?;
        if row >= self.row_count() {
            return Err(CircuitsErrors::Other(format!(
                "l-BFV row index {row_index} is out of range for {} rows",
                self.row_count()
            )));
        }

        let a_components = public_key.a_components()?;
        let b_components = public_key.b_components()?;
        if a_components.len() != self.row_count() || b_components.len() != self.row_count() {
            return Err(CircuitsErrors::Other(format!(
                "public-key row counts must equal {}",
                self.row_count()
            )));
        }

        let mut selected = None;
        for (index, (a_component, b_component)) in
            a_components.iter().zip(b_components.iter()).enumerate()
        {
            validate_fhe_poly_context(a_component, &self.context, "l-BFV public-key a component")?;
            validate_fhe_poly_context(b_component, &self.context, "l-BFV public-key b component")?;

            let a = fhe_poly_to_crt_centered_checked(a_component, &self.moduli, self.degree)?;
            if a != self.a_rows[index] {
                return Err(CircuitsErrors::Other(format!(
                    "public-key CRS row {index} does not match the fixed l-BFV CRS"
                )));
            }
            if index == row {
                selected = Some((
                    a,
                    fhe_poly_to_crt_centered_checked(b_component, &self.moduli, self.degree)?,
                ));
            }
        }

        selected.ok_or_else(|| {
            CircuitsErrors::Other(format!("l-BFV public-key row {row_index} is missing"))
        })
    }

    fn from_crp(
        params: &Arc<BfvParameters>,
        crp: &CommonRandomPolyVec,
    ) -> Result<Self, CircuitsErrors> {
        let moduli = params.moduli().to_vec();
        let degree = params.degree();
        let rows = crp.to_polys();
        if rows.len() != moduli.len() {
            return Err(CircuitsErrors::Other(format!(
                "l-BFV CRS row count {} does not match modulus count {}",
                rows.len(),
                moduli.len()
            )));
        }

        let a_rows = rows
            .iter()
            .map(|row| fhe_poly_to_crt_centered_checked(row, &moduli, degree))
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Self {
            context: params
                .context_at_level(0)
                .map_err(|error| CircuitsErrors::Other(error.to_string()))?
                .clone(),
            moduli,
            degree,
            a_rows,
            cyclotomic: cyclotomic_polynomial(degree as u64),
        })
    }
}

impl LbfvPkGenerationCircuitData {
    /// Generate row zero for codegen and prover tests.
    pub fn generate_sample(
        preset: BfvPreset,
        committee: CiphernodesCommittee,
    ) -> Result<Self, CircuitsErrors> {
        Self::generate_sample_for_row(preset, committee, 0)
    }

    /// Generate one valid l-BFV public-key row for codegen and prover tests.
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
        let crp = CommonRandomPolyVec::from_seed(&params, crs_seed)?;
        let mut rng = rand::rng();
        let secret_key = SecretKey::random(&params, &mut rng);
        let public_key = PublicKeyShare::contribute_with_crp(&secret_key, &crp, &mut rng)?;
        let adapter = LbfvPkGenerationAdapter::from_crp(&params, &crp)?;
        adapter.row_data(committee, row_index, &secret_key, &public_key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CiphernodesCommitteeSize;
    use fhe::bfv::BfvParametersBuilder;
    use rand::rng;

    #[test]
    fn row_data_reconstructs_lbfv_public_key_rows() -> Result<(), CircuitsErrors> {
        let mut rng = rng();
        let params = BfvParametersBuilder::new()
            .set_degree(8)
            .set_plaintext_modulus(1153)
            .set_moduli_sizes(&[62; 6])
            .build_arc()
            .map_err(|error| CircuitsErrors::Other(error.to_string()))?;
        let crp = CommonRandomPolyVec::new(&params, &mut rng)?;
        let adapter = LbfvPkGenerationAdapter::from_crp(&params, &crp)?;
        let secret_key = SecretKey::random(&params, &mut rng);
        let public_key = PublicKeyShare::contribute_with_crp(&secret_key, &crp, &mut rng)?;
        let committee = CiphernodesCommitteeSize::Minimum.values();
        let mut first_sk = None;

        for row_index in 0..adapter.row_count() {
            let data = adapter.row_data(
                committee.clone(),
                row_index as u32,
                &secret_key,
                &public_key,
            )?;
            assert_eq!(data.row_index, row_index as u32);
            assert_eq!(adapter.crs_row(row_index as u32)?, data.a);
            assert_eq!(data.pk0_share.limbs.len(), params.moduli().len());
            assert_eq!(data.a.limbs.len(), params.moduli().len());
            assert_eq!(data.eek.coefficients().len(), params.degree());
            assert_eq!(data.sk.coefficients().len(), params.degree());
            let inputs = compute_inputs(&params, &adapter, &data)?;
            assert_eq!(inputs.row_index, row_index as u32);
            if let Some(expected_sk) = &first_sk {
                assert_eq!(&data.sk, expected_sk);
            } else {
                first_sk = Some(data.sk.clone());
            }

            for (index, qi) in params.moduli().iter().enumerate() {
                let product = data
                    .a
                    .limb(index)
                    .mul(&data.sk)
                    .reduce_by_cyclotomic(&adapter.cyclotomic)
                    .map_err(|error| CircuitsErrors::Other(error.to_string()))?;
                let mut expected = data.eek.sub(&product);
                expected.reduce(&BigInt::from(*qi));
                expected.center(&BigInt::from(*qi));
                assert_eq!(&expected, data.pk0_share.limb(index));

                let expected_hat = data.a.limb(index).neg().mul(&data.sk).add(&data.eek);
                let (expected_r1, expected_r2) = decompose_residue(
                    data.pk0_share.limb(index),
                    &expected_hat,
                    &BigInt::from(*qi),
                    &adapter.cyclotomic,
                    params.degree() as u64,
                );
                assert_eq!(&expected_r1, inputs.r1is.limb(index));
                assert_eq!(&expected_r2, inputs.r2is.limb(index));
            }
        }

        let mut mismatched = adapter.row_data(committee, 0, &secret_key, &public_key)?;
        mismatched.a = adapter.crs_row(1)?;
        assert!(compute_inputs(&params, &adapter, &mismatched).is_err());

        Ok(())
    }

    #[test]
    fn row_data_rejects_a_row_from_another_crs() -> Result<(), CircuitsErrors> {
        let mut rng = rng();
        let params = BfvParametersBuilder::new()
            .set_degree(8)
            .set_plaintext_modulus(1153)
            .set_moduli_sizes(&[62; 6])
            .build_arc()
            .map_err(|error| CircuitsErrors::Other(error.to_string()))?;
        let crp = CommonRandomPolyVec::new(&params, &mut rng)?;
        let other_crp = CommonRandomPolyVec::new(&params, &mut rng)?;
        let adapter = LbfvPkGenerationAdapter::from_crp(&params, &crp)?;
        let secret_key = SecretKey::random(&params, &mut rng);
        let public_key = PublicKeyShare::contribute_with_crp(&secret_key, &other_crp, &mut rng)?;

        assert!(adapter
            .row_data(
                CiphernodesCommitteeSize::Minimum.values(),
                0,
                &secret_key,
                &public_key,
            )
            .is_err());
        Ok(())
    }

    #[test]
    fn compute_inputs_accepts_zero_quotients() -> Result<(), CircuitsErrors> {
        let mut rng = rng();
        let params = BfvParametersBuilder::new()
            .set_degree(8)
            .set_plaintext_modulus(1153)
            .set_moduli_sizes(&[62; 6])
            .build_arc()
            .map_err(|error| CircuitsErrors::Other(error.to_string()))?;
        let crp = CommonRandomPolyVec::new(&params, &mut rng)?;
        let adapter = LbfvPkGenerationAdapter::from_crp(&params, &crp)?;
        let degree = params.degree();
        let data = LbfvPkGenerationCircuitData {
            committee: CiphernodesCommitteeSize::Minimum.values(),
            row_index: 0,
            pk0_share: CrtPolynomial::new(
                params
                    .moduli()
                    .iter()
                    .map(|_| Polynomial::zero(degree - 1))
                    .collect(),
            ),
            a: adapter.crs_row(0)?,
            eek: Polynomial::zero(degree - 1),
            sk: Polynomial::zero(degree - 1),
        };

        let inputs = compute_inputs(&params, &adapter, &data)?;

        assert!(inputs.r1is.limbs.iter().all(Polynomial::is_zero));
        assert!(inputs.r2is.limbs.iter().all(Polynomial::is_zero));
        assert!(inputs
            .r1is
            .limbs
            .iter()
            .all(|polynomial| polynomial.degree() == 2 * (degree - 1)));
        assert!(inputs
            .r2is
            .limbs
            .iter()
            .all(|polynomial| polynomial.degree() == degree - 2));
        Ok(())
    }
}
