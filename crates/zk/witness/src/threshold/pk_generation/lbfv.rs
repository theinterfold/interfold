// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Conversion of l-BFV public-key rows into Noir witnesses.

use crate::encoding::verify_crt_shapes;
use crate::encoding::{crt_polynomial_to_toml_json, polynomial_to_toml_json};
use crate::encoding::{
    fhe_poly_to_crt_centered_checked, fhe_secret_key_to_crt_centered, validate_fhe_poly_context,
};
use crate::negacyclic::{exact_quotient, negacyclic_mul};
use crate::threshold::lbfv_proof_domain::{lbfv_proof_session, validate_lbfv_generation_party_id};
use crate::WitnessError;
use e3_committee::CiphernodesCommittee;
use e3_committee_hash::LbfvProofDomainContext;
use e3_fhe_params::{lbfv_crs_seed, BfvPreset};
use e3_polynomial::{CrtPolynomial, Polynomial};
use fhe::bfv::{BfvParameters, CommonRandomPolyVec, SecretKey};
use fhe::trlbfv::PublicKeyShare;
use fhe_math::rq::Context;
use num_bigint::BigInt;
use std::sync::Arc;

use e3_zk_config::threshold::pk_generation::Configs;
pub struct LbfvPkGenerationCircuitData {
    /// Committee values used by the matching circuit configuration.
    pub committee: CiphernodesCommittee,
    /// Protocol context used to derive the public proof-session identifier.
    pub proof_domain: LbfvProofDomainContext,
    /// Zero-based party ID in the finalized committee.
    pub party_id: u32,
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
#[derive(serde::Serialize, serde::Deserialize)]
pub struct LbfvPkGenerationInputs {
    pub session_id_hi: u128,
    pub session_id_lo: u128,
    pub party_id: u32,
    pub row_index: u32,
    pub eek: Polynomial,
    pub sk: Polynomial,
    /// Per-limb quotients of the reduced identity, `N` coefficients each.
    pub ris: CrtPolynomial,
    pub pk0is: CrtPolynomial,
    /// Fixed CRS row `a` in centered circuit form.
    pub crs: CrtPolynomial,
}
impl LbfvPkGenerationInputs {
    pub fn compute(
        config: &Configs,
        data: &LbfvPkGenerationCircuitData,
    ) -> Result<Self, WitnessError> {
        crate::validation::committee(config.committee, &data.committee)?;
        let adapter = LbfvPkGenerationAdapter::from_config(config)?;
        let params = &config.params;
        compute_inputs(&params, &adapter, data)
    }

    pub fn to_json(&self) -> serde_json::Result<serde_json::Value> {
        Ok(serde_json::json!({
            "session_id_hi": self.session_id_hi.to_string(),
            "session_id_lo": self.session_id_lo.to_string(),
            "party_id": self.party_id,
            "row_index": self.row_index,
            "eek": polynomial_to_toml_json(&self.eek),
            "sk": polynomial_to_toml_json(&self.sk),
            "ris": crt_polynomial_to_toml_json(&self.ris),
            "pk0is": crt_polynomial_to_toml_json(&self.pk0is),
            "crs": crt_polynomial_to_toml_json(&self.crs),
        }))
    }
}
fn compute_inputs(
    params: &BfvParameters,
    adapter: &LbfvPkGenerationAdapter,
    data: &LbfvPkGenerationCircuitData,
) -> Result<LbfvPkGenerationInputs, WitnessError> {
    validate_lbfv_generation_party_id(data.party_id, &data.committee)?;
    let session = lbfv_proof_session(data.proof_domain)?;
    let crs = adapter.crs_row(data.row_index)?;
    if crs != data.a {
        return Err(WitnessError::Other(
            "l-BFV public-key row does not match the fixed CRS".to_string(),
        ));
    }

    let l = params.moduli().len();
    let n = params.degree();
    verify_crt_shapes(&[&data.pk0_share, &data.a], l, n).map_err(|error| {
        WitnessError::Other(format!("l-BFV public-key CRT shape mismatch: {error}"))
    })?;
    for (name, polynomial) in [("eek", &data.eek), ("sk", &data.sk)] {
        if polynomial.coefficients().len() != n {
            return Err(WitnessError::Other(format!(
                "l-BFV public-key {name} has {} coefficients; expected {n}",
                polynomial.coefficients().len()
            )));
        }
    }

    // The circuit checks, per limb, `pk0 == -(a * sk mod X^N + 1) + eek + q_i * r` over the integers,
    // so `r` is the exact quotient of `pk0` minus the reduced right-hand side.
    let mut ris = Vec::with_capacity(l);
    for (index, modulus) in params.moduli().iter().enumerate() {
        let modulus = BigInt::from(*modulus);
        let reduced = negacyclic_mul(data.a.limb(index), &data.sk, n)?
            .neg()
            .add(&data.eek);
        let mut expected_residue = reduced.clone();
        expected_residue.reduce(&modulus);
        expected_residue.center(&modulus);
        if data.pk0_share.limb(index) != &expected_residue {
            return Err(WitnessError::Other(format!(
                "l-BFV public-key residue mismatch at CRT limb {index}"
            )));
        }
        ris.push(exact_quotient(
            &data.pk0_share.limb(index).sub(&reduced),
            &modulus,
            "l-BFV public-key reduced identity",
        )?);
    }

    Ok(LbfvPkGenerationInputs {
        session_id_hi: session.session_id_hi,
        session_id_lo: session.session_id_lo,
        party_id: data.party_id,
        row_index: data.row_index,
        eek: data.eek.clone(),
        sk: data.sk.clone(),
        ris: CrtPolynomial::new(ris),
        pk0is: data.pk0_share.clone(),
        crs,
    })
}
pub struct LbfvPkGenerationAdapter {
    context: Arc<Context>,
    moduli: Vec<u64>,
    degree: usize,
    a_rows: Vec<CrtPolynomial>,
}

impl LbfvPkGenerationAdapter {
    /// Build an adapter for a preset with an enabled l-BFV public-key path.
    pub fn from_config(config: &Configs) -> Result<Self, WitnessError> {
        Self::from_parameters(config.preset, &config.params)
    }
    pub(crate) fn from_parameters(
        preset: BfvPreset,
        params: &Arc<BfvParameters>,
    ) -> Result<Self, WitnessError> {
        let crs_seed = lbfv_crs_seed(preset).ok_or_else(|| {
            WitnessError::Other(format!("l-BFV CRS is not enabled for {preset:?}"))
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
    pub fn crs_row(&self, row_index: u32) -> Result<CrtPolynomial, WitnessError> {
        let row = usize::try_from(row_index)
            .map_err(|_| WitnessError::Other("l-BFV row index does not fit usize".to_string()))?;
        self.a_rows.get(row).cloned().ok_or_else(|| {
            WitnessError::Other(format!(
                "l-BFV row index {row_index} is out of range for {} rows",
                self.row_count()
            ))
        })
    }

    /// Convert one concrete public-key row into circuit inputs.
    pub fn row_data(
        &self,
        committee: CiphernodesCommittee,
        proof_domain: LbfvProofDomainContext,
        party_id: u32,
        row_index: u32,
        secret_key: &SecretKey,
        public_key: &PublicKeyShare,
    ) -> Result<LbfvPkGenerationCircuitData, WitnessError> {
        let (a, pk0_share) = self.share_row_components(row_index, public_key)?;

        let sk_crt =
            fhe_secret_key_to_crt_centered(secret_key, &self.context, &self.moduli, self.degree)?;
        verify_crt_shapes(&[&a, &pk0_share, &sk_crt], self.moduli.len(), self.degree)
            .map_err(|error| WitnessError::Other(format!("l-BFV CRT shape mismatch: {error}")))?;

        let sk = sk_crt.limb(0).clone();
        if sk_crt.limbs.iter().any(|limb| limb != &sk) {
            return Err(WitnessError::Other(
                "secret-key CRT limbs do not represent one common polynomial".to_string(),
            ));
        }

        let mut eek_limbs = Vec::with_capacity(self.moduli.len());
        for (index, qi) in self.moduli.iter().enumerate() {
            let product = negacyclic_mul(a.limb(index), &sk, self.degree)?;
            let mut eek = pk0_share.limb(index).add(&product);
            eek.reduce(&BigInt::from(*qi));
            eek.center(&BigInt::from(*qi));
            eek_limbs.push(eek);
        }

        let eek = eek_limbs
            .first()
            .cloned()
            .ok_or_else(|| WitnessError::Other("l-BFV public key has no CRT limbs".to_string()))?;
        if eek_limbs.iter().any(|limb| limb != &eek) {
            return Err(WitnessError::Other(
                "l-BFV public-key errors differ across CRT limbs".to_string(),
            ));
        }

        Ok(LbfvPkGenerationCircuitData {
            committee,
            proof_domain,
            party_id,
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
    ) -> Result<(CrtPolynomial, CrtPolynomial), WitnessError> {
        let row = usize::try_from(row_index)
            .map_err(|_| WitnessError::Other("l-BFV row index does not fit usize".to_string()))?;
        if row >= self.row_count() {
            return Err(WitnessError::Other(format!(
                "l-BFV row index {row_index} is out of range for {} rows",
                self.row_count()
            )));
        }

        let a_components = public_key.a_components()?;
        let b_components = public_key.b_components()?;
        if a_components.len() != self.row_count() || b_components.len() != self.row_count() {
            return Err(WitnessError::Other(format!(
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
                return Err(WitnessError::Other(format!(
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
            WitnessError::Other(format!("l-BFV public-key row {row_index} is missing"))
        })
    }

    pub fn from_crp(
        params: &Arc<BfvParameters>,
        crp: &CommonRandomPolyVec,
    ) -> Result<Self, WitnessError> {
        let moduli = params.moduli().to_vec();
        let degree = params.degree();
        let rows = crp.to_polys();
        if rows.len() != moduli.len() {
            return Err(WitnessError::Other(format!(
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
                .map_err(|error| WitnessError::Other(error.to_string()))?
                .clone(),
            moduli,
            degree,
            a_rows,
        })
    }
}

#[cfg(test)]
mod tests {

    use e3_zk_samples::lbfv_proof_domain::sample_lbfv_proof_domain;
    use fhe::bfv::{CommonRandomPolyVec, SecretKey};

    use super::*;
    use e3_committee::CiphernodesCommitteeSize;
    use fhe::bfv::BfvParametersBuilder;

    use rand::rng;

    #[test]
    fn row_data_reconstructs_lbfv_public_key_rows() -> Result<(), WitnessError> {
        let mut rng = rng();
        let params = BfvParametersBuilder::new()
            .set_degree(8)
            .set_plaintext_modulus(1153)
            .set_moduli_sizes(&[62; 6])
            .build_arc()
            .map_err(|error| WitnessError::Other(error.to_string()))?;
        let crp = CommonRandomPolyVec::new(&params, &mut rng)?;
        let adapter = LbfvPkGenerationAdapter::from_crp(&params, &crp)?;
        let secret_key = SecretKey::random(&params, &mut rng);
        let public_key = PublicKeyShare::contribute_with_crp(&secret_key, &crp, &mut rng)?;
        let committee = CiphernodesCommitteeSize::Minimum.values();
        let mut first_sk = None;

        for row_index in 0..adapter.row_count() {
            let data = adapter.row_data(
                committee.clone(),
                sample_lbfv_proof_domain(),
                0,
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
            assert_eq!(inputs.crs, data.a);
            if let Some(expected_sk) = &first_sk {
                assert_eq!(&data.sk, expected_sk);
            } else {
                first_sk = Some(data.sk.clone());
            }

            for (index, qi) in params.moduli().iter().enumerate() {
                let product = crate::negacyclic::reduce_reference(
                    &data.a.limb(index).mul(&data.sk),
                    params.degree(),
                );
                let mut expected = data.eek.sub(&product);
                expected.reduce(&BigInt::from(*qi));
                expected.center(&BigInt::from(*qi));
                assert_eq!(&expected, data.pk0_share.limb(index));

                // The reduced identity the circuit checks, restated with the generic
                // cyclotomic reduction rather than the fold the witness uses.
                let r = inputs.ris.limb(index);
                assert_eq!(r.coefficients().len(), params.degree());
                let restated = data
                    .eek
                    .sub(&product)
                    .add(&r.scalar_mul(&BigInt::from(*qi)));
                assert!(data.pk0_share.limb(index).sub(&restated).is_zero());
            }
        }

        let mut mismatched = adapter.row_data(
            committee,
            sample_lbfv_proof_domain(),
            0,
            0,
            &secret_key,
            &public_key,
        )?;
        mismatched.a = adapter.crs_row(1)?;
        assert!(compute_inputs(&params, &adapter, &mismatched).is_err());

        let mut inconsistent = adapter.row_data(
            CiphernodesCommitteeSize::Minimum.values(),
            sample_lbfv_proof_domain(),
            0,
            0,
            &secret_key,
            &public_key,
        )?;
        let mut coefficients = inconsistent.pk0_share.limb(0).coefficients().to_vec();
        coefficients[0] += 1;
        inconsistent.pk0_share.limbs[0] = Polynomial::new(coefficients);
        let error = compute_inputs(&params, &adapter, &inconsistent)
            .err()
            .expect("an inconsistent CRT residue must fail");
        assert!(error
            .to_string()
            .contains("l-BFV public-key residue mismatch at CRT limb 0"));

        Ok(())
    }

    #[test]
    fn row_data_rejects_a_row_from_another_crs() -> Result<(), WitnessError> {
        let mut rng = rng();
        let params = BfvParametersBuilder::new()
            .set_degree(8)
            .set_plaintext_modulus(1153)
            .set_moduli_sizes(&[62; 6])
            .build_arc()
            .map_err(|error| WitnessError::Other(error.to_string()))?;
        let crp = CommonRandomPolyVec::new(&params, &mut rng)?;
        let other_crp = CommonRandomPolyVec::new(&params, &mut rng)?;
        let adapter = LbfvPkGenerationAdapter::from_crp(&params, &crp)?;
        let secret_key = SecretKey::random(&params, &mut rng);
        let public_key = PublicKeyShare::contribute_with_crp(&secret_key, &other_crp, &mut rng)?;

        assert!(adapter
            .row_data(
                CiphernodesCommitteeSize::Minimum.values(),
                sample_lbfv_proof_domain(),
                0,
                0,
                &secret_key,
                &public_key,
            )
            .is_err());
        Ok(())
    }

    #[test]
    fn compute_inputs_accepts_zero_quotients() -> Result<(), WitnessError> {
        let mut rng = rng();
        let params = BfvParametersBuilder::new()
            .set_degree(8)
            .set_plaintext_modulus(1153)
            .set_moduli_sizes(&[62; 6])
            .build_arc()
            .map_err(|error| WitnessError::Other(error.to_string()))?;
        let crp = CommonRandomPolyVec::new(&params, &mut rng)?;
        let adapter = LbfvPkGenerationAdapter::from_crp(&params, &crp)?;
        let degree = params.degree();
        let data = LbfvPkGenerationCircuitData {
            committee: CiphernodesCommitteeSize::Minimum.values(),
            proof_domain: sample_lbfv_proof_domain(),
            party_id: 0,
            row_index: 0,
            pk0_share: CrtPolynomial::new(
                params
                    .moduli()
                    .iter()
                    .map(|_| Polynomial::new(vec![BigInt::from(0); degree]))
                    .collect(),
            ),
            a: adapter.crs_row(0)?,
            eek: Polynomial::new(vec![BigInt::from(0); degree]),
            sk: Polynomial::new(vec![BigInt::from(0); degree]),
        };

        let inputs = compute_inputs(&params, &adapter, &data)?;

        assert!(inputs.ris.limbs.iter().all(Polynomial::is_zero));
        assert!(inputs
            .ris
            .limbs
            .iter()
            .all(|polynomial| polynomial.coefficients().len() == degree));
        Ok(())
    }
}
