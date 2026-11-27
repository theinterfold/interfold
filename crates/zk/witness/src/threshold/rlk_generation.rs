// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Conversion of l-BFV relinearization-key rows into Noir witnesses.

use crate::encoding::{crt_polynomial_to_toml_json, polynomial_to_toml_json};
use crate::encoding::{
    fhe_poly_to_crt_centered_checked, fhe_secret_key_to_crt_centered, validate_fhe_poly_context,
};
use crate::negacyclic::negacyclic_mul_exact;
use crate::threshold::lbfv_proof_domain::{lbfv_proof_session, validate_lbfv_generation_party_id};
use crate::WitnessError;
use e3_committee::CiphernodesCommittee;
use e3_committee_hash::LbfvProofDomainContext;
use e3_fhe_params::{lbfv_crs_seed, lbfv_urs_seed, BfvPreset};
use e3_polynomial::{CrtPolynomial, Polynomial};
use e3_zk_config::threshold::rlk_generation::RlkGenerationConfigs;
use fhe::bfv::{BfvParameters, CommonRandomPolyVec, SecretKey};
use fhe::trlbfv::{RelinKeyShare, RelinKeyWitness};
use fhe_math::rq::Context;
use num_bigint::BigInt;
use std::sync::Arc;

/// Witness data for one l-BFV relinearization-key row proof.
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

/// Noir inputs of one l-BFV relinearization-key row proof.
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

impl RlkGenerationInputs {
    pub fn compute(
        config: &RlkGenerationConfigs,
        data: &RlkGenerationCircuitData,
    ) -> Result<Self, WitnessError> {
        crate::validation::committee(config.committee, &data.committee)?;
        RlkGenerationAdapter::from_config(config)?.row_inputs(data)
    }

    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
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
        })
    }
}

/// Converts l-BFV relinearization-key shares to circuit rows against the preset's fixed URS and CRS.
pub struct RlkGenerationAdapter {
    params: Arc<BfvParameters>,
    context: Arc<Context>,
    d1_rows: Vec<CrtPolynomial>,
    a_rows: Vec<CrtPolynomial>,
}

impl RlkGenerationAdapter {
    /// Build an adapter for a preset with an enabled l-BFV RLK path.
    pub fn from_config(config: &RlkGenerationConfigs) -> Result<Self, WitnessError> {
        Self::from_parameters(config.preset, &config.params)
    }

    pub(crate) fn from_parameters(
        preset: BfvPreset,
        params: &Arc<BfvParameters>,
    ) -> Result<Self, WitnessError> {
        let crs_seed = lbfv_crs_seed(preset).ok_or_else(|| {
            WitnessError::Other(format!("l-BFV CRS is not enabled for {preset:?}"))
        })?;
        let urs_seed = lbfv_urs_seed(preset).ok_or_else(|| {
            WitnessError::Other(format!("l-BFV URS is not enabled for {preset:?}"))
        })?;
        let crp_d1 = CommonRandomPolyVec::from_seed(params, urs_seed)?;
        let crp_a = CommonRandomPolyVec::from_seed(params, crs_seed)?;

        Self::from_rows(params, &crp_d1, &crp_a)
    }

    /// Number of gadget rows in the canonical l-BFV key-switching vectors.
    #[must_use]
    pub fn row_count(&self) -> usize {
        self.d1_rows.len()
    }

    /// Convert one public RLK share row to the circuit's centered CRT representation.
    ///
    /// The share must carry the fixed URS and CRS: a peer share whose `d1` or `a` rows differ makes
    /// RLK aggregation fail after all of its proofs verified.
    pub fn share_row_components(
        &self,
        row_index: u32,
        share: &RelinKeyShare,
    ) -> Result<(CrtPolynomial, CrtPolynomial), WitnessError> {
        let row = self.row(row_index)?;
        self.validate_reference_strings(share)?;
        self.row_components(row, share)
    }

    /// Convert every row of a public RLK share, checking its URS and CRS once.
    ///
    /// Returns the `d0` rows and the `d2` rows, each in gadget-row order.
    pub fn share_d_rows(
        &self,
        share: &RelinKeyShare,
    ) -> Result<(Vec<CrtPolynomial>, Vec<CrtPolynomial>), WitnessError> {
        self.validate_reference_strings(share)?;
        let rows = (0..self.row_count())
            .map(|row| self.row_components(row, share))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows.into_iter().unzip())
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
        witness: &RelinKeyWitness,
    ) -> Result<RlkGenerationCircuitData, WitnessError> {
        let row = self.row(row_index)?;
        let expected_rows = self.row_count();
        if witness.errors_d0.len() != expected_rows || witness.errors_d2.len() != expected_rows {
            return Err(WitnessError::Other(format!(
                "RLK witness row counts must equal {expected_rows}"
            )));
        }

        let error_d0 = &witness.errors_d0[row];
        let error_d2 = &witness.errors_d2[row];
        validate_fhe_poly_context(error_d0, &self.context, "RLK e0 component")?;
        validate_fhe_poly_context(error_d2, &self.context, "RLK e2 component")?;

        let moduli = self.params.moduli();
        let degree = self.params.degree();
        let (d0, d2) = self.row_components(row, share)?;
        let e0_crt = fhe_poly_to_crt_centered_checked(&**error_d0, moduli, degree)?;
        let e2_crt = fhe_poly_to_crt_centered_checked(&**error_d2, moduli, degree)?;
        let sk_crt = fhe_secret_key_to_crt_centered(sk, &self.context, moduli, degree)?;
        let r_crt = fhe_secret_key_to_crt_centered(&witness.r, &self.context, moduli, degree)?;

        let sk = sk_crt.limb(0).clone();
        let r = r_crt.limb(0).clone();
        let e0 = e0_crt.limb(0).clone();
        let e2 = e2_crt.limb(0).clone();

        let mut rd0 = Vec::with_capacity(moduli.len());
        let mut rd2 = Vec::with_capacity(moduli.len());

        for (i, qi) in moduli.iter().enumerate() {
            let (d0_hat, d2_hat) = self.reduced_limb_terms(row, i, &sk, &r, &e0, &e2);
            let qi = BigInt::from(*qi);
            rd0.push(d0.limb(i).sub(&d0_hat).div_exact(&qi)?);
            rd2.push(d2.limb(i).sub(&d2_hat).div_exact(&qi)?);
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
    ) -> Result<RlkGenerationInputs, WitnessError> {
        validate_lbfv_generation_party_id(data.party_id, &data.committee)?;
        let session = lbfv_proof_session(data.proof_domain)?;
        let row = self.row(data.row_index)?;
        for (name, polynomial) in [
            ("RLK d0", &data.d0),
            ("RLK d2", &data.d2),
            ("RLK rd0", &data.rd0),
            ("RLK rd2", &data.rd2),
        ] {
            crate::validation::crt(name, polynomial, &self.params)?;
        }
        for (name, polynomial) in [
            ("RLK sk", &data.sk),
            ("RLK r", &data.r),
            ("RLK e0", &data.e0),
            ("RLK e2", &data.e2),
        ] {
            crate::validation::polynomial(name, polynomial, self.params.degree())?;
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
    ) -> (Polynomial, Polynomial) {
        let degree = self.params.degree();
        let mut d0_hat = negacyclic_mul_exact(self.d1_rows[row].limb(limb), sk, degree)
            .neg()
            .add(e0);
        let mut d2_hat = negacyclic_mul_exact(self.a_rows[row].limb(limb), r, degree).add(e2);
        if row == limb {
            d0_hat = d0_hat.add(r);
            d2_hat = d2_hat.add(sk);
        }
        (d0_hat, d2_hat)
    }

    /// Convert every RLK row.
    ///
    /// The returned data holds `sk`, `r`, `e0` and `e2` as plain `BigInt` polynomials; the caller
    /// owns their lifetime.
    pub fn all_rows_data(
        &self,
        committee: CiphernodesCommittee,
        proof_domain: LbfvProofDomainContext,
        party_id: u32,
        sk: &SecretKey,
        share: &RelinKeyShare,
        witness: RelinKeyWitness,
    ) -> Result<Vec<RlkGenerationCircuitData>, WitnessError> {
        (0..self.row_count())
            .map(|row_index| {
                self.row_data(
                    committee.clone(),
                    proof_domain,
                    party_id,
                    row_index as u32,
                    sk,
                    share,
                    &witness,
                )
            })
            .collect()
    }

    /// Build an adapter from explicit URS and CRS rows.
    pub fn from_rows(
        params: &Arc<BfvParameters>,
        crp_d1: &CommonRandomPolyVec,
        crp_a: &CommonRandomPolyVec,
    ) -> Result<Self, WitnessError> {
        let moduli = params.moduli();
        let degree = params.degree();
        if crp_d1.len() != crp_a.len() || crp_d1.len() != moduli.len() {
            return Err(WitnessError::Other(
                "l-BFV CRP row counts must match each other and the modulus count".to_string(),
            ));
        }

        let d1_rows = crp_d1
            .to_polys()
            .iter()
            .map(|poly| fhe_poly_to_crt_centered_checked(poly, moduli, degree))
            .collect::<Result<Vec<_>, _>>()?;
        let a_rows = crp_a
            .to_polys()
            .iter()
            .map(|poly| fhe_poly_to_crt_centered_checked(poly, moduli, degree))
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Self {
            params: params.clone(),
            context: params
                .context_at_level(0)
                .map_err(|error| WitnessError::Other(error.to_string()))?
                .clone(),
            d1_rows,
            a_rows,
        })
    }

    /// Validate a row index against the fixed rows.
    fn row(&self, row_index: u32) -> Result<usize, WitnessError> {
        let row = usize::try_from(row_index)
            .map_err(|_| WitnessError::Other("RLK row index does not fit usize".to_string()))?;
        if row >= self.row_count() {
            return Err(WitnessError::Other(format!(
                "RLK row index {row_index} is out of range for {} rows",
                self.row_count()
            )));
        }
        Ok(row)
    }

    /// Check that a share's `d1` and `a` rows are the fixed URS and CRS.
    ///
    /// fhe.rs compares every share with the first one at aggregation, so one share with other
    /// rows stops the aggregation even though its `d0` and `d2` rows and their proofs are valid.
    fn validate_reference_strings(&self, share: &RelinKeyShare) -> Result<(), WitnessError> {
        let rows = self.row_count();
        if share.d0_components().len() != rows
            || share.d1_components().len() != rows
            || share.d2_components().len() != rows
            || share.a_components().len() != rows
        {
            return Err(WitnessError::Other(format!(
                "RLK share row counts must equal {rows}"
            )));
        }

        let moduli = self.params.moduli();
        let degree = self.params.degree();
        for (row, (d1, a)) in share
            .d1_components()
            .iter()
            .zip(share.a_components())
            .enumerate()
        {
            validate_fhe_poly_context(d1, &self.context, "RLK d1 component")?;
            validate_fhe_poly_context(a, &self.context, "RLK a component")?;
            if fhe_poly_to_crt_centered_checked(d1, moduli, degree)? != self.d1_rows[row] {
                return Err(WitnessError::Other(format!(
                    "RLK d1 row {row} does not match the fixed l-BFV URS"
                )));
            }
            if fhe_poly_to_crt_centered_checked(a, moduli, degree)? != self.a_rows[row] {
                return Err(WitnessError::Other(format!(
                    "RLK a row {row} does not match the fixed l-BFV CRS"
                )));
            }
        }
        Ok(())
    }

    /// Convert the secret-dependent `d0` and `d2` rows of one gadget row.
    fn row_components(
        &self,
        row: usize,
        share: &RelinKeyShare,
    ) -> Result<(CrtPolynomial, CrtPolynomial), WitnessError> {
        if share.ciphertext_level() != 0 || share.key_level() != 0 {
            return Err(WitnessError::Other(format!(
                "RLK levels ({}, {}) are unsupported; only level 0 is supported",
                share.ciphertext_level(),
                share.key_level()
            )));
        }
        let (Some(d0), Some(d2)) = (
            share.d0_components().get(row),
            share.d2_components().get(row),
        ) else {
            return Err(WitnessError::Other(format!(
                "RLK share is missing row {row}"
            )));
        };
        validate_fhe_poly_context(d0, &self.context, "RLK d0 component")?;
        validate_fhe_poly_context(d2, &self.context, "RLK d2 component")?;

        let moduli = self.params.moduli();
        let degree = self.params.degree();
        Ok((
            fhe_poly_to_crt_centered_checked(d0, moduli, degree)?,
            fhe_poly_to_crt_centered_checked(d2, moduli, degree)?,
        ))
    }
}

#[cfg(test)]
mod tests {
    use e3_fhe_params::{build_pair_for_preset, BfvPreset};
    use e3_zk_samples::lbfv_proof_domain::sample_lbfv_proof_domain;
    use fhe::bfv::{CommonRandomPolyVec, SecretKey};
    use num_bigint::BigUint;

    use super::*;
    use e3_committee::CiphernodesCommitteeSize;
    use fhe::bfv::BfvParametersBuilder;

    use rand::rng;

    fn small_params() -> Result<Arc<BfvParameters>, WitnessError> {
        BfvParametersBuilder::new()
            .set_degree(8)
            .set_plaintext_modulus(1153)
            .set_moduli_sizes(&[62; 6])
            .build_arc()
            .map_err(|error| WitnessError::Other(error.to_string()))
    }

    #[test]
    fn row_data_reconstructs_each_rlk_equation() -> Result<(), WitnessError> {
        let mut rng = rng();
        let params = small_params()?;
        let crp_d1 = CommonRandomPolyVec::new(&params, &mut rng)?;
        let crp_a = CommonRandomPolyVec::new(&params, &mut rng)?;
        let adapter = RlkGenerationAdapter::from_rows(&params, &crp_d1, &crp_a)?;
        let secret_key = SecretKey::random(&params, &mut rng);
        let (share, witness) = RelinKeyShare::contribute_with_crp_and_witness(
            &secret_key,
            &crp_d1,
            &crp_a,
            0,
            0,
            &mut rng,
        )?;
        let committee = CiphernodesCommitteeSize::Minimum.values();

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
                let d0_expected = crate::negacyclic::reduce_reference(
                    &adapter.d1_rows[row_index].limb(i).mul(&data.sk),
                    params.degree(),
                )
                .neg()
                .add(&data.e0)
                .add(&data.r.scalar_mul(&delta))
                .add(&data.rd0.limb(i).scalar_mul(&qi));
                assert!(data.d0.limb(i).sub(&d0_expected).is_zero());

                let d2_expected = crate::negacyclic::reduce_reference(
                    &adapter.a_rows[row_index].limb(i).mul(&data.r),
                    params.degree(),
                )
                .add(&data.e2)
                .add(&data.sk.scalar_mul(&delta))
                .add(&data.rd2.limb(i).scalar_mul(&qi));
                assert!(data.d2.limb(i).sub(&d2_expected).is_zero());
            }
        }

        Ok(())
    }

    /// The circuit replaces the row's gadget scalar, the Garner coefficient `g_row`, by
    /// `delta = (row == limb)`. That is sound only because `g_row` is the CRT unit vector:
    /// `1 mod q_row` and `0 mod q_j` for every other modulus.
    #[test]
    fn garner_coefficient_is_the_crt_unit_vector() -> Result<(), WitnessError> {
        for preset in [
            BfvPreset::InsecureThresholdLbfv,
            BfvPreset::SecureThreshold16384,
        ] {
            let (params, _) = build_pair_for_preset(preset)
                .map_err(|error| WitnessError::Other(error.to_string()))?;
            let rns = fhe_math::rns::RnsContext::new(params.moduli())
                .map_err(|error| WitnessError::Other(error.to_string()))?;
            for row in 0..params.moduli().len() {
                let garner = rns.get_garner(row).ok_or_else(|| {
                    WitnessError::Other(format!("missing Garner coefficient at index {row}"))
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

    /// A peer share must carry the fixed URS and CRS rows. The share is otherwise a valid output of
    /// the honest contribution routine, so only its `d1` or `a` rows can set it apart.
    #[test]
    fn share_rows_reject_a_share_on_another_reference_string() -> Result<(), WitnessError> {
        let mut rng = rng();
        let params = small_params()?;
        let crp_d1 = CommonRandomPolyVec::new(&params, &mut rng)?;
        let crp_a = CommonRandomPolyVec::new(&params, &mut rng)?;
        let foreign = CommonRandomPolyVec::new(&params, &mut rng)?;
        let adapter = RlkGenerationAdapter::from_rows(&params, &crp_d1, &crp_a)?;
        let secret_key = SecretKey::random(&params, &mut rng);
        let contribute = |d1: &CommonRandomPolyVec, a: &CommonRandomPolyVec| {
            RelinKeyShare::contribute_with_crp(&secret_key, d1, a, 0, 0, &mut rand::rng())
        };

        let honest = contribute(&crp_d1, &crp_a)?;
        let (d0_rows, d2_rows) = adapter.share_d_rows(&honest)?;
        assert_eq!(d0_rows.len(), adapter.row_count());
        assert_eq!(d2_rows.len(), adapter.row_count());
        for row in 0..adapter.row_count() {
            let (d0, d2) = adapter.share_row_components(row as u32, &honest)?;
            assert_eq!((&d0, &d2), (&d0_rows[row], &d2_rows[row]));
        }

        for (share, expected) in [
            (contribute(&foreign, &crp_a)?, "RLK d1 row 0 does not match"),
            (contribute(&crp_d1, &foreign)?, "RLK a row 0 does not match"),
        ] {
            let error = adapter.share_d_rows(&share).unwrap_err().to_string();
            assert!(error.contains(expected), "{error}");
            let error = adapter
                .share_row_components(3, &share)
                .unwrap_err()
                .to_string();
            assert!(error.contains(expected), "{error}");
        }
        Ok(())
    }

    #[test]
    fn share_row_components_reject_an_out_of_range_row() -> Result<(), WitnessError> {
        let mut rng = rng();
        let params = small_params()?;
        let crp_d1 = CommonRandomPolyVec::new(&params, &mut rng)?;
        let crp_a = CommonRandomPolyVec::new(&params, &mut rng)?;
        let adapter = RlkGenerationAdapter::from_rows(&params, &crp_d1, &crp_a)?;
        let secret_key = SecretKey::random(&params, &mut rng);
        let share =
            RelinKeyShare::contribute_with_crp(&secret_key, &crp_d1, &crp_a, 0, 0, &mut rng)?;

        assert!(adapter
            .share_row_components(adapter.row_count() as u32, &share)
            .is_err());
        Ok(())
    }
}
