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
use crate::encoding::{validate_crt_shape, verify_crt_shapes};
use crate::negacyclic::{exact_quotient, negacyclic_mul};
use crate::threshold::lbfv_proof_domain::{lbfv_proof_session, validate_lbfv_generation_party_id};
use crate::WitnessError;
use e3_committee::CiphernodesCommittee;
use e3_committee_hash::LbfvProofDomainContext;
use e3_fhe_params::{lbfv_crs_seed, lbfv_urs_seed, BfvPreset};
use e3_polynomial::{CrtPolynomial, Polynomial};
use fhe::bfv::{BfvParameters, CommonRandomPolyVec, SecretKey};
use fhe::trlbfv::{PublicKeyShare, RelinKeyShare, RlkWitness};
use fhe_math::rq::Context;
use num_bigint::BigInt;
use std::sync::Arc;
use zeroize::Zeroize;

use e3_zk_config::threshold::rlk_generation::RlkGenerationConfigs;
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
impl RlkGenerationInputs {
    pub fn compute(
        config: &RlkGenerationConfigs,
        data: &RlkGenerationCircuitData,
    ) -> Result<Self, WitnessError> {
        crate::validation::committee(config.committee, &data.committee)?;
        let _preset = config.preset;
        RlkGenerationAdapter::from_config(config)?.row_inputs(data)
    }

    pub fn to_json(&self) -> serde_json::Result<serde_json::Value> {
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
pub struct RlkGenerationAdapter {
    context: Arc<Context>,
    moduli: Vec<u64>,
    degree: usize,
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
    ) -> Result<(CrtPolynomial, CrtPolynomial), WitnessError> {
        let row = usize::try_from(row_index)
            .map_err(|_| WitnessError::Other("RLK row index does not fit usize".to_string()))?;
        if row >= self.row_count() {
            return Err(WitnessError::Other(format!(
                "RLK row index {row_index} is out of range for {} rows",
                self.row_count()
            )));
        }
        if share.ciphertext_level() != 0 || share.key_level() != 0 {
            return Err(WitnessError::Other(format!(
                "RLK levels ({}, {}) are unsupported; only level 0 is supported",
                share.ciphertext_level(),
                share.key_level()
            )));
        }
        if share.d0_components().len() != self.row_count()
            || share.d2_components().len() != self.row_count()
        {
            return Err(WitnessError::Other(format!(
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
    ) -> Result<RlkGenerationCircuitData, WitnessError> {
        let row = usize::try_from(row_index)
            .map_err(|_| WitnessError::Other("RLK row index does not fit usize".to_string()))?;
        let expected_rows = self.row_count();
        if witness.errors_d0.len() != expected_rows || witness.errors_d2.len() != expected_rows {
            return Err(WitnessError::Other(format!(
                "RLK witness row counts must equal {expected_rows}"
            )));
        }

        let error_d0 = witness
            .errors_d0
            .get(row)
            .ok_or_else(|| WitnessError::Other("RLK d0 error row is missing".to_string()))?;
        let error_d2 = witness
            .errors_d2
            .get(row)
            .ok_or_else(|| WitnessError::Other("RLK d2 error row is missing".to_string()))?;

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
        .map_err(|error| WitnessError::Other(format!("RLK CRT shape mismatch: {error}")))?;

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
    ) -> Result<RlkGenerationInputs, WitnessError> {
        validate_lbfv_generation_party_id(data.party_id, &data.committee)?;
        let session = lbfv_proof_session(data.proof_domain)?;
        let l = self.moduli.len();
        let n = self.degree;
        let row = usize::try_from(data.row_index)
            .map_err(|_| WitnessError::Other("RLK row index does not fit usize".to_string()))?;
        if row >= self.row_count() {
            return Err(WitnessError::Other(format!(
                "RLK row index {} is out of range for {} rows",
                data.row_index,
                self.row_count()
            )));
        }
        verify_crt_shapes(&[&data.d0, &data.d2], l, n)
            .map_err(|error| WitnessError::Other(format!("RLK CRT shape mismatch: {error}")))?;
        for (name, polynomial) in [("rd0", &data.rd0), ("rd2", &data.rd2)] {
            validate_crt_shape(polynomial, l, n).map_err(|error| {
                WitnessError::Other(format!("invalid RLK {name} shape: {error}"))
            })?;
        }
        for (name, polynomial) in [
            ("sk", &data.sk),
            ("r", &data.r),
            ("e0", &data.e0),
            ("e2", &data.e2),
        ] {
            if polynomial.coefficients().len() != n {
                return Err(WitnessError::Other(format!(
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
    ) -> Result<(Polynomial, Polynomial), WitnessError> {
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
    ) -> Result<Vec<RlkGenerationCircuitData>, WitnessError> {
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
    pub fn validate_public_key_crs(&self, public_key: &PublicKeyShare) -> Result<(), WitnessError> {
        let a_components = public_key.a_components()?;
        if a_components.len() != self.row_count() {
            return Err(WitnessError::Other(format!(
                "public-key CRS has {} rows; expected {}",
                a_components.len(),
                self.row_count()
            )));
        }

        for (row, component) in a_components.iter().enumerate() {
            validate_fhe_poly_context(component, &self.context, "public-key CRS component")?;
            let actual = fhe_poly_to_crt_centered_checked(component, &self.moduli, self.degree)?;
            if actual != self.a_rows[row] {
                return Err(WitnessError::Other(format!(
                    "public-key CRS row {row} does not match the RLK CRS"
                )));
            }
        }

        Ok(())
    }

    pub fn from_rows(
        params: &Arc<BfvParameters>,
        crp_d1: &CommonRandomPolyVec,
        crp_a: &CommonRandomPolyVec,
    ) -> Result<Self, WitnessError> {
        let moduli = params.moduli().to_vec();
        let degree = params.degree();
        if crp_d1.len() != crp_a.len() || crp_d1.len() != moduli.len() {
            return Err(WitnessError::Other(
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
                .map_err(|error| WitnessError::Other(error.to_string()))?
                .clone(),
            moduli,
            degree,
            d1_rows,
            a_rows,
        })
    }
}

pub struct RlkWitnessGuard {
    witness: RlkWitness,
}

impl RlkWitnessGuard {
    pub fn new(witness: RlkWitness) -> Self {
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

#[cfg(test)]
mod tests {
    use e3_fhe_params::{build_pair_for_preset, BfvPreset};
    use e3_zk_samples::lbfv_proof_domain::sample_lbfv_proof_domain;
    use fhe::bfv::{CommonRandomPolyVec, SecretKey};
    use num_bigint::BigUint;

    use super::*;
    use e3_committee::CiphernodesCommitteeSize;
    use fhe::aggregate::AggregateIter;
    use fhe::bfv::{BfvParametersBuilder, Encoding, Plaintext};
    use fhe::trlbfv::{aggregate_relinearization_key, LBFVPublicKey, PublicKeyShare};
    use fhe_traits::{
        DeserializeParametrized, FheDecoder, FheDecrypter, FheEncoder, FheEncrypter, Serialize,
    };

    use rand::rng;

    #[test]
    fn row_data_reconstructs_each_rlk_equation() -> Result<(), WitnessError> {
        let mut rng = rng();
        let params = BfvParametersBuilder::new()
            .set_degree(8)
            .set_plaintext_modulus(1153)
            .set_moduli_sizes(&[62; 6])
            .build_arc()
            .map_err(|error| WitnessError::Other(error.to_string()))?;
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

    #[test]
    fn adapter_rejects_presets_without_lbfv() {
        assert!(RlkGenerationConfigs::for_preset(
            BfvPreset::SecureThreshold8192,
            CiphernodesCommitteeSize::Minimum
        )
        .is_err());
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

    /// The reduced identity needs one quotient bound for both equations, and with the 0/1
    /// gadget scalar it is the same order as the public-key limb's `r` bound, not the product of
    /// a full-width Garner coefficient.
    #[test]
    fn secure_rd_bounds_track_the_public_key_bound() -> Result<(), WitnessError> {
        let preset = BfvPreset::SecureThreshold16384;
        let committee = CiphernodesCommitteeSize::Minimum.values();
        let bounds =
            RlkGenerationConfigs::for_preset(preset, size(&committee)).map(|c| c.bounds)?;
        let _pk_bounds =
            e3_zk_config::threshold::pk_generation::Configs::for_preset(preset, size(&committee))
                .map(|c| c.bounds)?;
        let pk_r_bounds = Ok::<_, WitnessError>(
            e3_zk_config::threshold::pk_generation::Configs::for_preset(preset, size(&committee))?
                .bounds
                .r_bounds,
        )?;
        let bits = RlkGenerationConfigs::for_preset(preset, size(&committee)).map(|c| c.bits)?;

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
    fn standalone_configs_use_derived_rlk_bounds() -> Result<(), WitnessError> {
        let preset = BfvPreset::SecureThreshold16384;
        let committee = CiphernodesCommitteeSize::Minimum.values();
        let configs = RlkGenerationConfigs::for_preset(preset, size(&committee))?;
        let noir = configs.render()?;

        assert!(noir.contains("RLK_GENERATION_RD0_BOUNDS"));
        assert!(noir.contains(&configs.bounds.rd0_bounds[0].to_string()));
        Ok(())
    }

    #[test]
    fn public_key_crs_matches_rlk_rows() -> Result<(), WitnessError> {
        let mut rng = rng();
        let params = BfvParametersBuilder::new()
            .set_degree(8)
            .set_plaintext_modulus(1153)
            .set_moduli_sizes(&[62; 6])
            .build_arc()
            .map_err(|error| WitnessError::Other(error.to_string()))?;
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
    fn share_roundtrip_relinearizes_with_matching_public_key() -> Result<(), WitnessError> {
        let mut rng = rng();
        let params = BfvParametersBuilder::new()
            .set_degree(8)
            .set_plaintext_modulus(1153)
            .set_moduli_sizes(&[62; 6])
            .build_arc()
            .map_err(|error| WitnessError::Other(error.to_string()))?;
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
            .map_err(|error| WitnessError::Other(error.to_string()))?;
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

    fn size(c: &e3_committee::CiphernodesCommittee) -> e3_committee::CiphernodesCommitteeSize {
        e3_committee::CiphernodesCommitteeSize::from_threshold(c.threshold, c.n).unwrap()
    }
}
