// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Conversion of l-BFV public-key rows into C1 circuit inputs.

use crate::math::{
    cyclotomic_polynomial, fhe_poly_to_crt_centered_checked, fhe_secret_key_to_crt_centered,
    validate_fhe_poly_context,
};
use crate::utils::verify_crt_shapes;
use crate::{CiphernodesCommittee, CircuitsErrors};
use e3_fhe_params::{build_pair_for_preset, lbfv_crs_seed, BfvPreset};
use e3_polynomial::{CrtPolynomial, Polynomial};
use fhe::bfv::{BfvParameters, CommonRandomPolyVec, SecretKey};
use fhe::trlbfv::PublicKeyShare;
use fhe_math::rq::Context;
use num_bigint::BigInt;
use std::sync::Arc;

/// Circuit-ready values for one l-BFV C1 public-key row.
#[derive(Debug, Clone)]
pub struct LbfvPkGenerationRowData {
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

/// Converts a concrete l-BFV public-key share into row-level C1 inputs.
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
            .map_err(|_| CircuitsErrors::Other("C1 row index does not fit usize".to_string()))?;
        self.a_rows.get(row).cloned().ok_or_else(|| {
            CircuitsErrors::Other(format!(
                "C1 row index {row_index} is out of range for {} rows",
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
    ) -> Result<LbfvPkGenerationRowData, CircuitsErrors> {
        let row = usize::try_from(row_index)
            .map_err(|_| CircuitsErrors::Other("C1 row index does not fit usize".to_string()))?;
        if row >= self.row_count() {
            return Err(CircuitsErrors::Other(format!(
                "C1 row index {row_index} is out of range for {} rows",
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

        let mut a_rows = Vec::with_capacity(a_components.len());
        let mut b_rows = Vec::with_capacity(b_components.len());
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
            a_rows.push(a);
            b_rows.push(fhe_poly_to_crt_centered_checked(
                b_component,
                &self.moduli,
                self.degree,
            )?);
        }

        let sk_crt =
            fhe_secret_key_to_crt_centered(secret_key, &self.context, &self.moduli, self.degree)?;
        verify_crt_shapes(
            &[&a_rows[row], &b_rows[row], &sk_crt],
            self.moduli.len(),
            self.degree,
        )
        .map_err(|error| CircuitsErrors::Other(format!("C1 CRT shape mismatch: {error}")))?;

        let sk = sk_crt.limb(0).clone();
        if sk_crt.limbs.iter().any(|limb| limb != &sk) {
            return Err(CircuitsErrors::Other(
                "secret-key CRT limbs do not represent one common polynomial".to_string(),
            ));
        }

        let a = a_rows[row].clone();
        let pk0_share = b_rows[row].clone();
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

        Ok(LbfvPkGenerationRowData {
            committee,
            row_index,
            pk0_share,
            a,
            eek,
            sk,
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
            }
        }

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
}
