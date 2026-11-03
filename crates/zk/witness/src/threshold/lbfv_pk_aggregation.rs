// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Conversion and aggregation of threshold l-BFV public-key share rows.

use crate::threshold::lbfv_proof_domain::{
    lbfv_accepted_party_set, lbfv_proof_session, validate_lbfv_generation_party_id,
};
use crate::WitnessError;
use e3_committee::CiphernodesCommittee;
use e3_committee_hash::LbfvProofDomainContext;
use e3_fhe_params::utils::compute_modulus_bit;
use e3_fhe_params::{lbfv_crs_seed, BfvPreset};
use e3_polynomial::{CrtPolynomial, Polynomial};
use fhe::trlbfv::PublicKeyShare;
use num_bigint::BigInt;

use e3_zk_config::threshold::lbfv_pk_aggregation::LbfvPkAggregationConfigs;
pub struct LbfvPkAggregationCircuitData {
    pub committee: CiphernodesCommittee,
    pub proof_domain: LbfvProofDomainContext,
    pub aggregator_party_id: u32,
    pub party_ids: Vec<u32>,
    pub row_index: u32,
    pub shares: Vec<PublicKeyShare>,
}
#[derive(serde::Serialize, serde::Deserialize)]
pub struct LbfvPkAggregationInputs {
    pub session_id_hi: u128,
    pub session_id_lo: u128,
    pub aggregator_party_id: u32,
    pub accepted_party_set_hash_hi: u128,
    pub accepted_party_set_hash_lo: u128,
    pub row_index: u32,
    pub expected_pk_generation_commitments: Vec<BigInt>,
    pub pk0: Vec<CrtPolynomial>,
    pub pk0_agg: CrtPolynomial,
    /// Packing width of the parties' row commitments. The circuit takes each party's `pk0` as the
    /// carriers packed at this width and derives `pk0_agg` itself.
    #[serde(default)]
    pub pk_bit: u32,
}
impl LbfvPkAggregationInputs {
    pub fn compute(
        config: &LbfvPkAggregationConfigs,
        data: &LbfvPkAggregationCircuitData,
    ) -> Result<Self, WitnessError> {
        crate::validation::committee(config.committee, &data.committee)?;
        let preset = config.preset;
        ensure_supported(preset)?;
        let canonical = e3_zk_config::committee::canonical_committee_for_circuit(&data.committee)
            .map_err(|error| WitnessError::Other(error.to_string()))?;
        let session = lbfv_proof_session(data.proof_domain)?;
        validate_lbfv_generation_party_id(data.aggregator_party_id, &data.committee)?;
        let accepted = lbfv_accepted_party_set(&data.party_ids, &data.committee)?;
        if data.shares.len() != canonical.h {
            return Err(WitnessError::Other(format!(
                "l-BFV public-key aggregation requires exactly {} shares; received {}",
                canonical.h,
                data.shares.len()
            )));
        }

        let params = &config.params;
        let adapter = super::pk_generation::LbfvPkGenerationAdapter::from_parameters(
            config.preset,
            &config.params,
        )?;
        let bit_pk = compute_modulus_bit(&params);
        let mut pk0 = Vec::with_capacity(canonical.h);
        let mut expected_pk_generation_commitments = Vec::with_capacity(canonical.h);

        for share in &data.shares {
            let (_, pk0_row) = adapter.share_row_components(data.row_index, share)?;
            expected_pk_generation_commitments.push(compute_lbfv_pk_row_commitment(
                data.row_index,
                &pk0_row,
                bit_pk,
            ));
            pk0.push(pk0_row);
        }
        let pk0_agg = aggregate_rows(&pk0, params.moduli(), params.degree())?;

        Ok(Self {
            session_id_hi: session.session_id_hi,
            session_id_lo: session.session_id_lo,
            aggregator_party_id: data.aggregator_party_id,
            accepted_party_set_hash_hi: accepted.accepted_party_set_hash_hi,
            accepted_party_set_hash_lo: accepted.accepted_party_set_hash_lo,
            row_index: data.row_index,
            expected_pk_generation_commitments,
            pk0,
            pk0_agg,
            pk_bit: bit_pk,
        })
    }

    pub fn to_json(&self) -> serde_json::Result<serde_json::Value> {
        let pk0_carriers = self
            .pk0
            .iter()
            .map(|row| {
                row.limbs
                    .iter()
                    .map(|limb| {
                        bigint_1d_to_json_values(&crate::packing::pack_to_bigints(
                            limb,
                            self.pk_bit,
                        ))
                    })
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        Ok(serde_json::json!({
            "session_id_hi": self.session_id_hi.to_string(),
            "session_id_lo": self.session_id_lo.to_string(),
            "aggregator_party_id": self.aggregator_party_id,
            "accepted_party_set_hash_hi": self.accepted_party_set_hash_hi.to_string(),
            "accepted_party_set_hash_lo": self.accepted_party_set_hash_lo.to_string(),
            "row_index": self.row_index,
            "expected_pk_generation_commitments": bigint_1d_to_json_values(
                &self.expected_pk_generation_commitments,
            ),
            "pk0_carriers": pk0_carriers,
        }))
    }
}
fn ensure_supported(preset: BfvPreset) -> Result<(), WitnessError> {
    if lbfv_crs_seed(preset).is_none() {
        return Err(WitnessError::Other(format!(
            "l-BFV public-key aggregation is not enabled for {preset:?}"
        )));
    }
    Ok(())
}
fn aggregate_rows(
    rows: &[CrtPolynomial],
    moduli: &[u64],
    degree: usize,
) -> Result<CrtPolynomial, WitnessError> {
    if rows.is_empty() {
        return Err(WitnessError::Other(
            "l-BFV public-key aggregation requires at least one share".to_string(),
        ));
    }
    crate::encoding::verify_crt_shapes(&rows.iter().collect::<Vec<_>>(), moduli.len(), degree)
        .map_err(|error| WitnessError::Other(format!("l-BFV CRT shape mismatch: {error}")))?;

    let limbs = (0..moduli.len())
        .map(|limb_index| {
            let mut coefficients = vec![BigInt::from(0u8); degree];
            for row in rows {
                for (sum, coefficient) in coefficients
                    .iter_mut()
                    .zip(row.limb(limb_index).coefficients())
                {
                    *sum += coefficient;
                }
            }
            Polynomial::new(coefficients)
        })
        .collect();
    let mut aggregate = CrtPolynomial::new(limbs);
    aggregate.reduce(moduli)?;
    aggregate.center(moduli)?;
    Ok(aggregate)
}

use crate::commitments::*;
use crate::encoding::bigint_1d_to_json_values;

#[cfg(test)]
mod tests {
    use e3_fhe_params::BfvPreset;

    use super::*;

    use e3_committee::CiphernodesCommitteeSize;

    #[test]
    fn unsupported_presets_fail_closed() {
        let committee = CiphernodesCommitteeSize::Minimum.values();
        assert!(LbfvPkAggregationConfigs::for_preset(
            BfvPreset::SecureThreshold8192,
            size(&committee)
        )
        .is_err());
    }

    #[test]
    fn aggregation_reduces_and_centers_each_limb() -> Result<(), WitnessError> {
        let rows = vec![
            CrtPolynomial::new(
                vec![vec![4.into(), (-4).into()], vec![6.into(), 1.into()]]
                    .into_iter()
                    .map(Polynomial::new)
                    .collect::<Vec<_>>(),
            ),
            CrtPolynomial::new(
                vec![vec![4.into(), 3.into()], vec![6.into(), 6.into()]]
                    .into_iter()
                    .map(Polynomial::new)
                    .collect::<Vec<_>>(),
            ),
        ];
        let aggregate = aggregate_rows(&rows, &[7, 11], 2)?;

        assert_eq!(aggregate.limb(0).coefficients(), &[1.into(), (-1).into()]);
        assert_eq!(aggregate.limb(1).coefficients(), &[1.into(), (-4).into()]);
        Ok(())
    }

    fn size(c: &e3_committee::CiphernodesCommittee) -> e3_committee::CiphernodesCommitteeSize {
        e3_committee::CiphernodesCommitteeSize::from_threshold(c.threshold, c.n).unwrap()
    }
}
