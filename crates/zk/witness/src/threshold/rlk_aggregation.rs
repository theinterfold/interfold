// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Conversion and aggregation of l-BFV relinearization-key share rows. Each gadget row is proved
//! once per component: `d0` and `d2` are independent sums, and `lbfv_aggregation_fold` binds the
//! two proofs of a row to components 0 and 1.

use crate::commitments::{compute_rlk_d0_commitment, compute_rlk_d2_commitment};
use crate::encoding::bigint_1d_to_json_values;
use crate::threshold::lbfv_pk_aggregation::aggregate_rows;
use crate::threshold::lbfv_proof_domain::{
    lbfv_accepted_party_set, lbfv_proof_session, validate_lbfv_generation_party_id,
};
use crate::WitnessError;
use e3_committee::CiphernodesCommittee;
use e3_committee_hash::LbfvProofDomainContext;
use e3_fhe_params::utils::compute_modulus_bit;
use e3_polynomial::CrtPolynomial;
use e3_zk_config::threshold::rlk_aggregation::RlkAggregationConfigs;
use fhe::trlbfv::RelinKeyShare;
use num_bigint::BigInt;
use serde::{Deserialize, Serialize};

/// The component of an RLK gadget row that an aggregation proof covers.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum RlkAggregationComponent {
    D0 = 0,
    D2 = 1,
}

impl RlkAggregationComponent {
    /// Both components, in public-input order.
    pub const ALL: [Self; 2] = [Self::D0, Self::D2];

    /// The circuit's public `component` value.
    pub fn index(self) -> u32 {
        self as u32
    }

    /// The component at public `component` value `index`, if any.
    pub fn from_index(index: u32) -> Option<Self> {
        match index {
            0 => Some(Self::D0),
            1 => Some(Self::D2),
            _ => None,
        }
    }

    /// The RLK generation commitment that the circuit opens for this component's row.
    pub fn generation_commitment(self, row_index: u32, row: &CrtPolynomial, bit_d: u32) -> BigInt {
        match self {
            Self::D0 => compute_rlk_d0_commitment(row_index, row, bit_d),
            Self::D2 => compute_rlk_d2_commitment(row_index, row, bit_d),
        }
    }
}

/// Witness data for one l-BFV RLK aggregation row proof.
pub struct RlkAggregationCircuitData {
    pub committee: CiphernodesCommittee,
    pub proof_domain: LbfvProofDomainContext,
    pub aggregator_party_id: u32,
    pub party_ids: Vec<u32>,
    pub row_index: u32,
    pub component: RlkAggregationComponent,
    pub shares: Vec<RelinKeyShare>,
}

/// Noir inputs of one l-BFV RLK aggregation row proof.
pub struct RlkAggregationInputs {
    pub session_id_hi: u128,
    pub session_id_lo: u128,
    pub aggregator_party_id: u32,
    pub accepted_party_set_hash_hi: u128,
    pub accepted_party_set_hash_lo: u128,
    pub row_index: u32,
    pub component: u32,
    pub expected_commitments: Vec<BigInt>,
    pub values: Vec<CrtPolynomial>,
    pub agg: CrtPolynomial,
    /// Packing width of the parties' row commitments. The circuit takes each party's row as the
    /// carriers packed at this width and derives `agg` itself.
    pub value_bit: u32,
}

impl RlkAggregationInputs {
    pub fn compute(
        config: &RlkAggregationConfigs,
        data: &RlkAggregationCircuitData,
    ) -> Result<Self, WitnessError> {
        crate::validation::committee(config.committee, &data.committee)?;
        let canonical = e3_zk_config::committee::canonical_committee_for_circuit(&data.committee)
            .map_err(|error| WitnessError::Other(error.to_string()))?;
        let session = lbfv_proof_session(data.proof_domain)?;
        validate_lbfv_generation_party_id(data.aggregator_party_id, &data.committee)?;
        let accepted = lbfv_accepted_party_set(&data.party_ids, &data.committee)?;
        if data.shares.len() != canonical.h {
            return Err(WitnessError::Other(format!(
                "RLK aggregation requires exactly {} shares; received {}",
                canonical.h,
                data.shares.len()
            )));
        }

        let params = &config.params;
        let adapter =
            super::rlk_generation::RlkGenerationAdapter::from_parameters(config.preset, params)?;
        let bit_d = compute_modulus_bit(params);
        let mut values = Vec::with_capacity(canonical.h);
        let mut expected_commitments = Vec::with_capacity(canonical.h);

        for share in &data.shares {
            let (d0_row, d2_row) = adapter.share_row_components(data.row_index, share)?;
            let row = match data.component {
                RlkAggregationComponent::D0 => d0_row,
                RlkAggregationComponent::D2 => d2_row,
            };
            expected_commitments.push(data.component.generation_commitment(
                data.row_index,
                &row,
                bit_d,
            ));
            values.push(row);
        }

        let agg = aggregate_rows(&values, params.moduli(), params.degree())?;

        Ok(Self {
            session_id_hi: session.session_id_hi,
            session_id_lo: session.session_id_lo,
            aggregator_party_id: data.aggregator_party_id,
            accepted_party_set_hash_hi: accepted.accepted_party_set_hash_hi,
            accepted_party_set_hash_lo: accepted.accepted_party_set_hash_lo,
            row_index: data.row_index,
            component: data.component.index(),
            expected_commitments,
            values,
            agg,
            value_bit: bit_d,
        })
    }

    pub fn to_json(&self) -> serde_json::Value {
        let value_carriers = self
            .values
            .iter()
            .map(|row| {
                row.limbs
                    .iter()
                    .map(|limb| {
                        bigint_1d_to_json_values(&crate::packing::pack_to_bigints(
                            limb,
                            self.value_bit,
                        ))
                    })
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        serde_json::json!({
            "session_id_hi": self.session_id_hi.to_string(),
            "session_id_lo": self.session_id_lo.to_string(),
            "aggregator_party_id": self.aggregator_party_id,
            "accepted_party_set_hash_hi": self.accepted_party_set_hash_hi.to_string(),
            "accepted_party_set_hash_lo": self.accepted_party_set_hash_lo.to_string(),
            "row_index": self.row_index,
            "component": self.component,
            "expected_commitments": bigint_1d_to_json_values(&self.expected_commitments),
            "value_carriers": value_carriers,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn component_indices_round_trip() {
        for component in RlkAggregationComponent::ALL {
            assert_eq!(
                RlkAggregationComponent::from_index(component.index()),
                Some(component)
            );
        }
        assert_eq!(RlkAggregationComponent::from_index(2), None);
    }
}
