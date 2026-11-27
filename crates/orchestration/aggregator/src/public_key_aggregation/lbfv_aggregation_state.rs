// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Durable l-BFV row aggregation state.

use anyhow::{ensure, Context, Result};
use e3_committee_hash::LbfvProofDomainContext;
use e3_events::{CorrelationId, E3id, LbfvPublicKeyAggregated, Proof};
use e3_fhe_params::{lbfv_row_count, BfvPreset};
use e3_utils::ArcBytes;
use e3_zk_witness::threshold::rlk_aggregation::RlkAggregationComponent;
use serde::{Deserialize, Serialize};

pub const LBFV_AGGREGATION_SCHEMA_VERSION: u32 = 1;
pub const LBFV_PUBLICATION_SCHEMA_VERSION: u32 = 1;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LbfvPublicKeyPublicationStateV1 {
    pub schema_version: u32,
    pub e3_id: E3id,
    pub pending: Option<LbfvPublicKeyAggregated>,
}

impl LbfvPublicKeyPublicationStateV1 {
    pub fn new(e3_id: E3id) -> Self {
        Self {
            schema_version: LBFV_PUBLICATION_SCHEMA_VERSION,
            e3_id,
            pending: None,
        }
    }

    pub fn validate_loaded(&self) -> Result<()> {
        ensure!(
            self.schema_version == LBFV_PUBLICATION_SCHEMA_VERSION,
            "unsupported l-BFV publication schema version {}",
            self.schema_version
        );
        if let Some(event) = &self.pending {
            ensure!(
                event.e3_id == self.e3_id,
                "l-BFV publication intent belongs to another E3"
            );
            ensure!(
                event.dkg_aggregator_v2_proof.circuit == e3_events::CircuitName::DkgAggregatorV2,
                "l-BFV publication intent has the wrong recursive circuit"
            );
            e3_bfv_client::decode_lbfv_key_envelope(&event.pubkey)
                .context("l-BFV publication intent has an unsupported key envelope")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod publication_tests {
    use super::*;
    use alloy::primitives::Address;
    use e3_events::CircuitName;
    use e3_utils::OrderedSet;

    fn publication(e3_id: E3id, circuit: CircuitName) -> LbfvPublicKeyAggregated {
        let mut key_envelope = Vec::from(*b"IFLBFVKE");
        key_envelope.extend_from_slice(&3_u16.to_be_bytes());
        key_envelope.extend_from_slice(&0_u32.to_be_bytes());
        key_envelope.extend_from_slice(&1_u32.to_be_bytes());
        key_envelope.push(1);
        LbfvPublicKeyAggregated {
            pubkey: ArcBytes::from_bytes(&key_envelope),
            e3_id,
            nodes: OrderedSet::from_iter(["node".to_owned()]),
            committee_addresses: vec![Address::repeat_byte(1)],
            honest_committee_addresses: vec![Address::repeat_byte(1)],
            pk_commitment: [2; 32],
            dkg_aggregator_v2_proof: Proof::new(
                circuit,
                ArcBytes::from_bytes(&[3]),
                ArcBytes::from_bytes(&[4]),
            ),
            dkg_attestation_bundle: Some(ArcBytes::from_bytes(&[5])),
        }
    }

    #[test]
    fn publication_state_accepts_the_v3_envelope_intent() {
        let e3_id = E3id::new("42", 1);
        let state = LbfvPublicKeyPublicationStateV1 {
            schema_version: LBFV_PUBLICATION_SCHEMA_VERSION,
            e3_id: e3_id.clone(),
            pending: Some(publication(e3_id, CircuitName::DkgAggregatorV2)),
        };

        assert!(state.validate_loaded().is_ok());
    }

    #[test]
    fn publication_state_rejects_wrong_identity_and_circuit() {
        let e3_id = E3id::new("42", 1);
        let mut state = LbfvPublicKeyPublicationStateV1 {
            schema_version: LBFV_PUBLICATION_SCHEMA_VERSION,
            e3_id: e3_id.clone(),
            pending: Some(publication(
                E3id::new("43", 1),
                CircuitName::DkgAggregatorV2,
            )),
        };
        assert!(state.validate_loaded().is_err());

        state.pending = Some(publication(e3_id, CircuitName::PkAggregation));
        assert!(state.validate_loaded().is_err());
    }

    #[test]
    fn publication_state_rejects_the_version_two_envelope() {
        let e3_id = E3id::new("42", 1);
        let mut event = publication(e3_id.clone(), CircuitName::DkgAggregatorV2);
        let mut key_envelope = event.pubkey.to_vec();
        key_envelope[8..10].copy_from_slice(&2_u16.to_be_bytes());
        event.pubkey = ArcBytes::from_bytes(&key_envelope);
        let state = LbfvPublicKeyPublicationStateV1 {
            schema_version: LBFV_PUBLICATION_SCHEMA_VERSION,
            e3_id,
            pending: Some(event),
        };

        let error = state
            .validate_loaded()
            .expect_err("the version-2 envelope must be rejected");
        assert!(error.to_string().contains("unsupported key envelope"));
    }
}

/// The accepted parties' key shares are not stored here. They live in the content-addressed
/// documents of the sealed collection, and the actor reads them when it needs them.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LbfvAggregationStateV1 {
    pub schema_version: u32,
    pub e3_id: E3id,
    pub proof_domain: LbfvProofDomainContext,
    pub accepted_party_ids: Vec<u32>,
    pub public_key_aggregation_proofs: Vec<Option<Proof>>,
    /// Indexed by row, then by [`RlkAggregationComponent::index`]: each row has one `d0` and one
    /// `d2` proof.
    pub rlk_aggregation_proofs: Vec<[Option<Proof>; 2]>,
    pub public_key_aggregation_correlations: Vec<Option<CorrelationId>>,
    /// Indexed like `rlk_aggregation_proofs`.
    pub rlk_aggregation_correlations: Vec<[Option<CorrelationId>; 2]>,
    pub aggregation_fold_proof: Option<Proof>,
    pub aggregation_fold_correlation: Option<CorrelationId>,
    pub aggregation_fold_completed_rows: u32,
    pub dkg_aggregation_correlation: Option<CorrelationId>,
    pub dkg_aggregated_proof: Option<Proof>,
    pub operational_public_key: Option<ArcBytes>,
    pub operational_rlk: Option<ArcBytes>,
    pub params_preset: BfvPreset,
}

impl LbfvAggregationStateV1 {
    pub fn new(
        e3_id: E3id,
        proof_domain: LbfvProofDomainContext,
        accepted_party_ids: Vec<u32>,
        params_preset: BfvPreset,
    ) -> Result<Self> {
        let row_count = lbfv_row_count(params_preset)
            .ok_or_else(|| anyhow::anyhow!("selected preset does not support l-BFV"))?;
        let state = Self {
            schema_version: LBFV_AGGREGATION_SCHEMA_VERSION,
            e3_id,
            proof_domain,
            accepted_party_ids,
            public_key_aggregation_proofs: vec![None; row_count],
            rlk_aggregation_proofs: vec![[None, None]; row_count],
            public_key_aggregation_correlations: vec![None; row_count],
            rlk_aggregation_correlations: vec![[None, None]; row_count],
            aggregation_fold_proof: None,
            aggregation_fold_correlation: None,
            aggregation_fold_completed_rows: 0,
            dkg_aggregation_correlation: None,
            dkg_aggregated_proof: None,
            operational_public_key: None,
            operational_rlk: None,
            params_preset,
        };
        state.validate_loaded()?;
        Ok(state)
    }

    pub fn validate_loaded(&self) -> Result<()> {
        ensure!(
            self.schema_version == LBFV_AGGREGATION_SCHEMA_VERSION,
            "unsupported l-BFV aggregation schema version {}",
            self.schema_version
        );
        self.proof_domain.validate().map_err(anyhow::Error::msg)?;
        ensure!(
            !self.accepted_party_ids.is_empty(),
            "accepted l-BFV party set is empty"
        );
        ensure!(
            self.accepted_party_ids
                .windows(2)
                .all(|ids| ids[0] < ids[1]),
            "accepted l-BFV party IDs must be strictly ascending"
        );
        let row_count = self.row_count()?;
        ensure!(
            self.public_key_aggregation_proofs.len() == row_count
                && self.rlk_aggregation_proofs.len() == row_count
                && self.public_key_aggregation_correlations.len() == row_count
                && self.rlk_aggregation_correlations.len() == row_count,
            "l-BFV aggregation proof families do not match the selected preset"
        );
        ensure!(
            self.aggregation_fold_completed_rows <= row_count as u32,
            "l-BFV aggregation fold row cursor is out of range"
        );
        Ok(())
    }

    pub fn record_public_key_proof(&mut self, row: u32, proof: Proof) -> Result<()> {
        self.validate_loaded()?;
        let index = row_slot(row, self.row_count()?)?;
        record_row_proof(&mut self.public_key_aggregation_proofs[index], proof)
    }

    pub fn record_rlk_proof(
        &mut self,
        row: u32,
        component: RlkAggregationComponent,
        proof: Proof,
    ) -> Result<()> {
        self.validate_loaded()?;
        let index = row_slot(row, self.row_count()?)?;
        record_row_proof(
            &mut self.rlk_aggregation_proofs[index][component.index() as usize],
            proof,
        )
    }

    /// The row's RLK aggregation correlation for `component`.
    pub fn rlk_correlation(
        &self,
        row: u32,
        component: RlkAggregationComponent,
    ) -> Result<Option<CorrelationId>> {
        let index = row_slot(row, self.row_count()?)?;
        Ok(self.rlk_aggregation_correlations[index][component.index() as usize])
    }

    pub fn set_public_key_correlation(
        &mut self,
        row: u32,
        correlation: CorrelationId,
    ) -> Result<()> {
        let index = row_slot(row, self.row_count()?)?;
        set_row_correlation(
            &mut self.public_key_aggregation_correlations[index],
            correlation,
        )
    }

    pub fn set_rlk_correlation(
        &mut self,
        row: u32,
        component: RlkAggregationComponent,
        correlation: CorrelationId,
    ) -> Result<()> {
        let index = row_slot(row, self.row_count()?)?;
        set_row_correlation(
            &mut self.rlk_aggregation_correlations[index][component.index() as usize],
            correlation,
        )
    }

    pub fn clear_public_key_correlation(
        &mut self,
        row: u32,
        correlation: CorrelationId,
    ) -> Result<()> {
        let index = row_slot(row, self.row_count()?)?;
        clear_row_correlation(
            &mut self.public_key_aggregation_correlations[index],
            correlation,
        )
    }

    pub fn clear_rlk_correlation(
        &mut self,
        row: u32,
        component: RlkAggregationComponent,
        correlation: CorrelationId,
    ) -> Result<()> {
        let index = row_slot(row, self.row_count()?)?;
        clear_row_correlation(
            &mut self.rlk_aggregation_correlations[index][component.index() as usize],
            correlation,
        )
    }

    pub fn set_fold_correlation(&mut self, correlation: CorrelationId) -> Result<()> {
        ensure!(
            self.aggregation_fold_completed_rows < self.row_count()? as u32,
            "l-BFV aggregation fold is already complete"
        );
        ensure!(
            self.aggregation_fold_correlation.is_none()
                || self.aggregation_fold_correlation == Some(correlation),
            "l-BFV aggregation fold already has a different correlation"
        );
        self.aggregation_fold_correlation = Some(correlation);
        Ok(())
    }

    pub fn complete_fold(&mut self, correlation: CorrelationId, proof: Proof) -> Result<()> {
        ensure!(
            self.aggregation_fold_correlation == Some(correlation),
            "stale l-BFV aggregation fold response"
        );
        ensure!(
            self.aggregation_fold_completed_rows < self.row_count()? as u32,
            "l-BFV aggregation fold has too many rows"
        );
        self.aggregation_fold_proof = Some(proof);
        self.aggregation_fold_completed_rows += 1;
        self.aggregation_fold_correlation = None;
        Ok(())
    }

    pub fn clear_fold_correlation(&mut self, correlation: CorrelationId) -> Result<()> {
        ensure!(
            self.aggregation_fold_correlation == Some(correlation),
            "stale l-BFV aggregation fold correlation"
        );
        self.aggregation_fold_correlation = None;
        Ok(())
    }

    pub fn clear_process_correlations(&mut self) {
        self.public_key_aggregation_correlations.fill(None);
        self.rlk_aggregation_correlations.fill([None, None]);
        self.aggregation_fold_correlation = None;
        self.dkg_aggregation_correlation = None;
    }

    pub fn set_dkg_correlation(&mut self, correlation: CorrelationId) -> Result<()> {
        ensure!(
            self.aggregation_fold_completed_rows == self.row_count()? as u32
                && self.aggregation_fold_proof.is_some(),
            "l-BFV DKG aggregation requires a completed aggregation fold"
        );
        ensure!(
            self.dkg_aggregation_correlation.is_none()
                || self.dkg_aggregation_correlation == Some(correlation),
            "l-BFV DKG aggregation already has a different correlation"
        );
        ensure!(
            self.dkg_aggregated_proof.is_none(),
            "l-BFV DKG aggregation proof is already complete"
        );
        self.dkg_aggregation_correlation = Some(correlation);
        Ok(())
    }

    pub fn complete_dkg(&mut self, correlation: CorrelationId, proof: Proof) -> Result<()> {
        ensure!(
            self.dkg_aggregation_correlation == Some(correlation),
            "stale l-BFV DKG aggregation response"
        );
        if let Some(existing) = &self.dkg_aggregated_proof {
            ensure!(
                existing == &proof,
                "conflicting l-BFV DKG aggregation proof"
            );
        } else {
            self.dkg_aggregated_proof = Some(proof);
        }
        self.dkg_aggregation_correlation = None;
        Ok(())
    }

    pub fn clear_dkg_correlation(&mut self, correlation: CorrelationId) -> Result<()> {
        ensure!(
            self.dkg_aggregation_correlation == Some(correlation),
            "stale l-BFV DKG aggregation correlation"
        );
        self.dkg_aggregation_correlation = None;
        Ok(())
    }

    pub fn set_operational_keys(&mut self, public_key: ArcBytes, rlk: ArcBytes) -> Result<()> {
        self.validate_loaded()?;
        ensure!(
            !public_key.is_empty(),
            "operational l-BFV public key is empty"
        );
        ensure!(!rlk.is_empty(), "operational l-BFV RLK is empty");
        if let Some(existing) = &self.operational_public_key {
            ensure!(
                existing == &public_key,
                "conflicting operational l-BFV public key"
            );
        } else {
            self.operational_public_key = Some(public_key);
        }
        if let Some(existing) = &self.operational_rlk {
            ensure!(existing == &rlk, "conflicting operational l-BFV RLK");
        } else {
            self.operational_rlk = Some(rlk);
        }
        Ok(())
    }

    pub fn row_count(&self) -> Result<usize> {
        lbfv_row_count(self.params_preset)
            .ok_or_else(|| anyhow::anyhow!("selected preset does not support l-BFV"))
    }
}

fn row_slot(row: u32, row_count: usize) -> Result<usize> {
    let index = usize::try_from(row)?;
    ensure!(index < row_count, "l-BFV aggregation row is out of range");
    Ok(index)
}

fn record_row_proof(slot: &mut Option<Proof>, proof: Proof) -> Result<()> {
    if let Some(existing) = slot {
        ensure!(
            existing == &proof,
            "conflicting l-BFV aggregation row proof"
        );
    } else {
        *slot = Some(proof);
    }
    Ok(())
}

fn set_row_correlation(slot: &mut Option<CorrelationId>, correlation: CorrelationId) -> Result<()> {
    ensure!(
        slot.is_none() || *slot == Some(correlation),
        "l-BFV aggregation row already has a different correlation"
    );
    *slot = Some(correlation);
    Ok(())
}

fn clear_row_correlation(
    slot: &mut Option<CorrelationId>,
    correlation: CorrelationId,
) -> Result<()> {
    ensure!(
        *slot == Some(correlation),
        "l-BFV aggregation row correlation is stale"
    );
    *slot = None;
    Ok(())
}

#[cfg(test)]
mod aggregation_tests {
    use super::*;
    use alloy::primitives::{Address, B256, U256};

    fn aggregation_state() -> LbfvAggregationStateV1 {
        LbfvAggregationStateV1::new(
            E3id::new("7", 1),
            LbfvProofDomainContext {
                protocol_version: 4,
                chain_id: 1,
                interfold_address: Address::repeat_byte(0x11),
                e3_id: U256::from(7),
                crypto_config_id: B256::repeat_byte(0x22),
                finalized_committee_hash: B256::repeat_byte(0x33),
                lbfv_constants_version: 1,
                ciphertext_level: 0,
                key_level: 0,
            },
            vec![0, 2],
            BfvPreset::SecureThreshold16384,
        )
        .expect("state must be valid")
    }

    #[test]
    fn current_aggregation_schema_round_trips() {
        let state = aggregation_state();
        let encoded = bincode::serialize(&state).unwrap();
        let restored: LbfvAggregationStateV1 = bincode::deserialize(&encoded).unwrap();

        assert_eq!(restored, state);
        restored.validate_loaded().unwrap();
    }

    #[test]
    fn rlk_components_of_a_row_are_tracked_independently() {
        let mut state = aggregation_state();
        let d0 = CorrelationId::new();
        let d2 = CorrelationId::new();
        state
            .set_rlk_correlation(1, RlkAggregationComponent::D0, d0)
            .unwrap();
        state
            .set_rlk_correlation(1, RlkAggregationComponent::D2, d2)
            .unwrap();
        assert!(state
            .clear_rlk_correlation(1, RlkAggregationComponent::D0, d2)
            .is_err());

        let proof = |byte| {
            Proof::new(
                e3_events::CircuitName::RlkAggregation,
                ArcBytes::from_bytes(&[byte]),
                ArcBytes::from_bytes(&[byte]),
            )
        };
        state
            .record_rlk_proof(1, RlkAggregationComponent::D2, proof(2))
            .unwrap();
        state
            .clear_rlk_correlation(1, RlkAggregationComponent::D2, d2)
            .unwrap();
        assert_eq!(state.rlk_aggregation_proofs[1], [None, Some(proof(2))]);
        assert_eq!(
            state
                .rlk_correlation(1, RlkAggregationComponent::D0)
                .unwrap(),
            Some(d0)
        );
        assert!(state
            .record_rlk_proof(1, RlkAggregationComponent::D2, proof(3))
            .is_err());
    }

    #[test]
    fn process_correlations_are_cleared() {
        let mut state = aggregation_state();
        state.public_key_aggregation_correlations[0] = Some(CorrelationId::new());
        state.rlk_aggregation_correlations[1][1] = Some(CorrelationId::new());
        state.aggregation_fold_correlation = Some(CorrelationId::new());
        state.dkg_aggregation_correlation = Some(CorrelationId::new());

        state.clear_process_correlations();

        assert!(state
            .public_key_aggregation_correlations
            .iter()
            .all(Option::is_none));
        assert!(state
            .rlk_aggregation_correlations
            .iter()
            .flatten()
            .all(Option::is_none));
        assert!(state.aggregation_fold_correlation.is_none());
        assert!(state.dkg_aggregation_correlation.is_none());
    }

    #[test]
    fn a_zero_domain_field_is_rejected() {
        let mut state = aggregation_state();
        state.proof_domain.crypto_config_id = B256::ZERO;
        assert!(state.validate_loaded().is_err());

        let mut state = aggregation_state();
        state.proof_domain.interfold_address = Address::ZERO;
        assert!(state.validate_loaded().is_err());

        let mut state = aggregation_state();
        state.proof_domain.protocol_version = 0;
        assert!(state.validate_loaded().is_err());

        let mut state = aggregation_state();
        state.proof_domain.finalized_committee_hash = B256::ZERO;
        assert!(state.validate_loaded().is_err());
    }
}
