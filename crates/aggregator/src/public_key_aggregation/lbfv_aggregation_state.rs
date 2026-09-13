// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Durable secure-16384 l-BFV row aggregation state.

use anyhow::{ensure, Result};
use e3_committee_hash::LbfvProofDomainContext;
use e3_events::{CorrelationId, E3id, LbfvKeyShareDocument, LbfvPublicKeyAggregated, Proof};
use e3_utils::ArcBytes;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const LBFV_AGGREGATION_SCHEMA_VERSION: u32 = 1;
pub const LBFV_ROW_COUNT: usize = 5;
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
        }
        Ok(())
    }
}

#[cfg(test)]
mod publication_tests {
    use super::*;
    use alloy::primitives::Address;
    use e3_events::{CircuitName, OrderedSet};

    fn publication(e3_id: E3id, circuit: CircuitName) -> LbfvPublicKeyAggregated {
        LbfvPublicKeyAggregated {
            pubkey: ArcBytes::from_bytes(&[1]),
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
    fn publication_state_accepts_the_v2_intent() {
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
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LbfvAggregationStateV1 {
    pub schema_version: u32,
    pub e3_id: E3id,
    pub proof_domain: LbfvProofDomainContext,
    pub accepted_party_ids: Vec<u32>,
    pub public_key_documents: BTreeMap<u32, LbfvKeyShareDocument>,
    pub rlk_documents: BTreeMap<u32, LbfvKeyShareDocument>,
    pub public_key_aggregation_proofs: Vec<Option<Proof>>,
    pub rlk_aggregation_proofs: Vec<Option<Proof>>,
    pub public_key_aggregation_correlations: Vec<Option<CorrelationId>>,
    pub rlk_aggregation_correlations: Vec<Option<CorrelationId>>,
    pub aggregation_fold_proof: Option<Proof>,
    pub aggregation_fold_correlation: Option<CorrelationId>,
    pub aggregation_fold_completed_rows: u32,
    pub dkg_aggregation_correlation: Option<CorrelationId>,
    pub dkg_aggregated_proof: Option<Proof>,
    pub operational_rlk: Option<ArcBytes>,
    pub failure: Option<String>,
}

impl LbfvAggregationStateV1 {
    pub fn new(
        e3_id: E3id,
        proof_domain: LbfvProofDomainContext,
        accepted_party_ids: Vec<u32>,
    ) -> Result<Self> {
        let state = Self {
            schema_version: LBFV_AGGREGATION_SCHEMA_VERSION,
            e3_id,
            proof_domain,
            accepted_party_ids,
            public_key_documents: BTreeMap::new(),
            rlk_documents: BTreeMap::new(),
            public_key_aggregation_proofs: vec![None; LBFV_ROW_COUNT],
            rlk_aggregation_proofs: vec![None; LBFV_ROW_COUNT],
            public_key_aggregation_correlations: vec![None; LBFV_ROW_COUNT],
            rlk_aggregation_correlations: vec![None; LBFV_ROW_COUNT],
            aggregation_fold_proof: None,
            aggregation_fold_correlation: None,
            aggregation_fold_completed_rows: 0,
            dkg_aggregation_correlation: None,
            dkg_aggregated_proof: None,
            operational_rlk: None,
            failure: None,
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
        ensure!(
            self.public_key_aggregation_proofs.len() == LBFV_ROW_COUNT
                && self.rlk_aggregation_proofs.len() == LBFV_ROW_COUNT
                && self.public_key_aggregation_correlations.len() == LBFV_ROW_COUNT
                && self.rlk_aggregation_correlations.len() == LBFV_ROW_COUNT,
            "l-BFV aggregation proof families must contain five rows"
        );
        ensure!(
            self.aggregation_fold_completed_rows <= LBFV_ROW_COUNT as u32,
            "l-BFV aggregation fold row cursor is out of range"
        );
        for (party_id, document) in &self.public_key_documents {
            ensure!(
                document.e3_id() == &self.e3_id
                    && document.context().proof_domain == self.proof_domain
                    && document.context().party_id == *party_id,
                "l-BFV public-key document identity does not match its party slot"
            );
        }
        for (party_id, document) in &self.rlk_documents {
            ensure!(
                document.e3_id() == &self.e3_id
                    && document.context().proof_domain == self.proof_domain
                    && document.context().party_id == *party_id,
                "l-BFV RLK document identity does not match its party slot"
            );
        }
        if let Some(failure) = &self.failure {
            ensure!(
                !failure.trim().is_empty(),
                "l-BFV aggregation failure is empty"
            );
        }
        Ok(())
    }

    pub fn record_document(&mut self, document: LbfvKeyShareDocument) -> Result<bool> {
        self.validate_loaded()?;
        ensure!(
            document.e3_id() == &self.e3_id,
            "l-BFV document has the wrong E3 ID"
        );
        let party_id = document.context().party_id;
        ensure!(
            self.accepted_party_ids.binary_search(&party_id).is_ok(),
            "l-BFV document party is not in the accepted set"
        );
        let target = match document.role() {
            e3_events::LbfvKeyShareDocumentRole::PublicKey => &mut self.public_key_documents,
            e3_events::LbfvKeyShareDocumentRole::RelinearizationKey => &mut self.rlk_documents,
        };
        if let Some(existing) = target.get(&party_id) {
            ensure!(
                existing == &document,
                "conflicting l-BFV aggregation document"
            );
            return Ok(false);
        }
        target.insert(party_id, document);
        Ok(true)
    }

    pub fn record_public_key_proof(&mut self, row: u32, proof: Proof) -> Result<()> {
        self.validate_loaded()?;
        record_row_proof(&mut self.public_key_aggregation_proofs, row, proof)
    }

    pub fn record_rlk_proof(&mut self, row: u32, proof: Proof) -> Result<()> {
        self.validate_loaded()?;
        record_row_proof(&mut self.rlk_aggregation_proofs, row, proof)
    }

    pub fn set_public_key_correlation(
        &mut self,
        row: u32,
        correlation: CorrelationId,
    ) -> Result<()> {
        set_row_correlation(
            &mut self.public_key_aggregation_correlations,
            row,
            correlation,
        )
    }

    pub fn set_rlk_correlation(&mut self, row: u32, correlation: CorrelationId) -> Result<()> {
        set_row_correlation(&mut self.rlk_aggregation_correlations, row, correlation)
    }

    pub fn clear_public_key_correlation(
        &mut self,
        row: u32,
        correlation: CorrelationId,
    ) -> Result<()> {
        clear_row_correlation(
            &mut self.public_key_aggregation_correlations,
            row,
            correlation,
        )
    }

    pub fn clear_rlk_correlation(&mut self, row: u32, correlation: CorrelationId) -> Result<()> {
        clear_row_correlation(&mut self.rlk_aggregation_correlations, row, correlation)
    }

    pub fn set_fold_correlation(&mut self, correlation: CorrelationId) -> Result<()> {
        ensure!(
            self.aggregation_fold_completed_rows < LBFV_ROW_COUNT as u32,
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
            self.aggregation_fold_completed_rows < LBFV_ROW_COUNT as u32,
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
        self.rlk_aggregation_correlations.fill(None);
        self.aggregation_fold_correlation = None;
        self.dkg_aggregation_correlation = None;
    }

    pub fn set_dkg_correlation(&mut self, correlation: CorrelationId) -> Result<()> {
        ensure!(
            self.aggregation_fold_completed_rows == LBFV_ROW_COUNT as u32
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

    pub fn set_fold_proof(&mut self, proof: Proof) -> Result<()> {
        self.validate_loaded()?;
        if let Some(existing) = &self.aggregation_fold_proof {
            ensure!(
                existing == &proof,
                "conflicting l-BFV aggregation fold proof"
            );
        } else {
            self.aggregation_fold_proof = Some(proof);
        }
        Ok(())
    }

    pub fn set_operational_rlk(&mut self, rlk: ArcBytes) -> Result<()> {
        self.validate_loaded()?;
        ensure!(!rlk.is_empty(), "operational l-BFV RLK is empty");
        if let Some(existing) = &self.operational_rlk {
            ensure!(existing == &rlk, "conflicting operational l-BFV RLK");
        } else {
            self.operational_rlk = Some(rlk);
        }
        Ok(())
    }

    pub fn fail(&mut self, reason: impl Into<String>) -> Result<()> {
        self.failure = Some(reason.into());
        self.validate_loaded()
    }
}

fn record_row_proof(slots: &mut [Option<Proof>], row: u32, proof: Proof) -> Result<()> {
    let index = usize::try_from(row)?;
    ensure!(
        index < LBFV_ROW_COUNT,
        "l-BFV aggregation row is out of range"
    );
    if let Some(existing) = &slots[index] {
        ensure!(
            existing == &proof,
            "conflicting l-BFV aggregation row proof"
        );
    } else {
        slots[index] = Some(proof);
    }
    Ok(())
}

fn set_row_correlation(
    slots: &mut [Option<CorrelationId>],
    row: u32,
    correlation: CorrelationId,
) -> Result<()> {
    let index = usize::try_from(row)?;
    ensure!(
        index < LBFV_ROW_COUNT,
        "l-BFV aggregation row is out of range"
    );
    ensure!(
        slots[index].is_none() || slots[index] == Some(correlation),
        "l-BFV aggregation row already has a different correlation"
    );
    slots[index] = Some(correlation);
    Ok(())
}

fn clear_row_correlation(
    slots: &mut [Option<CorrelationId>],
    row: u32,
    correlation: CorrelationId,
) -> Result<()> {
    let index = usize::try_from(row)?;
    ensure!(
        index < LBFV_ROW_COUNT,
        "l-BFV aggregation row is out of range"
    );
    ensure!(
        slots[index] == Some(correlation),
        "l-BFV aggregation row correlation is stale"
    );
    slots[index] = None;
    Ok(())
}
