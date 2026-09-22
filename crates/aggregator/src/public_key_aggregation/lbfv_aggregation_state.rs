// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Durable secure-16384 l-BFV row aggregation state.

use anyhow::{ensure, Result};
use e3_committee_hash::LbfvProofDomainContext;
use e3_events::{CorrelationId, E3id, LbfvKeyShareDocument, LbfvPublicKeyAggregated, Proof};
use e3_fhe_params::{lbfv_row_count, BfvPreset};
use e3_utils::ArcBytes;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const LBFV_AGGREGATION_SCHEMA_VERSION: u32 = 4;
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

#[derive(Clone, Debug, PartialEq, Eq)]
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
    pub operational_public_key: Option<ArcBytes>,
    pub operational_rlk: Option<ArcBytes>,
    pub failure: Option<String>,
    pub params_preset: BfvPreset,
}

impl Serialize for LbfvAggregationStateV1 {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("LbfvAggregationStateV1", 19)?;
        state.serialize_field("schema_version", &self.schema_version)?;
        state.serialize_field("e3_id", &self.e3_id)?;
        state.serialize_field("proof_domain", &self.proof_domain)?;
        state.serialize_field("accepted_party_ids", &self.accepted_party_ids)?;
        state.serialize_field("public_key_documents", &self.public_key_documents)?;
        state.serialize_field("rlk_documents", &self.rlk_documents)?;
        state.serialize_field(
            "public_key_aggregation_proofs",
            &self.public_key_aggregation_proofs,
        )?;
        state.serialize_field("rlk_aggregation_proofs", &self.rlk_aggregation_proofs)?;
        state.serialize_field(
            "public_key_aggregation_correlations",
            &self.public_key_aggregation_correlations,
        )?;
        state.serialize_field(
            "rlk_aggregation_correlations",
            &self.rlk_aggregation_correlations,
        )?;
        state.serialize_field("aggregation_fold_proof", &self.aggregation_fold_proof)?;
        state.serialize_field(
            "aggregation_fold_correlation",
            &self.aggregation_fold_correlation,
        )?;
        state.serialize_field(
            "aggregation_fold_completed_rows",
            &self.aggregation_fold_completed_rows,
        )?;
        state.serialize_field(
            "dkg_aggregation_correlation",
            &self.dkg_aggregation_correlation,
        )?;
        state.serialize_field("dkg_aggregated_proof", &self.dkg_aggregated_proof)?;
        state.serialize_field("operational_rlk", &self.operational_rlk)?;
        state.serialize_field("failure", &self.failure)?;
        state.serialize_field("params_preset", &self.params_preset)?;
        state.serialize_field("operational_public_key", &self.operational_public_key)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for LbfvAggregationStateV1 {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct AggregationVisitor;

        impl<'de> serde::de::Visitor<'de> for AggregationVisitor {
            type Value = LbfvAggregationStateV1;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a versioned l-BFV aggregation state")
            }

            fn visit_seq<A>(self, mut sequence: A) -> std::result::Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                use serde::de::Error;
                let schema_version: u32 = sequence
                    .next_element()?
                    .ok_or_else(|| A::Error::custom("missing l-BFV aggregation schema version"))?;
                if schema_version != LBFV_AGGREGATION_SCHEMA_VERSION {
                    return Err(A::Error::custom(format!(
                        "unsupported l-BFV aggregation schema version {schema_version}"
                    )));
                }
                let e3_id = sequence
                    .next_element()?
                    .ok_or_else(|| A::Error::custom("missing l-BFV aggregation E3 ID"))?;
                let proof_domain = sequence
                    .next_element()?
                    .ok_or_else(|| A::Error::custom("missing l-BFV aggregation proof domain"))?;
                let accepted_party_ids = sequence.next_element()?.ok_or_else(|| {
                    A::Error::custom("missing l-BFV aggregation accepted parties")
                })?;
                let public_key_documents = sequence.next_element()?.ok_or_else(|| {
                    A::Error::custom("missing l-BFV aggregation public-key documents")
                })?;
                let rlk_documents = sequence
                    .next_element()?
                    .ok_or_else(|| A::Error::custom("missing l-BFV aggregation RLK documents"))?;
                let public_key_aggregation_proofs = sequence.next_element()?.ok_or_else(|| {
                    A::Error::custom("missing l-BFV public-key aggregation proofs")
                })?;
                let rlk_aggregation_proofs = sequence
                    .next_element()?
                    .ok_or_else(|| A::Error::custom("missing l-BFV RLK aggregation proofs"))?;
                let public_key_aggregation_correlations =
                    sequence.next_element()?.ok_or_else(|| {
                        A::Error::custom("missing l-BFV public-key aggregation correlations")
                    })?;
                let rlk_aggregation_correlations = sequence.next_element()?.ok_or_else(|| {
                    A::Error::custom("missing l-BFV RLK aggregation correlations")
                })?;
                let aggregation_fold_proof = sequence
                    .next_element()?
                    .ok_or_else(|| A::Error::custom("missing l-BFV aggregation fold proof"))?;
                let aggregation_fold_correlation = sequence.next_element()?.ok_or_else(|| {
                    A::Error::custom("missing l-BFV aggregation fold correlation")
                })?;
                let aggregation_fold_completed_rows = sequence
                    .next_element()?
                    .ok_or_else(|| A::Error::custom("missing l-BFV aggregation fold cursor"))?;
                let dkg_aggregation_correlation = sequence.next_element()?.ok_or_else(|| {
                    A::Error::custom("missing l-BFV final aggregation correlation")
                })?;
                let dkg_aggregated_proof = sequence
                    .next_element()?
                    .ok_or_else(|| A::Error::custom("missing l-BFV final aggregation proof"))?;
                let operational_rlk = sequence
                    .next_element()?
                    .ok_or_else(|| A::Error::custom("missing l-BFV operational RLK"))?;
                let failure = sequence
                    .next_element()?
                    .ok_or_else(|| A::Error::custom("missing l-BFV aggregation failure"))?;
                let params_preset = if schema_version == 1 {
                    BfvPreset::SecureThreshold16384
                } else {
                    sequence.next_element()?.ok_or_else(|| {
                        A::Error::custom("missing l-BFV aggregation parameter preset")
                    })?
                };
                let operational_public_key = if schema_version >= 3 {
                    sequence
                        .next_element()?
                        .ok_or_else(|| A::Error::custom("missing l-BFV operational public key"))?
                } else {
                    None
                };
                Ok(LbfvAggregationStateV1 {
                    schema_version: LBFV_AGGREGATION_SCHEMA_VERSION,
                    e3_id,
                    proof_domain,
                    accepted_party_ids,
                    public_key_documents,
                    rlk_documents,
                    public_key_aggregation_proofs,
                    rlk_aggregation_proofs,
                    public_key_aggregation_correlations,
                    rlk_aggregation_correlations,
                    aggregation_fold_proof,
                    aggregation_fold_correlation,
                    aggregation_fold_completed_rows,
                    dkg_aggregation_correlation,
                    dkg_aggregated_proof,
                    operational_public_key,
                    operational_rlk,
                    failure,
                    params_preset,
                })
            }
        }

        deserializer.deserialize_struct(
            "LbfvAggregationStateV1",
            &[
                "schema_version",
                "e3_id",
                "proof_domain",
                "accepted_party_ids",
                "public_key_documents",
                "rlk_documents",
                "public_key_aggregation_proofs",
                "rlk_aggregation_proofs",
                "public_key_aggregation_correlations",
                "rlk_aggregation_correlations",
                "aggregation_fold_proof",
                "aggregation_fold_correlation",
                "aggregation_fold_completed_rows",
                "dkg_aggregation_correlation",
                "dkg_aggregated_proof",
                "operational_rlk",
                "failure",
                "params_preset",
                "operational_public_key",
            ],
            AggregationVisitor,
        )
    }
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
            public_key_documents: BTreeMap::new(),
            rlk_documents: BTreeMap::new(),
            public_key_aggregation_proofs: vec![None; row_count],
            rlk_aggregation_proofs: vec![None; row_count],
            public_key_aggregation_correlations: vec![None; row_count],
            rlk_aggregation_correlations: vec![None; row_count],
            aggregation_fold_proof: None,
            aggregation_fold_correlation: None,
            aggregation_fold_completed_rows: 0,
            dkg_aggregation_correlation: None,
            dkg_aggregated_proof: None,
            operational_public_key: None,
            operational_rlk: None,
            failure: None,
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
        for (party_id, document) in &self.public_key_documents {
            ensure!(
                document.e3_id() == &self.e3_id
                    && document.context().proof_domain == self.proof_domain
                    && document.context().party_id == *party_id,
                "l-BFV public-key document identity does not match its party slot"
            );
            ensure!(
                document.row_count() == row_count,
                "l-BFV public-key document row count does not match the selected preset"
            );
        }
        for (party_id, document) in &self.rlk_documents {
            ensure!(
                document.e3_id() == &self.e3_id
                    && document.context().proof_domain == self.proof_domain
                    && document.context().party_id == *party_id,
                "l-BFV RLK document identity does not match its party slot"
            );
            ensure!(
                document.row_count() == row_count,
                "l-BFV RLK document row count does not match the selected preset"
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
        let row_count = self.row_count()?;
        record_row_proof(
            &mut self.public_key_aggregation_proofs,
            row,
            proof,
            row_count,
        )
    }

    pub fn record_rlk_proof(&mut self, row: u32, proof: Proof) -> Result<()> {
        self.validate_loaded()?;
        let row_count = self.row_count()?;
        record_row_proof(&mut self.rlk_aggregation_proofs, row, proof, row_count)
    }

    pub fn set_public_key_correlation(
        &mut self,
        row: u32,
        correlation: CorrelationId,
    ) -> Result<()> {
        let row_count = self.row_count()?;
        set_row_correlation(
            &mut self.public_key_aggregation_correlations,
            row,
            correlation,
            row_count,
        )
    }

    pub fn set_rlk_correlation(&mut self, row: u32, correlation: CorrelationId) -> Result<()> {
        let row_count = self.row_count()?;
        set_row_correlation(
            &mut self.rlk_aggregation_correlations,
            row,
            correlation,
            row_count,
        )
    }

    pub fn clear_public_key_correlation(
        &mut self,
        row: u32,
        correlation: CorrelationId,
    ) -> Result<()> {
        let row_count = self.row_count()?;
        clear_row_correlation(
            &mut self.public_key_aggregation_correlations,
            row,
            correlation,
            row_count,
        )
    }

    pub fn clear_rlk_correlation(&mut self, row: u32, correlation: CorrelationId) -> Result<()> {
        let row_count = self.row_count()?;
        clear_row_correlation(
            &mut self.rlk_aggregation_correlations,
            row,
            correlation,
            row_count,
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
        self.rlk_aggregation_correlations.fill(None);
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

    pub fn is_failed(&self) -> bool {
        self.failure.is_some()
    }

    pub fn fail(&mut self, reason: impl Into<String>) -> Result<()> {
        let reason = reason.into();
        ensure!(
            !reason.trim().is_empty(),
            "l-BFV aggregation failure is empty"
        );
        if let Some(existing) = &self.failure {
            ensure!(
                existing == &reason,
                "l-BFV aggregation failure is already terminal"
            );
        } else {
            self.failure = Some(reason);
        }
        self.clear_process_correlations();
        self.validate_loaded()
    }

    pub fn row_count(&self) -> Result<usize> {
        lbfv_row_count(self.params_preset)
            .ok_or_else(|| anyhow::anyhow!("selected preset does not support l-BFV"))
    }
}

fn record_row_proof(
    slots: &mut [Option<Proof>],
    row: u32,
    proof: Proof,
    row_count: usize,
) -> Result<()> {
    let index = usize::try_from(row)?;
    ensure!(index < row_count, "l-BFV aggregation row is out of range");
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
    row_count: usize,
) -> Result<()> {
    let index = usize::try_from(row)?;
    ensure!(index < row_count, "l-BFV aggregation row is out of range");
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
    row_count: usize,
) -> Result<()> {
    let index = usize::try_from(row)?;
    ensure!(index < row_count, "l-BFV aggregation row is out of range");
    ensure!(
        slots[index] == Some(correlation),
        "l-BFV aggregation row correlation is stale"
    );
    slots[index] = None;
    Ok(())
}

#[cfg(test)]
mod aggregation_tests {
    use super::*;
    use alloy::primitives::{Address, B256, U256};

    const LEGACY_AGGREGATION_STATE: &[u8] =
        include_bytes!("fixtures/lbfv_aggregation_state_v1.bincode");
    const SCHEMA_TWO_AGGREGATION_STATE: &[u8] =
        include_bytes!("fixtures/lbfv_aggregation_state_v2.bincode");

    #[derive(Serialize)]
    struct LegacyLbfvAggregationStateV1 {
        schema_version: u32,
        e3_id: E3id,
        proof_domain: LbfvProofDomainContext,
        accepted_party_ids: Vec<u32>,
        public_key_documents: BTreeMap<u32, LbfvKeyShareDocument>,
        rlk_documents: BTreeMap<u32, LbfvKeyShareDocument>,
        public_key_aggregation_proofs: Vec<Option<Proof>>,
        rlk_aggregation_proofs: Vec<Option<Proof>>,
        public_key_aggregation_correlations: Vec<Option<CorrelationId>>,
        rlk_aggregation_correlations: Vec<Option<CorrelationId>>,
        aggregation_fold_proof: Option<Proof>,
        aggregation_fold_correlation: Option<CorrelationId>,
        aggregation_fold_completed_rows: u32,
        dkg_aggregation_correlation: Option<CorrelationId>,
        dkg_aggregated_proof: Option<Proof>,
        operational_rlk: Option<ArcBytes>,
        failure: Option<String>,
    }

    #[derive(Serialize)]
    struct LegacyLbfvAggregationStateV2 {
        schema_version: u32,
        e3_id: E3id,
        proof_domain: LbfvProofDomainContext,
        accepted_party_ids: Vec<u32>,
        public_key_documents: BTreeMap<u32, LbfvKeyShareDocument>,
        rlk_documents: BTreeMap<u32, LbfvKeyShareDocument>,
        public_key_aggregation_proofs: Vec<Option<Proof>>,
        rlk_aggregation_proofs: Vec<Option<Proof>>,
        public_key_aggregation_correlations: Vec<Option<CorrelationId>>,
        rlk_aggregation_correlations: Vec<Option<CorrelationId>>,
        aggregation_fold_proof: Option<Proof>,
        aggregation_fold_correlation: Option<CorrelationId>,
        aggregation_fold_completed_rows: u32,
        dkg_aggregation_correlation: Option<CorrelationId>,
        dkg_aggregated_proof: Option<Proof>,
        operational_rlk: Option<ArcBytes>,
        failure: Option<String>,
        params_preset: BfvPreset,
    }

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

    fn legacy_state() -> LegacyLbfvAggregationStateV1 {
        let state = aggregation_state();
        LegacyLbfvAggregationStateV1 {
            schema_version: 1,
            e3_id: state.e3_id,
            proof_domain: state.proof_domain,
            accepted_party_ids: state.accepted_party_ids,
            public_key_documents: state.public_key_documents,
            rlk_documents: state.rlk_documents,
            public_key_aggregation_proofs: state.public_key_aggregation_proofs,
            rlk_aggregation_proofs: state.rlk_aggregation_proofs,
            public_key_aggregation_correlations: state.public_key_aggregation_correlations,
            rlk_aggregation_correlations: state.rlk_aggregation_correlations,
            aggregation_fold_proof: state.aggregation_fold_proof,
            aggregation_fold_correlation: state.aggregation_fold_correlation,
            aggregation_fold_completed_rows: state.aggregation_fold_completed_rows,
            dkg_aggregation_correlation: state.dkg_aggregation_correlation,
            dkg_aggregated_proof: state.dkg_aggregated_proof,
            operational_rlk: state.operational_rlk,
            failure: state.failure,
        }
    }

    fn schema_two_state() -> LegacyLbfvAggregationStateV2 {
        let state = aggregation_state();
        LegacyLbfvAggregationStateV2 {
            schema_version: 2,
            e3_id: state.e3_id,
            proof_domain: state.proof_domain,
            accepted_party_ids: state.accepted_party_ids,
            public_key_documents: state.public_key_documents,
            rlk_documents: state.rlk_documents,
            public_key_aggregation_proofs: state.public_key_aggregation_proofs,
            rlk_aggregation_proofs: state.rlk_aggregation_proofs,
            public_key_aggregation_correlations: state.public_key_aggregation_correlations,
            rlk_aggregation_correlations: state.rlk_aggregation_correlations,
            aggregation_fold_proof: state.aggregation_fold_proof,
            aggregation_fold_correlation: state.aggregation_fold_correlation,
            aggregation_fold_completed_rows: state.aggregation_fold_completed_rows,
            dkg_aggregation_correlation: state.dkg_aggregation_correlation,
            dkg_aggregated_proof: state.dkg_aggregated_proof,
            operational_rlk: state.operational_rlk,
            failure: state.failure,
            params_preset: state.params_preset,
        }
    }

    #[test]
    fn legacy_aggregation_fixture_is_rejected_after_codec_cutover() {
        assert_eq!(
            bincode::serialize(&legacy_state()).unwrap(),
            LEGACY_AGGREGATION_STATE
        );

        let error = bincode::deserialize::<LbfvAggregationStateV1>(LEGACY_AGGREGATION_STATE)
            .expect_err("pre-cutover aggregation state must be rejected");
        assert!(error
            .to_string()
            .contains("unsupported l-BFV aggregation schema version 1"));
    }

    #[test]
    fn schema_two_aggregation_fixture_is_rejected_after_codec_cutover() {
        assert_eq!(
            bincode::serialize(&schema_two_state()).unwrap(),
            SCHEMA_TWO_AGGREGATION_STATE
        );

        let error = bincode::deserialize::<LbfvAggregationStateV1>(SCHEMA_TWO_AGGREGATION_STATE)
            .expect_err("pre-cutover aggregation state must be rejected");
        assert!(error
            .to_string()
            .contains("unsupported l-BFV aggregation schema version 2"));
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
    fn failure_is_immutable_and_clears_process_correlations() {
        let mut state = aggregation_state();
        state.public_key_aggregation_correlations[0] = Some(CorrelationId::new());
        state.rlk_aggregation_correlations[1] = Some(CorrelationId::new());
        state.aggregation_fold_correlation = Some(CorrelationId::new());
        state.dkg_aggregation_correlation = Some(CorrelationId::new());

        state
            .fail("worker failed")
            .expect("first failure must persist");
        state
            .fail("worker failed")
            .expect("the same failure must be idempotent");

        assert!(state.is_failed());
        assert!(state
            .public_key_aggregation_correlations
            .iter()
            .all(Option::is_none));
        assert!(state
            .rlk_aggregation_correlations
            .iter()
            .all(Option::is_none));
        assert!(state.aggregation_fold_correlation.is_none());
        assert!(state.dkg_aggregation_correlation.is_none());
        assert!(state.fail("another failure").is_err());
    }
}
