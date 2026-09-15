// SPDX-License-Identifier: LGPL-3.0-only

//! Dispatch and correlate secure-16384 l-BFV row aggregation proofs.

use super::super::*;
use crate::{LbfvAggregationStateV1, LBFV_ROW_COUNT};
use e3_events::{
    ComputeRequest, LbfvAggregationFoldRequest, LbfvKeyShareDocument,
    LbfvPkAggregationProofRequest, RlkAggregationProofRequest, ZkRequest,
};
use e3_trbfv::lbfv_operation::LbfvOperationId;

impl PublicKeyAggregator {
    pub(in crate::actors::publickey_aggregator) fn try_dispatch_lbfv_aggregation_rows(
        &mut self,
        ec: &EventContext<Sequenced>,
    ) -> Result<()> {
        if !self.is_lbfv() || !self.can_run_aggregation_effects() {
            return Ok(());
        }
        let Some(mut state) = self.lbfv_aggregation_state()? else {
            return Ok(());
        };
        state.validate_loaded()?;
        if state.is_failed() {
            return Ok(());
        }
        let expected_h = self.committee_size.values().h;
        anyhow::ensure!(
            state.accepted_party_ids.len() == expected_h,
            "l-BFV aggregation sidecar accepted set does not match H"
        );
        if state
            .accepted_party_ids
            .iter()
            .any(|party_id| !state.public_key_documents.contains_key(party_id))
            || state
                .accepted_party_ids
                .iter()
                .any(|party_id| !state.rlk_documents.contains_key(party_id))
        {
            return Ok(());
        }

        let party_ids = state.accepted_party_ids.clone();
        let public_key_shares = document_shares(
            &state,
            |document| matches!(document, LbfvKeyShareDocument::PublicKeyV1(_)),
            "public-key",
        )?;
        let rlk_shares = document_shares(
            &state,
            |document| matches!(document, LbfvKeyShareDocument::RelinearizationKeyV1(_)),
            "relinearization-key",
        )?;
        let mut requests = Vec::new();

        for row_index in 0..LBFV_ROW_COUNT as u32 {
            if state.public_key_aggregation_proofs[row_index as usize].is_none()
                && state.public_key_aggregation_correlations[row_index as usize].is_none()
            {
                let mut request = LbfvPkAggregationProofRequest {
                    operation_id: LbfvOperationId([0; 32]),
                    proof_domain: state.proof_domain,
                    aggregator_party_id: self.local_party_id,
                    party_ids: party_ids.clone(),
                    share_bytes: public_key_shares.clone(),
                    row_index,
                    params_preset: self.params_preset,
                    committee_size: self.committee_size,
                };
                request.operation_id = request.expected_operation_id()?;
                let correlation = CorrelationId::new();
                state.set_public_key_correlation(row_index, correlation)?;
                requests.push((correlation, ZkRequest::LbfvPkAggregation(request)));
            }

            if state.rlk_aggregation_proofs[row_index as usize].is_none()
                && state.rlk_aggregation_correlations[row_index as usize].is_none()
            {
                let mut request = RlkAggregationProofRequest {
                    operation_id: LbfvOperationId([0; 32]),
                    proof_domain: state.proof_domain,
                    aggregator_party_id: self.local_party_id,
                    party_ids: party_ids.clone(),
                    share_bytes: rlk_shares.clone(),
                    row_index,
                    params_preset: self.params_preset,
                    committee_size: self.committee_size,
                };
                request.operation_id = request.expected_operation_id()?;
                let correlation = CorrelationId::new();
                state.set_rlk_correlation(row_index, correlation)?;
                requests.push((correlation, ZkRequest::RlkAggregation(request)));
            }
        }

        if requests.is_empty() {
            return Ok(());
        }

        self.set_lbfv_aggregation(state, ec)?;
        for (correlation, request) in requests {
            self.bus.publish(
                ComputeRequest::zk(request, correlation, self.e3_id.clone()),
                ec.clone(),
            )?;
        }
        Ok(())
    }

    pub(in crate::actors::publickey_aggregator) fn handle_lbfv_aggregation_response(
        &mut self,
        correlation: CorrelationId,
        response: ZkResponse,
        ec: &EventContext<Sequenced>,
    ) -> Result<()> {
        let Some(mut state) = self.lbfv_aggregation_state()? else {
            return Ok(());
        };
        if state.is_failed() {
            return Ok(());
        }
        match response {
            ZkResponse::LbfvPkAggregation(response) => {
                let row = response.row_index;
                let index = usize::try_from(row)?;
                anyhow::ensure!(
                    index < LBFV_ROW_COUNT,
                    "l-BFV PK aggregation row is out of range"
                );
                anyhow::ensure!(
                    state.public_key_aggregation_correlations[index] == Some(correlation),
                    "stale l-BFV PK aggregation response"
                );
                anyhow::ensure!(
                    response.party_ids == state.accepted_party_ids,
                    "l-BFV PK aggregation party set changed"
                );
                let expected = expected_pk_operation_id(&state, self, row)?;
                anyhow::ensure!(
                    response.operation_id == expected,
                    "l-BFV PK aggregation operation ID changed"
                );
                state.record_public_key_proof(row, response.proof)?;
                state.clear_public_key_correlation(row, correlation)?;
            }
            ZkResponse::RlkAggregation(response) => {
                let row = response.row_index;
                let index = usize::try_from(row)?;
                anyhow::ensure!(
                    index < LBFV_ROW_COUNT,
                    "l-BFV RLK aggregation row is out of range"
                );
                anyhow::ensure!(
                    state.rlk_aggregation_correlations[index] == Some(correlation),
                    "stale l-BFV RLK aggregation response"
                );
                anyhow::ensure!(
                    response.party_ids == state.accepted_party_ids,
                    "l-BFV RLK aggregation party set changed"
                );
                let expected = expected_rlk_operation_id(&state, self, row)?;
                anyhow::ensure!(
                    response.operation_id == expected,
                    "l-BFV RLK aggregation operation ID changed"
                );
                state.record_rlk_proof(row, response.proof)?;
                state.clear_rlk_correlation(row, correlation)?;
            }
            ZkResponse::LbfvAggregationFold(response) => {
                anyhow::ensure!(
                    state.aggregation_fold_correlation == Some(correlation),
                    "stale l-BFV aggregation fold response"
                );
                state.complete_fold(correlation, response.proof)?;
            }
            _ => return Ok(()),
        }
        let fold_complete = state.aggregation_fold_completed_rows == LBFV_ROW_COUNT as u32;
        self.set_lbfv_aggregation(state, ec)?;
        self.try_dispatch_lbfv_aggregation_fold(ec)?;
        if fold_complete {
            self.persist_operational_lbfv_rlk(ec)?;
            self.try_dispatch_dkg_aggregation(ec)?;
        }
        Ok(())
    }

    pub(in crate::actors::publickey_aggregator) fn handle_lbfv_aggregation_error(
        &mut self,
        correlation: CorrelationId,
        error: &str,
        ec: &EventContext<Sequenced>,
    ) -> Result<bool> {
        let Some(mut state) = self.lbfv_aggregation_state()? else {
            return Ok(false);
        };
        if state.is_failed() {
            return Ok(false);
        }
        let mut matched = false;
        for row in 0..LBFV_ROW_COUNT as u32 {
            let index = row as usize;
            if state.public_key_aggregation_correlations[index] == Some(correlation) {
                state.clear_public_key_correlation(row, correlation)?;
                matched = true;
            }
            if state.rlk_aggregation_correlations[index] == Some(correlation) {
                state.clear_rlk_correlation(row, correlation)?;
                matched = true;
            }
        }
        if state.aggregation_fold_correlation == Some(correlation) {
            state.clear_fold_correlation(correlation)?;
            matched = true;
        }
        if state.dkg_aggregation_correlation == Some(correlation) {
            state.clear_dkg_correlation(correlation)?;
            matched = true;
        }
        if !matched {
            return Ok(false);
        }
        state.fail(format!(
            "l-BFV aggregation proof generation failed: {error}"
        ))?;
        self.set_lbfv_aggregation(state, ec)?;
        self.bus.publish(
            E3Failed {
                e3_id: self.e3_id.clone(),
                failed_at_stage: E3Stage::CommitteeFinalized,
                reason: FailureReason::DKGInvalidShares,
            },
            ec.clone(),
        )?;
        Ok(true)
    }

    pub(in crate::actors::publickey_aggregator) fn try_dispatch_lbfv_aggregation_fold(
        &mut self,
        ec: &EventContext<Sequenced>,
    ) -> Result<()> {
        if !self.is_lbfv() || !self.can_run_aggregation_effects() {
            return Ok(());
        }
        let Some(mut state) = self.lbfv_aggregation_state()? else {
            return Ok(());
        };
        state.validate_loaded()?;
        if state.is_failed() {
            return Ok(());
        }
        if state.aggregation_fold_completed_rows == LBFV_ROW_COUNT as u32
            || state.aggregation_fold_correlation.is_some()
        {
            return Ok(());
        }
        let row = state.aggregation_fold_completed_rows as usize;
        let (Some(pk_proof), Some(rlk_proof)) = (
            state.public_key_aggregation_proofs[row].clone(),
            state.rlk_aggregation_proofs[row].clone(),
        ) else {
            return Ok(());
        };
        let request = LbfvAggregationFoldRequest {
            pk_proof,
            rlk_proof,
            prior_accumulator: state.aggregation_fold_proof.clone(),
            row_index: row as u32,
            params_preset: self.params_preset,
            committee_size: self.committee_size,
        };
        let correlation = CorrelationId::new();
        state.set_fold_correlation(correlation)?;
        self.set_lbfv_aggregation(state, ec)?;
        self.bus.publish(
            ComputeRequest::zk(
                ZkRequest::LbfvAggregationFold(request),
                correlation,
                self.e3_id.clone(),
            ),
            ec.clone(),
        )?;
        Ok(())
    }

    pub(in crate::actors::publickey_aggregator) fn persist_operational_lbfv_rlk(
        &mut self,
        ec: &EventContext<Sequenced>,
    ) -> Result<()> {
        if !self.is_lbfv() {
            return Ok(());
        }
        let Some(mut state) = self.lbfv_aggregation_state()? else {
            return Ok(());
        };
        state.validate_loaded()?;
        if state.is_failed() {
            return Ok(());
        }
        if state.operational_rlk.is_some() {
            return Ok(());
        }
        anyhow::ensure!(
            state.aggregation_fold_completed_rows == LBFV_ROW_COUNT as u32
                && state.aggregation_fold_proof.is_some(),
            "operational l-BFV RLK requires a completed aggregation fold"
        );
        let public_key_shares = document_shares(
            &state,
            |document| matches!(document, LbfvKeyShareDocument::PublicKeyV1(_)),
            "public-key",
        )?;
        let rlk_shares = document_shares(
            &state,
            |document| matches!(document, LbfvKeyShareDocument::RelinearizationKeyV1(_)),
            "relinearization-key",
        )?;
        let operational_rlk = e3_trbfv::aggregate_lbfv::aggregate_lbfv_relinearization_key(
            self.params_preset,
            &public_key_shares,
            &rlk_shares,
        )?;
        state.set_operational_rlk(operational_rlk)?;
        self.set_lbfv_aggregation(state, ec)
    }
}

fn document_shares(
    state: &LbfvAggregationStateV1,
    role: impl Fn(&LbfvKeyShareDocument) -> bool,
    name: &str,
) -> Result<Vec<e3_utils::ArcBytes>> {
    state
        .accepted_party_ids
        .iter()
        .map(|party_id| {
            let document = match name {
                "public-key" => state.public_key_documents.get(party_id),
                "relinearization-key" => state.rlk_documents.get(party_id),
                _ => None,
            }
            .ok_or_else(|| {
                anyhow::anyhow!("accepted l-BFV party {party_id} has no {name} document")
            })?;
            anyhow::ensure!(
                role(document),
                "accepted l-BFV party {party_id} has the wrong {name} document role"
            );
            Ok(match document {
                LbfvKeyShareDocument::PublicKeyV1(document) => document.share.clone(),
                LbfvKeyShareDocument::RelinearizationKeyV1(document) => document.share.clone(),
            })
        })
        .collect()
}

fn expected_pk_operation_id(
    state: &LbfvAggregationStateV1,
    actor: &PublicKeyAggregator,
    row_index: u32,
) -> Result<LbfvOperationId> {
    let request = LbfvPkAggregationProofRequest {
        operation_id: LbfvOperationId([0; 32]),
        proof_domain: state.proof_domain,
        aggregator_party_id: actor.local_party_id,
        party_ids: state.accepted_party_ids.clone(),
        share_bytes: document_shares(
            state,
            |document| matches!(document, LbfvKeyShareDocument::PublicKeyV1(_)),
            "public-key",
        )?,
        row_index,
        params_preset: actor.params_preset,
        committee_size: actor.committee_size,
    };
    Ok(request.expected_operation_id()?)
}

fn expected_rlk_operation_id(
    state: &LbfvAggregationStateV1,
    actor: &PublicKeyAggregator,
    row_index: u32,
) -> Result<LbfvOperationId> {
    let request = RlkAggregationProofRequest {
        operation_id: LbfvOperationId([0; 32]),
        proof_domain: state.proof_domain,
        aggregator_party_id: actor.local_party_id,
        party_ids: state.accepted_party_ids.clone(),
        share_bytes: document_shares(
            state,
            |document| matches!(document, LbfvKeyShareDocument::RelinearizationKeyV1(_)),
            "relinearization-key",
        )?,
        row_index,
        params_preset: actor.params_preset,
        committee_size: actor.committee_size,
    };
    Ok(request.expected_operation_id()?)
}
