// SPDX-License-Identifier: LGPL-3.0-only

//! Dispatch and correlate l-BFV row aggregation proofs.

use super::super::*;
use crate::{
    LbfvAggregationStateV1, LbfvContributionCollectionStateV1, LbfvContributionRepositoryFactory,
    LbfvContributionVerificationStateV1,
};
use e3_events::{
    ComputeRequest, LbfvAggregationFoldRequest, LbfvKeyShareDocument,
    LbfvPkAggregationProofRequest, RlkAggregationProofRequest, ZkRequest,
};
use e3_trbfv::lbfv_operation::LbfvOperationId;
use e3_zk_witness::threshold::rlk_aggregation::RlkAggregationComponent;

/// Read the accepted parties' key shares of a sealed collection from its content-addressed
/// documents, in ascending party order. A missing or mismatched document is an error: the sealed
/// set lists only parties whose documents were durable and validated.
pub(in crate::actors::publickey_aggregator) async fn load_lbfv_accepted_shares(
    repositories: &Repositories,
    collection: &LbfvContributionCollectionStateV1,
) -> Result<LbfvAcceptedShares> {
    let LbfvContributionVerificationStateV1::Sealed {
        accepted_parties, ..
    } = &collection.verification
    else {
        anyhow::bail!("l-BFV accepted shares require a sealed collection");
    };
    let mut shares = LbfvAcceptedShares {
        public_key: Vec::with_capacity(accepted_parties.len()),
        relinearization_key: Vec::with_capacity(accepted_parties.len()),
    };
    for accepted in accepted_parties {
        let party_id = accepted.party_id;
        let manifest = collection
            .parties
            .get(&party_id)
            .and_then(|party| party.manifest.as_ref())
            .ok_or_else(|| anyhow::anyhow!("sealed l-BFV party {party_id} has no manifest"))?;
        let (public_key_hash, rlk_hash) =
            crate::domain::lbfv_contribution_collection::manifest_hashes(&manifest.payload);
        let public_key = read_accepted_document(
            repositories,
            &collection.e3_id,
            &public_key_hash,
            party_id,
            "public-key",
        )
        .await?;
        let rlk = read_accepted_document(
            repositories,
            &collection.e3_id,
            &rlk_hash,
            party_id,
            "relinearization-key",
        )
        .await?;
        anyhow::ensure!(
            public_key.role() == e3_events::LbfvKeyShareDocumentRole::PublicKey
                && rlk.role() == e3_events::LbfvKeyShareDocumentRole::RelinearizationKey,
            "accepted l-BFV party {party_id} has a document with the wrong role"
        );
        shares.public_key.push(public_key.share().clone());
        shares.relinearization_key.push(rlk.share().clone());
    }
    Ok(shares)
}

async fn read_accepted_document(
    repositories: &Repositories,
    e3_id: &E3id,
    content_hash: &alloy::primitives::B256,
    party_id: u32,
    name: &str,
) -> Result<LbfvKeyShareDocument> {
    let document = repositories
        .publickey_lbfv_document(e3_id, content_hash)
        .read()
        .await?
        .ok_or_else(|| anyhow::anyhow!("accepted l-BFV party {party_id} has no {name} document"))?;
    anyhow::ensure!(
        document.context().party_id == party_id,
        "accepted l-BFV party {party_id} has a {name} document of another party"
    );
    Ok(document)
}

impl PublicKeyAggregator {
    /// The one place that builds a PK-aggregation request: the dispatch and the response check
    /// both use it, so the operation ID that a response must carry cannot drift from the one that
    /// the request carried.
    fn pk_aggregation_request(
        &self,
        state: &LbfvAggregationStateV1,
        shares: &LbfvAcceptedShares,
        row_index: u32,
    ) -> Result<LbfvPkAggregationProofRequest> {
        let mut request = LbfvPkAggregationProofRequest {
            operation_id: LbfvOperationId([0; 32]),
            proof_domain: state.proof_domain,
            aggregator_party_id: self.local_party_id,
            party_ids: state.accepted_party_ids.clone(),
            share_bytes: shares.public_key.clone(),
            row_index,
            params_preset: self.params_profile.threshold_preset(),
            committee_size: self.committee_size,
        };
        request.operation_id = request.expected_operation_id()?;
        Ok(request)
    }

    /// The one place that builds an RLK-aggregation request. See [`Self::pk_aggregation_request`].
    fn rlk_aggregation_request(
        &self,
        state: &LbfvAggregationStateV1,
        shares: &LbfvAcceptedShares,
        row_index: u32,
        component: RlkAggregationComponent,
    ) -> Result<RlkAggregationProofRequest> {
        let mut request = RlkAggregationProofRequest {
            operation_id: LbfvOperationId([0; 32]),
            proof_domain: state.proof_domain,
            aggregator_party_id: self.local_party_id,
            party_ids: state.accepted_party_ids.clone(),
            share_bytes: shares.relinearization_key.clone(),
            row_index,
            component,
            params_preset: self.params_profile.threshold_preset(),
            committee_size: self.committee_size,
        };
        request.operation_id = request.expected_operation_id()?;
        Ok(request)
    }

    pub(in crate::actors::publickey_aggregator) fn try_dispatch_lbfv_aggregation_rows(
        &mut self,
        ec: &EventContext<Sequenced>,
    ) -> Result<()> {
        if !self.is_lbfv() || !self.can_continue_aggregation_effects() {
            return Ok(());
        }
        let Some(mut state) = self.lbfv_aggregation_state()? else {
            return Ok(());
        };
        state.validate_loaded()?;
        let Some(shares) = self.lbfv_shares.clone() else {
            tracing::debug!(
                e3_id = %self.e3_id,
                "l-BFV row aggregation is waiting for the accepted parties' shares"
            );
            return Ok(());
        };
        let row_count = state.row_count()?;
        let expected_h = self.committee_size.values().h;
        anyhow::ensure!(
            state.accepted_party_ids.len() == expected_h
                && shares.public_key.len() == expected_h
                && shares.relinearization_key.len() == expected_h,
            "l-BFV aggregation accepted set does not match H"
        );
        let mut requests = Vec::new();

        for row_index in 0..row_count as u32 {
            if state.public_key_aggregation_proofs[row_index as usize].is_none()
                && state.public_key_aggregation_correlations[row_index as usize].is_none()
            {
                let request = self.pk_aggregation_request(&state, &shares, row_index)?;
                let correlation = CorrelationId::new();
                state.set_public_key_correlation(row_index, correlation)?;
                requests.push((correlation, ZkRequest::LbfvPkAggregation(request)));
            }

            // Each row is proved once per RLK component; the two requests are independent, so
            // the compute pool runs them concurrently.
            for component in RlkAggregationComponent::ALL {
                let slot = component.index() as usize;
                if state.rlk_aggregation_proofs[row_index as usize][slot].is_some()
                    || state.rlk_aggregation_correlations[row_index as usize][slot].is_some()
                {
                    continue;
                }
                let request =
                    self.rlk_aggregation_request(&state, &shares, row_index, component)?;
                let correlation = CorrelationId::new();
                state.set_rlk_correlation(row_index, component, correlation)?;
                requests.push((correlation, ZkRequest::RlkAggregation(request)));
            }
        }

        if requests.is_empty() {
            return Ok(());
        }

        self.set_lbfv_aggregation(state, ec)?;
        info!(
            e3_id = %self.e3_id,
            request_count = requests.len(),
            "Dispatching l-BFV row aggregation requests"
        );
        for (correlation, request) in requests {
            self.bus.publish(
                ComputeRequest::zk(request, correlation, self.e3_id.clone()),
                ec.clone(),
            )?;
            self.note_lbfv_aggregation_dispatch(correlation, ec);
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
        let row_count = state.row_count()?;
        // A response whose correlation is no longer the current one answers a request that the
        // redrive re-published or a failover superseded. Its replacement produces the accepted
        // response, so the late one is expected: ignore it instead of raising an error.
        let late = |kind: &str| {
            info!(e3_id = %self.e3_id, kind, "Ignoring a late l-BFV aggregation response for a superseded request");
            Ok(())
        };
        match response {
            ZkResponse::LbfvPkAggregation(response) => {
                let row = response.row_index;
                let index = usize::try_from(row)?;
                anyhow::ensure!(
                    index < row_count,
                    "l-BFV PK aggregation row is out of range"
                );
                if state.public_key_aggregation_correlations[index] != Some(correlation) {
                    return late("PK aggregation");
                }
                anyhow::ensure!(
                    response.party_ids == state.accepted_party_ids,
                    "l-BFV PK aggregation party set changed"
                );
                let shares = self.accepted_lbfv_shares()?;
                let expected = self
                    .pk_aggregation_request(&state, &shares, row)?
                    .operation_id;
                anyhow::ensure!(
                    response.operation_id == expected,
                    "l-BFV PK aggregation operation ID changed"
                );
                state.record_public_key_proof(row, response.proof)?;
                state.clear_public_key_correlation(row, correlation)?;
            }
            ZkResponse::RlkAggregation(response) => {
                let row = response.row_index;
                let component = response.component;
                let index = usize::try_from(row)?;
                anyhow::ensure!(
                    index < row_count,
                    "l-BFV RLK aggregation row is out of range"
                );
                if state.rlk_correlation(row, component)? != Some(correlation) {
                    return late("RLK aggregation");
                }
                anyhow::ensure!(
                    response.party_ids == state.accepted_party_ids,
                    "l-BFV RLK aggregation party set changed"
                );
                let shares = self.accepted_lbfv_shares()?;
                let expected = self
                    .rlk_aggregation_request(&state, &shares, row, component)?
                    .operation_id;
                anyhow::ensure!(
                    response.operation_id == expected,
                    "l-BFV RLK aggregation operation ID changed"
                );
                state.record_rlk_proof(row, component, response.proof)?;
                state.clear_rlk_correlation(row, component, correlation)?;
            }
            ZkResponse::LbfvAggregationFold(response) => {
                if state.aggregation_fold_correlation != Some(correlation) {
                    return late("aggregation fold");
                }
                state.complete_fold(correlation, response.proof)?;
            }
            _ => return Ok(()),
        }
        let fold_complete = state.aggregation_fold_completed_rows == row_count as u32;
        self.set_lbfv_aggregation(state, ec)?;
        self.try_dispatch_lbfv_aggregation_fold(ec)?;
        if fold_complete {
            self.persist_operational_lbfv_rlk(ec)?;
            self.try_dispatch_dkg_aggregation(ec)?;
        }
        Ok(())
    }

    /// A worker error on an l-BFV aggregation request is a local failure, not evidence of peer
    /// misbehavior. The correlation and the persisted inputs stay in place: the redrive publishes
    /// the request again when the correlation times out, and a restart clears it and dispatches
    /// again. Returns whether the error answers an l-BFV aggregation request.
    pub(in crate::actors::publickey_aggregator) fn handle_lbfv_aggregation_error(
        &self,
        correlation: CorrelationId,
        error: &str,
    ) -> Result<bool> {
        let Some(state) = self.lbfv_aggregation_state()? else {
            return Ok(false);
        };
        let in_flight = state
            .public_key_aggregation_correlations
            .iter()
            .any(|candidate| *candidate == Some(correlation))
            || state
                .rlk_aggregation_correlations
                .iter()
                .flatten()
                .any(|candidate| *candidate == Some(correlation))
            || state.aggregation_fold_correlation == Some(correlation)
            || state.dkg_aggregation_correlation == Some(correlation);
        if in_flight {
            error!(
                e3_id = %self.e3_id,
                %correlation,
                "l-BFV aggregation request failed locally: {error}; pending work is preserved for the redrive and for restart"
            );
        }
        Ok(in_flight)
    }

    pub(in crate::actors::publickey_aggregator) fn try_dispatch_lbfv_aggregation_fold(
        &mut self,
        ec: &EventContext<Sequenced>,
    ) -> Result<()> {
        if !self.is_lbfv() || !self.can_continue_aggregation_effects() {
            return Ok(());
        }
        let Some(mut state) = self.lbfv_aggregation_state()? else {
            return Ok(());
        };
        state.validate_loaded()?;
        let row_count = state.row_count()?;
        if state.aggregation_fold_completed_rows == row_count as u32
            || state.aggregation_fold_correlation.is_some()
        {
            return Ok(());
        }
        let row = state.aggregation_fold_completed_rows as usize;
        let (Some(pk_proof), [Some(rlk_d0_proof), Some(rlk_d2_proof)]) = (
            state.public_key_aggregation_proofs[row].clone(),
            state.rlk_aggregation_proofs[row].clone(),
        ) else {
            return Ok(());
        };
        let request = LbfvAggregationFoldRequest {
            pk_proof,
            rlk_d0_proof,
            rlk_d2_proof,
            prior_accumulator: state.aggregation_fold_proof.clone(),
            row_index: row as u32,
            params_preset: self.params_profile.threshold_preset(),
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
        self.note_lbfv_aggregation_dispatch(correlation, ec);
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
        let row_count = state.row_count()?;
        if state.operational_public_key.is_some() && state.operational_rlk.is_some() {
            return Ok(());
        }
        anyhow::ensure!(
            state.aggregation_fold_completed_rows == row_count as u32
                && state.aggregation_fold_proof.is_some(),
            "operational l-BFV RLK requires a completed aggregation fold"
        );
        // The shares are read again after a restart, before the work that needs them resumes.
        let Some(shares) = self.lbfv_shares.clone() else {
            return Ok(());
        };
        let operational_keys = e3_trbfv::aggregate_lbfv::aggregate_lbfv_keys(
            self.params_profile.threshold_preset(),
            &shares.public_key,
            &shares.relinearization_key,
        )?;
        state.set_operational_keys(
            operational_keys.public_key,
            operational_keys.relinearization_key,
        )?;
        self.set_lbfv_aggregation(state, ec)
    }

    fn accepted_lbfv_shares(&self) -> Result<Arc<LbfvAcceptedShares>> {
        self.lbfv_shares
            .clone()
            .ok_or_else(|| anyhow::anyhow!("l-BFV accepted shares are not loaded"))
    }
}
