// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Durable remote l-BFV contribution collection and verification dispatch.

use super::super::*;
use crate::{
    LbfvContributionRepositoryFactory, LbfvContributionVerificationStateV1,
    LbfvPartyContributionStatusV1,
};
use e3_data::{AutoPersist, Repositories};
use e3_events::{
    LbfvKeyShareDocument, LbfvKeyShareDocumentFetchFailed, LbfvKeyShareDocumentReceived,
    LbfvKeyShareManifestPublished, LbfvVerificationContext, LbfvVerificationContextV2,
    PartyProofsToVerify,
};
use std::{collections::BTreeSet, time::Duration};

enum PreparedLbfvDispatch {
    Dispatch {
        state: Box<crate::LbfvContributionCollectionStateV1>,
        event: ShareVerificationDispatched,
    },
    Invalidated(crate::LbfvContributionCollectionStateV1),
}

impl PublicKeyAggregator {
    pub(in crate::actors::publickey_aggregator) fn is_lbfv(&self) -> bool {
        e3_fhe_params::supports_lbfv(self.params_preset)
            && (self.lbfv_collection.is_some()
                || self.lbfv_aggregation.is_some()
                || self.lbfv_publication.is_some())
    }

    pub(in crate::actors::publickey_aggregator) fn replace_lbfv_collection(
        &mut self,
        state: crate::LbfvContributionCollectionStateV1,
    ) {
        if let Some(collection) = &mut self.lbfv_collection {
            collection.set(state);
        }
    }

    pub(in crate::actors::publickey_aggregator) fn lbfv_collection_state(
        &self,
    ) -> Result<crate::LbfvContributionCollectionStateV1> {
        self.lbfv_collection
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("secure-16384 aggregator has no l-BFV collection"))?
            .try_get()
    }

    fn submitted_lbfv_parties(&self) -> Option<Vec<u32>> {
        let state = self.state.get()?;
        let submissions = match state {
            PublicKeyAggregatorState::Collecting {
                submission_order, ..
            }
            | PublicKeyAggregatorState::VerifyingC1 {
                submission_order, ..
            } => submission_order,
            _ => return None,
        };
        submissions
            .iter()
            .map(|(party_id, _, _)| u32::try_from(*party_id).ok())
            .collect()
    }

    fn keyshare_c1_for_party(&self, party_id: u32) -> Option<Option<SignedProofPayload>> {
        let state = self.state.get()?;
        let (submissions, proofs) = match state {
            PublicKeyAggregatorState::Collecting {
                submission_order,
                c1_proofs,
                ..
            }
            | PublicKeyAggregatorState::VerifyingC1 {
                submission_order,
                c1_proofs,
                ..
            } => (submission_order, c1_proofs),
            _ => return None,
        };
        submissions
            .iter()
            .position(|(id, _, _)| *id == u64::from(party_id))
            .and_then(|index| proofs.get(index).cloned())
    }

    pub(in crate::actors::publickey_aggregator) fn publish_due_lbfv_fetches(
        &self,
        ec: EventContext<Sequenced>,
    ) -> Result<()> {
        if !self.effects_enabled || !self.is_lbfv() {
            return Ok(());
        }
        self.publish_lbfv_fetches_due_at(self.lbfv_retry_clock.now_unix_secs(), ec)
    }

    fn publish_lbfv_fetches_due_at(
        &self,
        unix_time: u64,
        ec: EventContext<Sequenced>,
    ) -> Result<()> {
        for request in self
            .lbfv_collection_state()?
            .due_fetch_requests(unix_time)?
        {
            self.bus.publish(request, ec.clone())?;
        }
        Ok(())
    }

    fn arm_lbfv_retry_timer(&mut self, ec: EventContext<Sequenced>, ctx: &mut Context<Self>) {
        if let Some(handle) = self.lbfv_retry_timer.take() {
            ctx.cancel_future(handle);
        }
        if !self.effects_enabled || !self.is_lbfv() {
            return;
        }
        let retry_at = match self
            .lbfv_collection_state()
            .and_then(|state| state.next_retry_at())
        {
            Ok(Some(retry_at)) => retry_at,
            Ok(None) => return,
            Err(error) => {
                self.bus.err(EType::PublickeyAggregation, error);
                return;
            }
        };
        let now = self.lbfv_retry_clock.now_unix_secs();
        if retry_at <= now {
            return;
        }
        let handle = ctx.run_later(Duration::from_secs(retry_at - now), move |actor, ctx| {
            actor.lbfv_retry_timer = None;
            let now = actor.lbfv_retry_clock.now_unix_secs();
            if now < retry_at {
                actor.arm_lbfv_retry_timer(ec, ctx);
                return;
            }
            if let Err(error) = actor.publish_lbfv_fetches_due_at(now, ec) {
                actor.bus.err(EType::PublickeyAggregation, error);
            }
        });
        self.lbfv_retry_timer = Some(handle);
    }

    pub(in crate::actors::publickey_aggregator) fn persist_lbfv_manifest(
        &mut self,
        event: TypedEvent<LbfvKeyShareManifestPublished>,
        ctx: &mut Context<Self>,
    ) {
        if !self.is_lbfv() || event.e3_id() != &self.e3_id {
            return;
        }
        let (event, ec) = event.into_components();
        let Ok(state) = self.lbfv_collection_state() else {
            self.bus.err(
                EType::PublickeyAggregation,
                anyhow::anyhow!("secure-16384 aggregator has no l-BFV collection"),
            );
            return;
        };
        let repositories = self.repositories.clone();
        ctx.wait(
            async move {
                repositories
                    .persist_publickey_lbfv_manifest(&state, &event.manifest)
                    .await
            }
            .into_actor(self)
            .map(move |result, actor, ctx| match result {
                Ok((state, _)) => {
                    actor.replace_lbfv_collection(state);
                    actor.after_lbfv_collection_update(ec, ctx);
                }
                Err(error) => actor.bus.err(EType::PublickeyAggregation, error),
            }),
        );
    }

    pub(in crate::actors::publickey_aggregator) fn persist_lbfv_document(
        &mut self,
        event: TypedEvent<LbfvKeyShareDocumentReceived>,
        ctx: &mut Context<Self>,
    ) {
        if !self.is_lbfv() || event.e3_id() != &self.e3_id {
            return;
        }
        let (event, ec) = event.into_components();
        let party_id = event.document.context().party_id;
        let document = event.document.clone();
        let Ok(state) = self.lbfv_collection_state() else {
            return;
        };
        let expected_c1 = self.keyshare_c1_for_party(party_id);
        let repositories = self.repositories.clone();
        let preset = self.params_preset;
        ctx.wait(
            async move {
                let (mut state, _) = repositories
                    .persist_publickey_lbfv_document(&state, &event)
                    .await?;
                if state.parties.get(&party_id).is_some_and(|party| {
                    party.status == LbfvPartyContributionStatusV1::DocumentsDurable
                }) {
                    match expected_c1 {
                        Some(Some(c1)) => {
                            (state, _) = repositories
                                .validate_publickey_lbfv_party(&state, party_id, &c1, preset)
                                .await?;
                        }
                        Some(None) => {
                            let mut invalid = state.clone();
                            invalid.mark_party_invalid(party_id)?;
                            repositories
                                .persist_publickey_lbfv_transition(&state, &invalid)
                                .await?;
                            state = invalid;
                        }
                        None => {}
                    }
                }
                let aggregation_repository = repositories.publickey_lbfv_aggregation(&state.e3_id);
                let mut aggregation_sidecar = aggregation_repository.load().await?;
                let aggregation = match aggregation_sidecar.get() {
                    Some(aggregation)
                        if aggregation
                            .accepted_party_ids
                            .binary_search(&party_id)
                            .is_ok() =>
                    {
                        aggregation_sidecar.try_mutate_without_context(|mut aggregation| {
                            aggregation.record_document(document)?;
                            Ok(aggregation)
                        })?;
                        Some(aggregation_sidecar)
                    }
                    Some(_) => None,
                    None => None,
                };
                anyhow::Ok((state, aggregation))
            }
            .into_actor(self)
            .map(move |result, actor, ctx| match result {
                Ok((state, aggregation)) => {
                    actor.replace_lbfv_collection(state);
                    if let Some(aggregation) = aggregation {
                        actor.replace_lbfv_aggregation(aggregation);
                    }
                    actor.after_lbfv_collection_update(ec, ctx);
                }
                Err(error) => actor.bus.err(EType::PublickeyAggregation, error),
            }),
        );
    }

    pub(in crate::actors::publickey_aggregator) fn persist_lbfv_fetch_failure(
        &mut self,
        event: TypedEvent<LbfvKeyShareDocumentFetchFailed>,
        ctx: &mut Context<Self>,
    ) {
        if !self.is_lbfv() || event.e3_id() != &self.e3_id {
            return;
        }
        let (event, ec) = event.into_components();
        let Ok(state) = self.lbfv_collection_state() else {
            return;
        };
        let repositories = self.repositories.clone();
        ctx.wait(
            async move {
                repositories
                    .persist_publickey_lbfv_fetch_failure(&state, &event)
                    .await
            }
            .into_actor(self)
            .map(move |result, actor, ctx| match result {
                Ok((state, _)) => {
                    actor.replace_lbfv_collection(state);
                    actor.after_lbfv_collection_update(ec, ctx);
                }
                Err(error) => actor.bus.err(EType::PublickeyAggregation, error),
            }),
        );
    }

    pub(in crate::actors::publickey_aggregator) fn persist_lbfv_exclusion(
        &mut self,
        node: alloy::primitives::Address,
        ec: EventContext<Sequenced>,
        ctx: &mut Context<Self>,
    ) {
        if !self.is_lbfv() {
            return;
        }
        let Ok(state) = self.lbfv_collection_state() else {
            return;
        };
        let Some(party_id) = state
            .committee
            .iter()
            .position(|candidate| *candidate == node)
            .and_then(|party_id| u32::try_from(party_id).ok())
        else {
            self.bus.err(
                EType::PublickeyAggregation,
                anyhow::anyhow!("excluded l-BFV node is not in the finalized committee"),
            );
            return;
        };
        let mut excluded = state.clone();
        let changed = match excluded.mark_party_excluded(party_id) {
            Ok(changed) => changed,
            Err(error) => {
                self.bus.err(EType::PublickeyAggregation, error);
                return;
            }
        };
        if !changed {
            self.after_lbfv_collection_update(ec, ctx);
            return;
        }
        let repositories = self.repositories.clone();
        ctx.wait(
            async move {
                repositories
                    .persist_publickey_lbfv_transition(&state, &excluded)
                    .await?;
                anyhow::Ok(excluded)
            }
            .into_actor(self)
            .map(move |result, actor, ctx| match result {
                Ok(state) => {
                    actor.replace_lbfv_collection(state);
                    actor.after_lbfv_collection_update(ec, ctx);
                }
                Err(error) => actor.bus.err(EType::PublickeyAggregation, error),
            }),
        );
    }

    pub(in crate::actors::publickey_aggregator) fn validate_stored_lbfv_bundle(
        &mut self,
        party_id: u32,
        ec: EventContext<Sequenced>,
        ctx: &mut Context<Self>,
    ) {
        if !self.is_lbfv() {
            return;
        }
        let Ok(state) = self.lbfv_collection_state() else {
            return;
        };
        if !state
            .parties
            .get(&party_id)
            .is_some_and(|party| party.status == LbfvPartyContributionStatusV1::DocumentsDurable)
        {
            self.after_lbfv_collection_update(ec, ctx);
            return;
        }
        let Some(expected_c1) = self.keyshare_c1_for_party(party_id) else {
            return;
        };
        let repositories = self.repositories.clone();
        let preset = self.params_preset;
        ctx.wait(
            async move {
                if let Some(c1) = expected_c1 {
                    let (state, _) = repositories
                        .validate_publickey_lbfv_party(&state, party_id, &c1, preset)
                        .await?;
                    anyhow::Ok(state)
                } else {
                    let mut invalid = state.clone();
                    invalid.mark_party_invalid(party_id)?;
                    repositories
                        .persist_publickey_lbfv_transition(&state, &invalid)
                        .await?;
                    anyhow::Ok(invalid)
                }
            }
            .into_actor(self)
            .map(move |result, actor, ctx| match result {
                Ok(state) => {
                    actor.replace_lbfv_collection(state);
                    actor.after_lbfv_collection_update(ec, ctx);
                }
                Err(error) => actor.bus.err(EType::PublickeyAggregation, error),
            }),
        );
    }

    fn reconcile_durable_lbfv_bundles(
        &mut self,
        state: crate::LbfvContributionCollectionStateV1,
        ec: EventContext<Sequenced>,
        ctx: &mut Context<Self>,
    ) -> bool {
        let Some(submitted_party_ids) = self.submitted_lbfv_parties() else {
            return false;
        };
        let pending = submitted_party_ids
            .into_iter()
            .filter(|party_id| {
                state.parties.get(party_id).is_some_and(|party| {
                    party.status == LbfvPartyContributionStatusV1::DocumentsDurable
                })
            })
            .filter_map(|party_id| {
                self.keyshare_c1_for_party(party_id)
                    .map(|c1| (party_id, c1))
            })
            .collect::<Vec<_>>();
        if pending.is_empty() {
            return false;
        }

        let repositories = self.repositories.clone();
        let preset = self.params_preset;
        ctx.wait(
            async move {
                let mut current = state;
                for (party_id, expected_c1) in pending {
                    if !current.parties.get(&party_id).is_some_and(|party| {
                        party.status == LbfvPartyContributionStatusV1::DocumentsDurable
                    }) {
                        continue;
                    }
                    current = if let Some(c1) = expected_c1 {
                        repositories
                            .validate_publickey_lbfv_party(&current, party_id, &c1, preset)
                            .await?
                            .0
                    } else {
                        let mut invalid = current.clone();
                        invalid.mark_party_invalid(party_id)?;
                        repositories
                            .persist_publickey_lbfv_transition(&current, &invalid)
                            .await?;
                        invalid
                    };
                }
                anyhow::Ok(current)
            }
            .into_actor(self)
            .map(move |result, actor, ctx| match result {
                Ok(state) => {
                    actor.replace_lbfv_collection(state);
                    actor.after_lbfv_collection_update(ec, ctx);
                }
                Err(error) => actor.bus.err(EType::PublickeyAggregation, error),
            }),
        );
        true
    }

    fn after_lbfv_collection_update(
        &mut self,
        ec: EventContext<Sequenced>,
        ctx: &mut Context<Self>,
    ) {
        if let Err(error) = self.publish_due_lbfv_fetches(ec.clone()) {
            self.bus.err(EType::PublickeyAggregation, error);
        }
        self.arm_lbfv_retry_timer(ec.clone(), ctx);
        if let Err(error) = self.publish_inputs_ready(ec.clone()) {
            self.bus.err(EType::PublickeyAggregation, error);
        }
        if matches!(
            self.state.get(),
            Some(PublicKeyAggregatorState::GeneratingC5Proof { .. })
        ) {
            if let Err(error) = self.try_dispatch_lbfv_aggregation_rows(&ec) {
                self.bus.err(EType::PublickeyAggregation, error);
            }
        }
        self.try_progress_lbfv_verification(ec, ctx);
    }

    pub(in crate::actors::publickey_aggregator) fn try_progress_lbfv_verification(
        &mut self,
        ec: EventContext<Sequenced>,
        ctx: &mut Context<Self>,
    ) {
        if !self.is_lbfv() {
            return;
        }
        if self.persist_lbfv_ready_quorum(ec.clone(), ctx) {
            return;
        }
        if !self.can_run_aggregation_effects() {
            return;
        }
        let Some(submitted_party_ids) = self.submitted_lbfv_parties() else {
            return;
        };
        if !matches!(
            self.state.get(),
            Some(PublicKeyAggregatorState::VerifyingC1 { .. })
        ) {
            return;
        }
        let Ok(state) = self.lbfv_collection_state() else {
            return;
        };
        match &state.verification {
            LbfvContributionVerificationStateV1::Failed { .. } => {
                if let Err(error) = self.publish_lbfv_failure(ec) {
                    self.bus.err(EType::PublickeyAggregation, error);
                }
                return;
            }
            LbfvContributionVerificationStateV1::Dispatched { .. } => return,
            LbfvContributionVerificationStateV1::Sealed { .. } => {
                self.apply_sealed_lbfv_collection(ec, ctx);
                return;
            }
            LbfvContributionVerificationStateV1::Collecting
            | LbfvContributionVerificationStateV1::Ready { .. } => {}
        }
        let ready_party_ids = match &state.verification {
            LbfvContributionVerificationStateV1::Ready { party_ids } => party_ids.clone(),
            LbfvContributionVerificationStateV1::Collecting => {
                let Ok(ready_party_ids) = state.ready_party_ids(&submitted_party_ids) else {
                    return;
                };
                ready_party_ids
            }
            _ => return,
        };
        if ready_party_ids.len() < state.committee_h as usize {
            if state
                .all_submitted_parties_settled(&submitted_party_ids)
                .unwrap_or(false)
            {
                self.persist_lbfv_failure(state, ec, ctx);
            }
            return;
        }

        let c1_by_party = ready_party_ids
            .iter()
            .filter_map(|party_id| {
                self.keyshare_c1_for_party(*party_id)
                    .flatten()
                    .map(|c1| (*party_id, c1))
            })
            .collect::<Vec<_>>();
        if c1_by_party.len() != ready_party_ids.len() {
            self.persist_lbfv_failure(state, ec, ctx);
            return;
        }
        let pre_dishonest = state
            .ineligible_party_ids(&ready_party_ids)
            .unwrap_or_default()
            .into_iter()
            .map(u64::from)
            .collect::<BTreeSet<_>>();
        let repositories = self.repositories.clone();
        let preset = self.params_preset;
        let committee_size = self.committee_size;
        ctx.wait(
            async move {
                prepare_lbfv_dispatch(
                    repositories,
                    state,
                    ready_party_ids,
                    c1_by_party,
                    pre_dishonest,
                    preset,
                    committee_size,
                )
                .await
            }
            .into_actor(self)
            .map(move |result, actor, ctx| match result {
                Ok(PreparedLbfvDispatch::Dispatch { state, event }) => {
                    actor.replace_lbfv_collection(*state);
                    if let Err(error) = actor.bus.publish(event, ec.clone()) {
                        actor.bus.err(EType::PublickeyAggregation, error);
                    }
                }
                Ok(PreparedLbfvDispatch::Invalidated(state)) => {
                    actor.replace_lbfv_collection(state);
                    actor.try_progress_lbfv_verification(ec, ctx);
                }
                Err(error) => actor.bus.err(EType::PublickeyAggregation, error),
            }),
        );
    }

    fn persist_lbfv_ready_quorum(
        &mut self,
        ec: EventContext<Sequenced>,
        ctx: &mut Context<Self>,
    ) -> bool {
        if !matches!(
            self.state.get(),
            Some(PublicKeyAggregatorState::VerifyingC1 { .. })
        ) {
            return false;
        }
        let Some(submitted_party_ids) = self.submitted_lbfv_parties() else {
            return false;
        };
        let Ok(state) = self.lbfv_collection_state() else {
            return false;
        };
        if !matches!(
            state.verification,
            LbfvContributionVerificationStateV1::Collecting
        ) {
            return false;
        }
        let Ok(Some(party_ids)) = state.ready_quorum_party_ids(&submitted_party_ids) else {
            return false;
        };
        let mut ready = state.clone();
        if let Err(error) = ready.mark_ready(party_ids) {
            self.bus.err(EType::PublickeyAggregation, error);
            return false;
        }
        let repositories = self.repositories.clone();
        ctx.wait(
            async move {
                repositories
                    .persist_publickey_lbfv_transition(&state, &ready)
                    .await?;
                Ok::<_, anyhow::Error>(ready)
            }
            .into_actor(self)
            .map(move |result, actor, ctx| match result {
                Ok(ready) => {
                    actor.replace_lbfv_collection(ready);
                    if let Err(error) = actor.publish_inputs_ready(ec.clone()) {
                        actor.bus.err(EType::PublickeyAggregation, error);
                    }
                    actor.try_progress_lbfv_verification(ec, ctx);
                }
                Err(error) => actor.bus.err(EType::PublickeyAggregation, error),
            }),
        );
        true
    }

    pub(in crate::actors::publickey_aggregator) fn resume_lbfv_work(
        &mut self,
        ec: EventContext<Sequenced>,
        ctx: &mut Context<Self>,
    ) {
        if let Err(error) = self.publish_due_lbfv_fetches(ec.clone()) {
            self.bus.err(EType::PublickeyAggregation, error);
        }
        self.arm_lbfv_retry_timer(ec.clone(), ctx);
        let Ok(state) = self.lbfv_collection_state() else {
            return;
        };
        if self.reconcile_durable_lbfv_bundles(state.clone(), ec.clone(), ctx) {
            return;
        }
        if matches!(
            state.verification,
            LbfvContributionVerificationStateV1::Sealed { .. }
        ) {
            self.try_progress_lbfv_verification(ec, ctx);
            return;
        }
        let LbfvContributionVerificationStateV1::Dispatched { party_ids } = &state.verification
        else {
            self.try_progress_lbfv_verification(ec, ctx);
            return;
        };
        if !self.can_run_aggregation_effects() {
            return;
        }
        let c1_by_party = party_ids
            .iter()
            .filter_map(|party_id| {
                self.keyshare_c1_for_party(*party_id)
                    .flatten()
                    .map(|c1| (*party_id, c1))
            })
            .collect::<Vec<_>>();
        if c1_by_party.len() != party_ids.len() {
            self.bus.err(
                EType::PublickeyAggregation,
                anyhow::anyhow!("persisted l-BFV dispatch has no matching C1 payload"),
            );
            return;
        }
        let pre_dishonest = state
            .ineligible_party_ids(party_ids)
            .unwrap_or_default()
            .into_iter()
            .map(u64::from)
            .collect();
        let repositories = self.repositories.clone();
        let party_ids = party_ids.clone();
        let preset = self.params_preset;
        let committee_size = self.committee_size;
        ctx.wait(
            async move {
                prepare_lbfv_dispatch(
                    repositories,
                    state,
                    party_ids,
                    c1_by_party,
                    pre_dishonest,
                    preset,
                    committee_size,
                )
                .await
            }
            .into_actor(self)
            .map(move |result, actor, _| match result {
                Ok(PreparedLbfvDispatch::Dispatch { state, event }) => {
                    actor.replace_lbfv_collection(*state);
                    if let Err(error) = actor.bus.publish(event, ec) {
                        actor.bus.err(EType::PublickeyAggregation, error);
                    }
                }
                Ok(PreparedLbfvDispatch::Invalidated(state)) => {
                    actor.replace_lbfv_collection(state);
                    actor.bus.err(
                        EType::PublickeyAggregation,
                        anyhow::anyhow!("persisted l-BFV dispatch became invalid during recovery"),
                    );
                }
                Err(error) => actor.bus.err(EType::PublickeyAggregation, error),
            }),
        );
    }

    fn persist_lbfv_failure(
        &mut self,
        state: crate::LbfvContributionCollectionStateV1,
        ec: EventContext<Sequenced>,
        ctx: &mut Context<Self>,
    ) {
        let mut failed = state.clone();
        if let Err(error) = failed.fail("fewer than H valid l-BFV contributions") {
            self.bus.err(EType::PublickeyAggregation, error);
            return;
        }
        let repositories = self.repositories.clone();
        ctx.wait(
            async move {
                repositories
                    .persist_publickey_lbfv_transition(&state, &failed)
                    .await?;
                anyhow::Ok(failed)
            }
            .into_actor(self)
            .map(move |result, actor, _| match result {
                Ok(state) => {
                    actor.replace_lbfv_collection(state);
                    if let Err(error) = actor.publish_lbfv_failure(ec) {
                        actor.bus.err(EType::PublickeyAggregation, error);
                    }
                }
                Err(error) => actor.bus.err(EType::PublickeyAggregation, error),
            }),
        );
    }

    fn publish_lbfv_failure(&self, ec: EventContext<Sequenced>) -> Result<()> {
        self.bus.publish(
            E3Failed {
                e3_id: self.e3_id.clone(),
                failed_at_stage: E3Stage::CommitteeFinalized,
                reason: FailureReason::DKGInvalidShares,
            },
            ec,
        )
    }
}

async fn prepare_lbfv_dispatch(
    repositories: Repositories,
    state: crate::LbfvContributionCollectionStateV1,
    candidate_party_ids: Vec<u32>,
    c1_by_party: Vec<(u32, SignedProofPayload)>,
    pre_dishonest: BTreeSet<u64>,
    preset: BfvPreset,
    committee_size: CiphernodesCommitteeSize,
) -> Result<PreparedLbfvDispatch> {
    let mut party_proofs = Vec::with_capacity(candidate_party_ids.len());
    for party_id in &candidate_party_ids {
        let party = &state.parties[party_id];
        let manifest = party.manifest.as_ref().expect("ready party has a manifest");
        let (public_key_hash, rlk_hash) =
            crate::domain::lbfv_contribution_collection::manifest_hashes(&manifest.payload);
        let public_key = repositories
            .publickey_lbfv_document(&state.e3_id, &public_key_hash)
            .read()
            .await?
            .ok_or_else(|| anyhow::anyhow!("ready l-BFV public-key artifact is missing"))?;
        let rlk = repositories
            .publickey_lbfv_document(&state.e3_id, &rlk_hash)
            .read()
            .await?
            .ok_or_else(|| {
                anyhow::anyhow!("ready l-BFV relinearization-key artifact is missing")
            })?;
        let expected_c1 = c1_by_party
            .iter()
            .find(|(candidate, _)| candidate == party_id)
            .map(|(_, c1)| c1)
            .expect("ready party has a KeyshareCreated C1 proof");
        let validation = (|| {
            manifest.validate_documents(&public_key, &rlk)?;
            anyhow::ensure!(
                public_key.role() == e3_events::LbfvKeyShareDocumentRole::PublicKey,
                "l-BFV public-key artifact has the wrong role"
            );
            anyhow::ensure!(
                rlk.role() == e3_events::LbfvKeyShareDocumentRole::RelinearizationKey,
                "l-BFV relinearization-key artifact has the wrong role"
            );
            let document_c1 = match &public_key {
                LbfvKeyShareDocument::PublicKeyV1(document) => &document.signed_c1_proof,
                LbfvKeyShareDocument::PublicKeyV2(document) => &document.signed_c1_proof,
                _ => unreachable!("the public-key role was checked above"),
            };
            anyhow::ensure!(
                document_c1.payload == expected_c1.payload,
                "l-BFV document C1 payload does not match KeyshareCreated"
            );
            let commitments = e3_zk_prover::validate_lbfv_key_share_document_commitments_dynamic(
                preset,
                &public_key,
                &rlk,
            )?;
            anyhow::ensure!(
                state.validated_commitments(*party_id)? == &commitments,
                "l-BFV bundle commitments changed after validation"
            );
            lbfv_proofs_for_dispatch(&public_key, &rlk, expected_c1)
        })();
        match validation {
            Ok(signed_proofs) => party_proofs.push(PartyProofsToVerify {
                sender_party_id: u64::from(*party_id),
                signed_proofs,
            }),
            Err(error) => {
                tracing::warn!(party_id, %error, "Invalid l-BFV bundle found before dispatch");
                let mut invalid = state.clone();
                invalid.mark_party_invalid(*party_id)?;
                repositories
                    .persist_publickey_lbfv_transition(&state, &invalid)
                    .await?;
                return Ok(PreparedLbfvDispatch::Invalidated(invalid));
            }
        }
    }

    let mut ready = state.clone();
    if matches!(
        ready.verification,
        LbfvContributionVerificationStateV1::Collecting
    ) {
        ready.mark_ready(candidate_party_ids)?;
        repositories
            .persist_publickey_lbfv_transition(&state, &ready)
            .await?;
    }
    let mut dispatched = ready.clone();
    if matches!(
        ready.verification,
        LbfvContributionVerificationStateV1::Ready { .. }
    ) {
        dispatched.mark_verification_dispatched()?;
        repositories
            .persist_publickey_lbfv_transition(&ready, &dispatched)
            .await?;
    }
    let LbfvContributionVerificationStateV1::Dispatched { party_ids } = &dispatched.verification
    else {
        anyhow::bail!("l-BFV dispatch did not persist its candidate set");
    };
    anyhow::ensure!(
        party_proofs
            .iter()
            .map(|proofs| proofs.sender_party_id)
            .eq(party_ids.iter().copied().map(u64::from)),
        "l-BFV dispatch proofs do not match the persisted candidate set"
    );
    let event = lbfv_dispatch_event(
        &dispatched,
        party_proofs,
        pre_dishonest,
        preset,
        committee_size,
    )?;
    Ok(PreparedLbfvDispatch::Dispatch {
        state: Box::new(dispatched),
        event,
    })
}

fn lbfv_proofs_for_dispatch(
    public_key: &LbfvKeyShareDocument,
    rlk: &LbfvKeyShareDocument,
    expected_c1: &SignedProofPayload,
) -> Result<Vec<SignedProofPayload>> {
    let (signed_c1_proof, pk_rows) = match public_key {
        LbfvKeyShareDocument::PublicKeyV1(document) => (
            &document.signed_c1_proof,
            document.signed_row_proofs.as_slice(),
        ),
        LbfvKeyShareDocument::PublicKeyV2(document) => (
            &document.signed_c1_proof,
            document.signed_row_proofs.as_slice(),
        ),
        _ => anyhow::bail!("l-BFV public-key artifact has the wrong role"),
    };
    let rlk_rows = match rlk {
        LbfvKeyShareDocument::RelinearizationKeyV1(document) => {
            document.signed_row_proofs.as_slice()
        }
        LbfvKeyShareDocument::RelinearizationKeyV2(document) => {
            document.signed_row_proofs.as_slice()
        }
        _ => anyhow::bail!("l-BFV relinearization-key artifact has the wrong role"),
    };
    anyhow::ensure!(
        signed_c1_proof.payload == expected_c1.payload,
        "l-BFV document C1 payload does not match KeyshareCreated"
    );
    let mut proofs = Vec::with_capacity(1 + pk_rows.len() + rlk_rows.len());
    proofs.push(signed_c1_proof.clone());
    proofs.extend(pk_rows.iter().cloned());
    proofs.extend(rlk_rows.iter().cloned());
    Ok(proofs)
}

fn lbfv_dispatch_event(
    state: &crate::LbfvContributionCollectionStateV1,
    party_proofs: Vec<PartyProofsToVerify>,
    pre_dishonest: BTreeSet<u64>,
    preset: BfvPreset,
    committee_size: CiphernodesCommitteeSize,
) -> Result<ShareVerificationDispatched> {
    Ok(ShareVerificationDispatched {
        e3_id: state.e3_id.clone(),
        kind: VerificationKind::LbfvGenerationProofs,
        share_proofs: party_proofs,
        decryption_proofs: Vec::new(),
        pre_dishonest,
        params_preset: preset,
        committee_size,
        lbfv_context: Some(LbfvVerificationContext::V2(LbfvVerificationContextV2 {
            proof_domain: state.proof_domain,
            aggregation: None,
        })),
        verification_id: Some(state.dispatched_verification_id()?),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::lbfv_contribution_collection::tests::{bundle, fixture};

    #[test]
    fn generation_dispatch_has_exact_proof_order_and_context() -> Result<()> {
        let fixture = fixture();
        let mut collection = fixture.state.clone();
        for party_id in 0..2 {
            crate::domain::lbfv_contribution_collection::tests::complete_party(
                &mut collection,
                &fixture,
                party_id,
            );
        }
        collection.mark_ready(vec![0, 1])?;
        collection.mark_verification_dispatched()?;
        let (public_key, rlk, _) = bundle(&fixture, 0);
        let expected_c1 = match &public_key.document {
            LbfvKeyShareDocument::PublicKeyV1(document) => &document.signed_c1_proof,
            LbfvKeyShareDocument::PublicKeyV2(document) => &document.signed_c1_proof,
            _ => unreachable!(),
        };
        let proofs = lbfv_proofs_for_dispatch(&public_key.document, &rlk.document, expected_c1)
            .expect("canonical proof bundle");
        assert_eq!(proofs.len(), 11);
        assert_eq!(proofs[0].payload.proof_type, ProofType::C1PkGeneration);
        for (row, proof) in proofs[1..6].iter().enumerate() {
            assert_eq!(proof.payload.proof_type, ProofType::LbfvPkGeneration);
            assert_eq!(
                proof
                    .payload
                    .proof_type
                    .identity(&proof.payload.proof)?
                    .instance,
                row as u32
            );
        }
        for (row, proof) in proofs[6..].iter().enumerate() {
            assert_eq!(proof.payload.proof_type, ProofType::RlkGeneration);
            assert_eq!(
                proof
                    .payload
                    .proof_type
                    .identity(&proof.payload.proof)?
                    .instance,
                row as u32
            );
        }

        let event = lbfv_dispatch_event(
            &collection,
            vec![PartyProofsToVerify {
                sender_party_id: 0,
                signed_proofs: proofs,
            }],
            BTreeSet::from([2]),
            BfvPreset::SecureThreshold16384,
            CiphernodesCommitteeSize::Minimum,
        )?;
        assert_eq!(event.kind, VerificationKind::LbfvGenerationProofs);
        assert_eq!(event.pre_dishonest, BTreeSet::from([2]));
        assert_eq!(
            event.verification_id,
            Some(collection.dispatched_verification_id()?)
        );
        assert!(matches!(
            event.lbfv_context,
            Some(LbfvVerificationContext::V2(LbfvVerificationContextV2 {
                proof_domain,
                aggregation: None,
            })) if proof_domain == fixture.state.proof_domain
        ));
        anyhow::Ok(())
    }
}
