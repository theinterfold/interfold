// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Durable remote l-BFV contribution collection and verification dispatch.

use super::super::*;
use super::aggregate_lbfv::load_lbfv_accepted_shares;
use crate::{
    LbfvContributionRepositoryFactory, LbfvContributionVerificationStateV1,
    LbfvPartyContributionStatusV1,
};
use e3_data::Repositories;
use e3_events::{
    LbfvKeyShareDocument, LbfvKeyShareDocumentFetchFailed, LbfvKeyShareDocumentReceived,
    LbfvKeyShareManifestPublished, LbfvShareVerificationDispatched, LbfvVerificationContext,
    LbfvVerificationContextV2, PartyProofsToVerify,
};
use std::{collections::BTreeSet, time::Duration};

enum PreparedLbfvDispatch {
    Dispatch {
        state: Box<crate::LbfvContributionCollectionStateV1>,
        event: LbfvShareVerificationDispatched,
    },
    Invalidated(crate::LbfvContributionCollectionStateV1),
}

impl PublicKeyAggregator {
    pub(in crate::actors::publickey_aggregator) fn is_lbfv(&self) -> bool {
        e3_fhe_params::supports_lbfv(self.params_profile.threshold_preset())
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
            .ok_or_else(|| anyhow::anyhow!("l-BFV aggregator has no l-BFV collection"))?
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

    /// Whether `party_id` submitted its `KeyshareCreated`. The l-BFV path validates a party's
    /// bundle only after that submission; the bundle carries no C1 to match against it.
    fn keyshare_submitted(&self, party_id: u32) -> bool {
        self.submitted_lbfv_parties()
            .is_some_and(|submitted| submitted.contains(&party_id))
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
                anyhow::anyhow!("l-BFV aggregator has no l-BFV collection"),
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
                Ok(state) => {
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
        let Ok(state) = self.lbfv_collection_state() else {
            return;
        };
        let submitted = self.keyshare_submitted(party_id);
        let repositories = self.repositories.clone();
        ctx.wait(
            async move {
                let mut state = repositories
                    .persist_publickey_lbfv_document(&state, &event)
                    .await?;
                if submitted
                    && state.parties.get(&party_id).is_some_and(|party| {
                        party.status == LbfvPartyContributionStatusV1::DocumentsDurable
                    })
                {
                    state = repositories
                        .validate_publickey_lbfv_party(&state, party_id)
                        .await?;
                }
                anyhow::Ok(state)
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
        // A canonical key on chain ends DKG expulsion handling: an expulsion during the
        // decryption phase must not fail the E3 through the collection.
        if !self.is_lbfv() || self.key_published {
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
        if !self.keyshare_submitted(party_id) {
            return;
        }
        let repositories = self.repositories.clone();
        ctx.wait(
            async move {
                repositories
                    .validate_publickey_lbfv_party(&state, party_id)
                    .await
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
            .collect::<Vec<_>>();
        if pending.is_empty() {
            return false;
        }

        let repositories = self.repositories.clone();
        ctx.wait(
            async move {
                let mut current = state;
                for party_id in pending {
                    if !current.parties.get(&party_id).is_some_and(|party| {
                        party.status == LbfvPartyContributionStatusV1::DocumentsDurable
                    }) {
                        continue;
                    }
                    current = repositories
                        .validate_publickey_lbfv_party(&current, party_id)
                        .await?;
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

    pub(in crate::actors::publickey_aggregator) fn after_lbfv_collection_update(
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
        // A canonical key on chain ends the DKG. Nothing here may start, fail, or finish the E3.
        if !self.is_lbfv() || self.key_published {
            return;
        }
        if self.persist_lbfv_ready_quorum(ec.clone(), ctx) {
            return;
        }
        if !self.can_continue_aggregation_effects() {
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
                if self.can_run_aggregation_effects() {
                    if let Err(error) = self.publish_lbfv_failure(ec) {
                        self.bus.err(EType::PublickeyAggregation, error);
                    }
                }
                return;
            }
            LbfvContributionVerificationStateV1::Dispatched { .. } => {
                self.apply_held_lbfv_verification(ec, ctx);
                return;
            }
            LbfvContributionVerificationStateV1::Sealed { .. } => {
                self.apply_sealed_lbfv_collection(ec, ctx);
                return;
            }
            LbfvContributionVerificationStateV1::Collecting
            | LbfvContributionVerificationStateV1::Ready { .. } => {}
        }
        if !self.can_run_aggregation_effects() {
            return;
        }
        if matches!(
            state.verification,
            LbfvContributionVerificationStateV1::Collecting
        ) {
            // `persist_lbfv_ready_quorum` moves a complete quorum to `Ready`. What remains here
            // cannot reach H, so the collection fails once every submitted party settled.
            let Ok(ready_party_ids) = state.ready_party_ids(&submitted_party_ids) else {
                return;
            };
            if ready_party_ids.len() < state.committee_h as usize
                && state
                    .all_submitted_parties_settled(&submitted_party_ids)
                    .unwrap_or(false)
            {
                self.persist_lbfv_failure(state, ec, ctx);
            }
            return;
        }
        let LbfvContributionVerificationStateV1::Ready { party_ids } = &state.verification else {
            return;
        };
        let ready_party_ids = party_ids.clone();

        let repositories = self.repositories.clone();
        let params_profile = self.params_profile;
        let committee_size = self.committee_size;
        ctx.wait(
            async move {
                prepare_lbfv_dispatch(
                    repositories,
                    state,
                    ready_party_ids,
                    params_profile,
                    committee_size,
                )
                .await
            }
            .into_actor(self)
            .map(move |result, actor, ctx| match result {
                Ok(PreparedLbfvDispatch::Dispatch { state, event }) => {
                    actor.commit_lbfv_dispatch(*state, event, ec);
                }
                Ok(PreparedLbfvDispatch::Invalidated(state)) => {
                    actor.replace_lbfv_collection(state);
                    actor.try_progress_lbfv_verification(ec, ctx);
                }
                Err(error) => actor.bus.err(EType::PublickeyAggregation, error),
            }),
        );
    }

    /// Record the dispatched candidate set and publish its verification request. The dispatch
    /// makes this node the owner of the verification: a failover that demotes it does not discard
    /// the work, and the ownership is persisted so that a restart resumes it.
    fn commit_lbfv_dispatch(
        &mut self,
        state: crate::LbfvContributionCollectionStateV1,
        event: LbfvShareVerificationDispatched,
        ec: EventContext<Sequenced>,
    ) {
        self.replace_lbfv_collection(state);
        if let Err(error) = self.mark_started_as_aggregator(&ec) {
            self.bus.err(EType::PublickeyAggregation, error);
            return;
        }
        if let Err(error) = self.bus.publish(event.into_event_data(), ec) {
            self.bus.err(EType::PublickeyAggregation, error);
        }
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

    /// Resume the l-BFV work of a restarted or promoted node: fetches, the verification of the
    /// collected bundles, and the aggregation that a sealed set leaves behind.
    pub(in crate::actors::publickey_aggregator) fn resume_lbfv_aggregation(
        &mut self,
        ec: EventContext<Sequenced>,
        ctx: &mut Context<Self>,
    ) {
        self.resume_lbfv_work(ec.clone(), ctx);
        if !matches!(
            self.state.get(),
            Some(
                PublicKeyAggregatorState::GeneratingC5Proof { .. }
                    | PublicKeyAggregatorState::Complete { .. }
            )
        ) {
            return;
        }
        // The row aggregation needs the accepted shares. They are not persisted in the sidecar, so
        // a restarted node reads them again before the in-flight work resumes.
        if self.lbfv_shares.is_none()
            && self.lbfv_collection.is_some()
            && matches!(
                self.state.get(),
                Some(PublicKeyAggregatorState::GeneratingC5Proof { .. })
            )
        {
            let Ok(collection) = self.lbfv_collection_state() else {
                return;
            };
            let repositories = self.repositories.clone();
            ctx.wait(
                async move { load_lbfv_accepted_shares(&repositories, &collection).await }
                    .into_actor(self)
                    .map(move |result, actor, _| match result {
                        Ok(shares) => {
                            actor.lbfv_shares = Some(Arc::new(shares));
                            trap(EType::PublickeyAggregation, &actor.bus.with_ec(&ec), || {
                                actor.resume_in_flight_work(ec.clone())
                            });
                        }
                        Err(error) => actor.bus.err(EType::PublickeyAggregation, error),
                    }),
            );
            return;
        }
        trap(EType::PublickeyAggregation, &self.bus.with_ec(&ec), || {
            self.resume_in_flight_work(ec.clone())
        });
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
        let LbfvContributionVerificationStateV1::Dispatched { party_ids } = &state.verification
        else {
            self.try_progress_lbfv_verification(ec, ctx);
            return;
        };
        if self.key_published {
            return;
        }
        // A verdict that outlived the restart answers this dispatch. Apply it instead of
        // dispatching again: the bus drops a repeated request, so a second dispatch could not
        // produce the verdict a second time.
        if self.apply_held_lbfv_verification(ec.clone(), ctx) {
            return;
        }
        if !self.can_run_aggregation_effects() {
            return;
        }
        if !party_ids
            .iter()
            .all(|party_id| self.keyshare_submitted(*party_id))
        {
            self.bus.err(
                EType::PublickeyAggregation,
                anyhow::anyhow!("persisted l-BFV dispatch has no matching KeyshareCreated"),
            );
            return;
        }
        let repositories = self.repositories.clone();
        let party_ids = party_ids.clone();
        let params_profile = self.params_profile;
        let committee_size = self.committee_size;
        ctx.wait(
            async move {
                prepare_lbfv_dispatch(
                    repositories,
                    state,
                    party_ids,
                    params_profile,
                    committee_size,
                )
                .await
            }
            .into_actor(self)
            .map(move |result, actor, _| match result {
                Ok(PreparedLbfvDispatch::Dispatch { state, event }) => {
                    actor.commit_lbfv_dispatch(*state, event, ec);
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
        // A key on chain ends the DKG: a late failure must not fail the E3.
        if self.key_published {
            return Ok(());
        }
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
    params_profile: BfvProfile,
    committee_size: CiphernodesCommitteeSize,
) -> Result<PreparedLbfvDispatch> {
    let preset = params_profile.threshold_preset();
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
        // The commitments of a ready party were computed once, when its bundle was validated.
        // Dispatch only checks that the stored artifacts are still the manifest's documents.
        let validation = (|| {
            manifest.validate_documents_for_preset(&public_key, &rlk, preset)?;
            state.validated_commitments(*party_id)?;
            lbfv_proofs_for_dispatch(&public_key, &rlk)
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

    let mut dispatched = state.clone();
    match &state.verification {
        LbfvContributionVerificationStateV1::Ready { .. } => {
            dispatched.mark_verification_dispatched()?;
            repositories
                .persist_publickey_lbfv_transition(&state, &dispatched)
                .await?;
        }
        LbfvContributionVerificationStateV1::Dispatched { .. } => {}
        _ => anyhow::bail!("l-BFV dispatch requires a ready candidate set"),
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
    let event = lbfv_dispatch_event(&dispatched, party_proofs, params_profile, committee_size)?;
    Ok(PreparedLbfvDispatch::Dispatch {
        state: Box::new(dispatched),
        event,
    })
}

/// The l-BFV generation bundle that share verification checks: every public-key row proof, then
/// every relinearization-key row proof, in row order.
fn lbfv_proofs_for_dispatch(
    public_key: &LbfvKeyShareDocument,
    rlk: &LbfvKeyShareDocument,
) -> Result<Vec<SignedProofPayload>> {
    anyhow::ensure!(
        public_key.role() == e3_events::LbfvKeyShareDocumentRole::PublicKey,
        "l-BFV public-key artifact has the wrong role"
    );
    anyhow::ensure!(
        rlk.role() == e3_events::LbfvKeyShareDocumentRole::RelinearizationKey,
        "l-BFV relinearization-key artifact has the wrong role"
    );
    let pk_rows = public_key.signed_row_proofs();
    let rlk_rows = rlk.signed_row_proofs();
    let mut proofs = Vec::with_capacity(pk_rows.len() + rlk_rows.len());
    proofs.extend(pk_rows.iter().cloned());
    proofs.extend(rlk_rows.iter().cloned());
    Ok(proofs)
}

fn lbfv_dispatch_event(
    state: &crate::LbfvContributionCollectionStateV1,
    party_proofs: Vec<PartyProofsToVerify>,
    params_profile: BfvProfile,
    committee_size: CiphernodesCommitteeSize,
) -> Result<LbfvShareVerificationDispatched> {
    Ok(LbfvShareVerificationDispatched {
        e3_id: state.e3_id.clone(),
        kind: VerificationKind::LbfvGenerationProofs,
        share_proofs: party_proofs,
        decryption_proofs: Vec::new(),
        pre_dishonest: BTreeSet::new(),
        params_profile,
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
    use e3_fhe_params::BfvPreset;

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
        let proofs = lbfv_proofs_for_dispatch(&public_key.document, &rlk.document)
            .expect("canonical proof bundle");
        let row_count = e3_fhe_params::lbfv_row_count(BfvPreset::SecureThreshold16384);
        let rows = row_count.expect("the preset supports l-BFV");
        assert_eq!(proofs.len(), 2 * rows);
        for (row, proof) in proofs[..rows].iter().enumerate() {
            assert_eq!(proof.payload.proof_type, ProofType::LbfvPkGeneration);
            assert_eq!(
                proof
                    .payload
                    .proof_type
                    .identity(&proof.payload.proof, row_count)?
                    .instance,
                row as u32
            );
        }
        for (row, proof) in proofs[rows..].iter().enumerate() {
            assert_eq!(proof.payload.proof_type, ProofType::RlkGeneration);
            assert_eq!(
                proof
                    .payload
                    .proof_type
                    .identity(&proof.payload.proof, row_count)?
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
            BfvProfile::SsSecure16384,
            CiphernodesCommitteeSize::Minimum,
        )?;
        assert_eq!(event.kind, VerificationKind::LbfvGenerationProofs);
        assert!(event.pre_dishonest.is_empty());
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
