// SPDX-License-Identifier: LGPL-3.0-only

//! Synchronized phases of the existing public-key actor. Standbys retain the same authenticated
//! inputs; an exclusive flush precedes readiness, compute dispatch and local publication intent.

use super::super::*;
use crate::workflow::publickey_aggregation::synchronized::PublicationRecord;
use alloy::primitives::Address;
use anyhow::{ensure, Context as _};
use e3_data::Repository;
use e3_events::*;
use e3_request::canonical_key::CanonicalPublicKeys;
use std::time::Duration;

#[derive(Message)]
#[rtype(result = "()")]
struct RetireSynchronizedPublication;

impl Handler<RetireSynchronizedPublication> for PublicKeyAggregator {
    type Result = ();
    fn handle(&mut self, _: RetireSynchronizedPublication, ctx: &mut Context<Self>) {
        let Some(runtime) = &mut self.synchronized else {
            return;
        };
        runtime.in_flight = None;
        if let Some(timer) = runtime.outcome_timer.take() {
            ctx.cancel_future(timer);
        }
        if let Some(retry) = runtime.retry.take() {
            ctx.cancel_future(retry);
        }
        if let Some(retry) = runtime.flush_retry.take() {
            ctx.cancel_future(retry);
        }
        let store = e3_data::DataStore::from(runtime.repository.clone());
        ctx.wait(
            async move { store.remove_sync().await }
                .into_actor(self)
                .map(|result, actor, ctx| match result {
                    Ok(()) => ctx.stop(),
                    Err(error) => {
                        actor.bus.err(EType::PublickeyAggregation, error);
                        ctx.notify_later(
                            RetireSynchronizedPublication,
                            std::time::Duration::from_secs(1),
                        );
                    }
                }),
        );
    }
}

pub(in crate::actors::publickey_aggregator) struct SynchronizedPublication {
    pub record: Option<PublicationRecord>,
    pub repository: Repository<PublicationRecord>,
    pub keys: CanonicalPublicKeys,
    pub interfold: Address,
    in_flight: Option<ComputeRequest>,
    published: bool,
    retry: Option<actix::SpawnHandle>,
    retry_delay: Duration,
    outcome_timer: Option<actix::SpawnHandle>,
    invalid_work: bool,
    flush_pending: bool,
    flush_retry: Option<actix::SpawnHandle>,
    flush_failures: u32,
}

impl PublicKeyAggregator {
    pub(crate) fn with_synchronized_publication(
        mut self,
        repository: Repository<PublicationRecord>,
        keys: CanonicalPublicKeys,
        interfold: Address,
        selection: Option<TypedEvent<CiphernodeSelected>>,
    ) -> Self {
        self.synchronized = Some(SynchronizedPublication {
            record: selection.map(|selected| {
                let (selected, ec) = selected.into_components();
                PublicationRecord::new(selected, ec)
            }),
            repository,
            keys,
            interfold,
            in_flight: None,
            published: false,
            retry: None,
            retry_delay: Duration::from_secs(1),
            outcome_timer: None,
            invalid_work: false,
            flush_pending: false,
            flush_retry: None,
            flush_failures: 0,
        });
        self
    }

    pub(crate) async fn recover_synchronized_publication(
        &mut self,
        history: &Recipient<EventStoreQueryBy<SeqAgg>>,
        meta: &e3_request::E3Meta,
    ) -> Result<()> {
        let runtime = self
            .synchronized
            .as_mut()
            .context("missing synchronized publication owner")?;
        runtime.record = e3_data::DataStore::from(runtime.repository.clone())
            .read_checked()
            .await?;
        let id = self.e3_id.clone();
        if runtime.record.is_none() {
            crate::history::visit_e3_history(history, &id, |event| {
                if let InterfoldEventData::CiphernodeSelected(selected) = event.get_data() {
                    runtime.record = Some(PublicationRecord::new(
                        selected.clone(),
                        event.get_ctx().clone(),
                    ));
                }
                Ok(())
            })
            .await?;
        }
        let record = runtime
            .record
            .as_mut()
            .context("missing canonical publication selection")?;
        ensure!(
            record.selected.e3_id == id && e3_request::E3Meta::from(&record.selected) == *meta,
            "recovered publication selection differs from request metadata"
        );
        let state = self.state.try_get()?;
        for (party, member) in record.selected.committee.iter().enumerate() {
            ensure!(
                state.party_id_for_node(member.parse()?) == Some(party as u64),
                "recovered publication selection differs from finalized committee"
            );
        }
        record.validate(runtime.interfold)?;
        // The mutable SS snapshot cursor may have passed inputs delivered before local C4
        // fixation. Scan the complete E3 history, including that prefix, with effects fenced.
        crate::history::visit_e3_history(history, &id, |event| {
            let data = event.get_data();
            if matches!(
                data,
                InterfoldEventData::KeyshareCreated(_)
                    | InterfoldEventData::SynchronizedRecipientProofReady(_)
                    | InterfoldEventData::SynchronizedDkgProofPublished(_)
                    | InterfoldEventData::SynchronizedDkgConsentPublished(_)
            ) {
                let mut next = record.clone();
                if next
                    .intake(
                        data,
                        event.get_ctx(),
                        runtime.interfold,
                        runtime.keys.synchronized_context(&id),
                    )
                    .is_ok()
                {
                    *record = next;
                }
            }
            Ok(())
        })
        .await?;
        record.prune_consents(runtime.keys.synchronized_context(&id))?;
        record.validate(runtime.interfold)?;
        runtime.repository.write_sync(record).await?;
        Ok(())
    }

    pub(in crate::actors::publickey_aggregator) fn route_synchronized_publication(
        &mut self,
        data: &InterfoldEventData,
        ec: &EventContext<Sequenced>,
        ctx: &mut Context<Self>,
    ) -> bool {
        if self.params_profile.protocol() != e3_fhe_params::BfvDecryptionProtocol::Synchronized {
            return false;
        }
        if self.params_profile.ensure_admission_enabled().is_err() {
            return true;
        }
        if let Err(error) = self.route_synchronized_publication_definition(data, ec, ctx) {
            self.bus.with_ec(ec).err(EType::PublickeyAggregation, error);
        }
        true
    }

    pub(in crate::actors::publickey_aggregator) fn route_synchronized_publication_definition(
        &mut self,
        data: &InterfoldEventData,
        ec: &EventContext<Sequenced>,
        ctx: &mut Context<Self>,
    ) -> Result<()> {
        // Many capabilities share this E3's compute mailbox. Only our current correlation can
        // answer this phase; unrelated and superseded outcomes are not aggregation errors.
        let pending = self
            .synchronized
            .as_ref()
            .and_then(|r| r.in_flight.as_ref());
        match data {
            InterfoldEventData::ComputeResponse(response)
                if pending.is_none_or(|p| p.correlation_id != response.correlation_id) =>
            {
                return Ok(());
            }
            InterfoldEventData::ComputeRequestError(error)
                if pending.is_none_or(|p| p.correlation_id != *error.correlation_id()) =>
            {
                return Ok(());
            }
            _ => {}
        }
        if !matches!(
            data,
            InterfoldEventData::EffectsEnabled(_)
                | InterfoldEventData::AggregatorChanged(_)
                | InterfoldEventData::CommitteePublished(_)
                | InterfoldEventData::E3StageChanged(_)
                | InterfoldEventData::E3RequestComplete(_)
                | InterfoldEventData::E3Failed(_)
                | InterfoldEventData::KeyshareCreated(_)
                | InterfoldEventData::SynchronizedRecipientProofReady(_)
                | InterfoldEventData::SynchronizedDkgProofPublished(_)
                | InterfoldEventData::SynchronizedDkgConsentPublished(_)
                | InterfoldEventData::ComputeResponse(_)
                | InterfoldEventData::ComputeRequestError(_)
                | InterfoldEventData::AggregationResumed(_)
                | InterfoldEventData::SynchronizedDkgContextEstablished(_)
        ) {
            return Ok(());
        }
        if matches!(
            data,
            InterfoldEventData::SynchronizedDkgProofPublished(SynchronizedDkgProofPublished {
                role: SynchronizedDkgProofRole::Dealer,
                ..
            })
        ) {
            return Ok(());
        }
        if let Some(id) = data.get_e3_id() {
            ensure!(id == self.e3_id, "publication event has another E3");
        }
        match data {
            InterfoldEventData::EffectsEnabled(_) => {
                ensure!(
                    ec.source() == EventSource::Local,
                    "effects signal must be local"
                );
                self.effects_enabled = true;
            }
            InterfoldEventData::AggregatorChanged(role) => self.is_aggregator = role.is_aggregator,
            InterfoldEventData::CommitteePublished(_) => self.observe_stage(&E3Stage::KeyPublished),
            InterfoldEventData::E3StageChanged(stage) if !stage.new_stage.is_terminal() => {
                self.observe_stage(&stage.new_stage);
            }
            InterfoldEventData::E3RequestComplete(_)
            | InterfoldEventData::E3Failed(_)
            | InterfoldEventData::E3StageChanged(E3StageChanged {
                new_stage: E3Stage::Complete | E3Stage::Failed,
                ..
            }) => {
                self.key_published = true;
                self.notify_sync(ctx, RetireSynchronizedPublication);
                return Ok(());
            }
            _ => {}
        }
        let runtime = self
            .synchronized
            .as_mut()
            .context("missing publication owner")?;
        let Some(mut next) = runtime.record.clone() else {
            return Ok(());
        };
        if self.key_published || runtime.keys.get(&self.e3_id).is_some() {
            runtime.in_flight = None;
            if let Some(timer) = runtime.outcome_timer.take() {
                ctx.cancel_future(timer);
            }
            if let Some(retry) = runtime.retry.take() {
                ctx.cancel_future(retry);
            }
            if let Some(retry) = runtime.flush_retry.take() {
                ctx.cancel_future(retry);
            }
            return Ok(());
        }
        next.prune_consents(runtime.keys.synchronized_context(&self.e3_id))?;
        match data {
            InterfoldEventData::ComputeResponse(response) => {
                ensure!(
                    ec.source() == EventSource::Local,
                    "publication worker result must be local"
                );
                let pending = runtime
                    .in_flight
                    .as_ref()
                    .context("unsolicited publication response")?;
                ensure!(
                    response.correlation_id == pending.correlation_id
                        && response.e3_id == pending.e3_id,
                    "stale publication response"
                );
                let plan = next.plan.as_ref().context("response without local setup")?;
                match (&pending.request, &response.response) {
                    (
                        ComputeRequestKind::Zk(ZkRequest::PkAggregation(native)),
                        ComputeResponseKind::Zk(ZkResponse::PkAggregation(result)),
                    ) => {
                        plan.validate_c5(native, &result.proof)?;
                        next.c5 = Some(result.proof.clone());
                    }
                    (
                        ComputeRequestKind::Zk(ZkRequest::SynchronizedDkg(work)),
                        ComputeResponseKind::Zk(ZkResponse::SynchronizedDkg(
                            SynchronizedDkgProofResponse::Publication { proof },
                        )),
                    ) => {
                        ensure!(
                            next.work()?.as_ref() == Some(work.as_ref()),
                            "publication plan was replaced"
                        );
                        plan.validate_publication(
                            &next.native()?.context("missing native PK")?,
                            work,
                            proof,
                        )?;
                        next.proof = Some(proof.clone());
                    }
                    _ => anyhow::bail!("publication response has another phase"),
                }
                runtime.in_flight = None;
                if let Some(timer) = runtime.outcome_timer.take() {
                    ctx.cancel_future(timer);
                }
                if let Some(retry) = runtime.retry.take() {
                    ctx.cancel_future(retry);
                }
                runtime.retry_delay = Duration::from_secs(1);
                runtime.invalid_work = false;
            }
            InterfoldEventData::ComputeRequestError(error) => {
                ensure!(
                    ec.source() == EventSource::Local
                        && runtime.in_flight.as_ref() == Some(error.request()),
                    "unrelated publication worker error"
                );
                if let Some(timer) = runtime.outcome_timer.take() {
                    ctx.cancel_future(timer);
                }
                runtime.invalid_work = matches!(
                    error.get_err(),
                    ComputeRequestErrorKind::Zk(ZkError::InvalidParams(_))
                );
                if runtime.invalid_work {
                    if let Some(retry) = runtime.retry.take() {
                        ctx.cancel_future(retry);
                    }
                }
                // Keep exact inputs; only local generation failures get a bounded-rate retry.
                // InvalidParams still waits for repaired inputs or an explicit resume.
                self.bus
                    .with_ec(ec)
                    .err(EType::PublickeyAggregation, anyhow::anyhow!("{error}"));
                if matches!(
                    error.get_err(),
                    ComputeRequestErrorKind::Zk(
                        ZkError::ProofGenerationFailed(_) | ZkError::WitnessGenerationFailed(_)
                    )
                ) {
                    self.retry_synchronized_work(ctx);
                }
                return Ok(());
            }
            InterfoldEventData::AggregationResumed(resume)
                if resume.phase == AggregationPhase::PublicKey =>
            {
                ensure!(
                    ec.source() == EventSource::Local,
                    "publication resume must be local"
                );
                runtime.in_flight = None;
                runtime.invalid_work = false;
                if let Some(timer) = runtime.outcome_timer.take() {
                    ctx.cancel_future(timer);
                }
            }
            _ => next.intake(
                data,
                ec,
                runtime.interfold,
                runtime.keys.synchronized_context(&self.e3_id),
            )?,
        }
        self.flush_synchronized_publication(next, ctx)
    }

    fn flush_synchronized_publication(
        &mut self,
        mut next: PublicationRecord,
        ctx: &mut Context<Self>,
    ) -> Result<()> {
        let runtime = self
            .synchronized
            .as_mut()
            .context("missing publication owner")?;
        next.prune_consents(runtime.keys.synchronized_context(&self.e3_id))?;
        next.validate(runtime.interfold)?;
        if self.effects_enabled && self.is_aggregator && next.native()?.is_some() {
            next.started = true;
        }
        let mut replaced_work = false;
        if let Some(ComputeRequest {
            request: ComputeRequestKind::Zk(ZkRequest::SynchronizedDkg(work)),
            ..
        }) = &runtime.in_flight
        {
            if next.work()?.as_ref() != Some(work.as_ref()) {
                runtime.in_flight = None;
                runtime.invalid_work = false;
                if let Some(timer) = runtime.outcome_timer.take() {
                    ctx.cancel_future(timer);
                }
                replaced_work = true;
            }
        }
        let repository = runtime.repository.clone();
        // Keep accepted inputs even if the flush fails; no effects may use this snapshot yet.
        runtime.record = Some(next.clone());
        runtime.flush_pending = true;
        if replaced_work {
            self.retry_synchronized_work(ctx);
        }
        ctx.wait(
            async move { repository.write_sync(&next).await }
            .into_actor(self)
            .map(|result, actor, ctx| match result {
                Ok(_) => {
                    let runtime = actor.synchronized.as_mut().expect("configured owner");
                    runtime.flush_pending = false;
                    runtime.flush_failures = 0;
                    if let Some(retry) = runtime.flush_retry.take() {
                        ctx.cancel_future(retry);
                    }
                    if let Err(error) = actor.publish_synchronized_work() {
                        actor.bus.err(EType::PublickeyAggregation, error);
                        actor.retry_synchronized_flush(ctx);
                    }
                    actor.watch_synchronized_outcome(ctx);
                }
                Err(error) => {
                    let runtime = actor.synchronized.as_mut().expect("configured owner");
                    runtime.flush_failures = runtime.flush_failures.saturating_add(1);
                    if runtime.flush_failures == 1 {
                        actor.bus.err(EType::PublickeyAggregation, error);
                    } else {
                        tracing::warn!(%error, "publication storage still unavailable; retry retained");
                    }
                    actor.retry_synchronized_flush(ctx);
                }
            }),
        );
        Ok(())
    }

    fn watch_synchronized_outcome(&mut self, ctx: &mut Context<Self>) {
        let Some(runtime) = &mut self.synchronized else {
            return;
        };
        if runtime.outcome_timer.is_some() || runtime.in_flight.is_none() || runtime.invalid_work {
            return;
        }
        runtime.outcome_timer = Some(ctx.run_later(Duration::from_secs(60), |actor, ctx| {
            let Some(runtime) = &mut actor.synchronized else {
                return;
            };
            runtime.outcome_timer = None;
            if runtime.in_flight.is_some() {
                // Fresh-correlated redelivery probes the gate's retained outcome; the gate
                // refuses to repeat slow work while any matching attempt is queued/running.
                actor.retry_synchronized_work(ctx);
            }
        }));
    }

    fn retry_synchronized_flush(&mut self, ctx: &mut Context<Self>) {
        if !self.effects_enabled || self.key_published {
            return;
        }
        let Some(runtime) = &mut self.synchronized else {
            return;
        };
        if runtime.flush_retry.is_some() || runtime.keys.get(&self.e3_id).is_some() {
            return;
        }
        let delay = e3_utils::backoff_delay(
            Duration::from_secs(1),
            runtime.flush_failures,
            Duration::from_secs(30),
        );
        runtime.flush_retry = Some(ctx.run_later(delay, |actor, ctx| {
            let Some(runtime) = &mut actor.synchronized else {
                return;
            };
            runtime.flush_retry = None;
            if !actor.effects_enabled
                || actor.key_published
                || runtime.keys.get(&actor.e3_id).is_some()
            {
                return;
            }
            let Some(record) = runtime.record.clone() else {
                return;
            };
            // A storage retry also belongs to standbys and must not clear a live worker's
            // correlation, unlike a worker redrive through AggregationResumed.
            if let Err(error) = actor.flush_synchronized_publication(record, ctx) {
                actor.bus.err(EType::PublickeyAggregation, error);
            }
        }));
    }

    fn retry_synchronized_work(&mut self, ctx: &mut Context<Self>) {
        if !self.effects_enabled || self.key_published {
            return;
        }
        let Some(runtime) = &mut self.synchronized else {
            return;
        };
        if runtime.retry.is_some() || runtime.keys.get(&self.e3_id).is_some() {
            return;
        }
        let delay = runtime.retry_delay;
        runtime.retry_delay = (delay * 2).min(Duration::from_secs(30));
        runtime.retry = Some(ctx.run_later(delay, |actor, ctx| {
            let Some(runtime) = &mut actor.synchronized else {
                return;
            };
            runtime.retry = None;
            if !actor.effects_enabled
                || actor.key_published
                || runtime.keys.get(&actor.e3_id).is_some()
            {
                return;
            }
            let Some(record) = &runtime.record else {
                return;
            };
            // A standby cannot start; the existing started-owner rule permits finishing after
            // demotion. Resume revalidates and flushes the latest record before fresh dispatch.
            if !actor.is_aggregator && !record.started {
                return;
            }
            let ec = record.ec.clone();
            let resume = AggregationResumed {
                e3_id: actor.e3_id.clone(),
                phase: AggregationPhase::PublicKey,
                correlation_id: CorrelationId::new(),
            };
            if let Err(error) =
                actor.route_synchronized_publication_definition(&resume.into(), &ec, ctx)
            {
                actor.bus.err(EType::PublickeyAggregation, error);
            }
        }));
    }

    fn publish_synchronized_work(&mut self) -> Result<()> {
        if !self.effects_enabled || self.key_published {
            return Ok(());
        }
        let runtime = self
            .synchronized
            .as_mut()
            .context("missing publication owner")?;
        if runtime.keys.get(&self.e3_id).is_some() {
            return Ok(());
        }
        if runtime.flush_pending {
            return Ok(());
        }
        let Some(record) = &runtime.record else {
            return Ok(());
        };
        let Some(native) = record.native()? else {
            return Ok(());
        };
        self.bus.publish(
            AggregationInputsReady {
                e3_id: self.e3_id.clone(),
                phase: AggregationPhase::PublicKey,
            },
            record.ec.clone(),
        )?;
        if !self.is_aggregator && !record.started {
            return Ok(());
        }
        if let Some(context) = runtime.keys.synchronized_context(&self.e3_id) {
            if let Some(output) = record.output(context)? {
                if !runtime.published {
                    self.bus.publish(output, record.ec.clone())?;
                    runtime.published = true;
                }
                return Ok(());
            }
        }
        if runtime.retry.is_some() || runtime.in_flight.is_some() || record.proof.is_some() {
            return Ok(());
        }
        let work = if record.c5.is_none() {
            ZkRequest::PkAggregation(native)
        } else if let Some(work) = record.work()? {
            ZkRequest::SynchronizedDkg(Box::new(work))
        } else {
            return Ok(());
        };
        let request = ComputeRequest::zk(work, CorrelationId::new(), self.e3_id.clone());
        self.bus.publish(request.clone(), record.ec.clone())?;
        runtime.in_flight = Some(request);
        Ok(())
    }
}
