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
                    .intake(data, event.get_ctx(), runtime.interfold)
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
            }
            InterfoldEventData::ComputeRequestError(error) => {
                ensure!(
                    ec.source() == EventSource::Local
                        && runtime.in_flight.as_ref() == Some(error.request()),
                    "unrelated publication worker error"
                );
                // Keep the exact work for a later resume/restart; infrastructure failure is never
                // an invalid peer-proof verdict or a reason to manufacture a partial-H result.
                self.bus
                    .with_ec(ec)
                    .err(EType::PublickeyAggregation, anyhow::anyhow!("{error}"));
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
            }
            _ => next.intake(data, ec, runtime.interfold)?,
        }
        next.prune_consents(runtime.keys.synchronized_context(&self.e3_id))?;
        next.validate(runtime.interfold)?;
        if self.effects_enabled && self.is_aggregator && next.native()?.is_some() {
            next.started = true;
        }
        if let Some(ComputeRequest {
            request: ComputeRequestKind::Zk(ZkRequest::SynchronizedDkg(work)),
            ..
        }) = &runtime.in_flight
        {
            if next.work()?.as_ref() != Some(work.as_ref()) {
                runtime.in_flight = None;
            }
        }
        let repository = runtime.repository.clone();
        ctx.wait(
            async move {
                repository.write_sync(&next).await?;
                Ok::<_, anyhow::Error>(next)
            }
            .into_actor(self)
            .map(|result, actor, _| match result {
                Ok(next) => {
                    actor
                        .synchronized
                        .as_mut()
                        .expect("configured owner")
                        .record = Some(next);
                    if let Err(error) = actor.publish_synchronized_work() {
                        actor.bus.err(EType::PublickeyAggregation, error);
                    }
                }
                Err(error) => actor.bus.err(EType::PublickeyAggregation, error),
            }),
        );
        Ok(())
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
        if runtime.in_flight.is_some() || record.proof.is_some() {
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
