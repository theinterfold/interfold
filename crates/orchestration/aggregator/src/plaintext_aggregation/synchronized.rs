// SPDX-License-Identifier: LGPL-3.0-only

//! Fixed-set plaintext recipient. The journal is the durable input queue on every committee
//! node; cursor advancement follows verification, so a local verifier failure can retry.
use actix::prelude::*;
use anyhow::{ensure, Result};
use e3_data::{DataStore, DurableIntent};
use e3_events::{
    prelude::*, AggregationInputsReady, AggregationPhase, BusHandle, DecryptionshareCreated, E3id,
    EventSource, EventStoreQueryBy, InterfoldEvent, InterfoldEventData as Data,
    PlaintextAggregated, SeqAgg,
};
use e3_request::canonical_key::{CanonicalPublicKeys, SynchronizedDecryptionPlan};
use e3_task_pool::{scoped_task_group, TaskTimeouts};
use e3_utils::ArcBytes;
use e3_zk_prover::synchronized::fixed_set::{
    reconstruct, verify_contribution, verify_saved_result, DecryptionRuntime,
};
use std::{collections::BTreeMap, ops::RangeInclusive, time::Duration};

type VerifiedRows = BTreeMap<u64, (u64, DecryptionshareCreated)>;

struct Collection {
    journal: Recipient<EventStoreQueryBy<SeqAgg>>,
    checkpoints: DataStore,
    keys: CanonicalPublicKeys,
    runtime: DecryptionRuntime,
}

impl Collection {
    async fn admit(
        &self,
        plan: SynchronizedDecryptionPlan,
        ct: ArcBytes,
        deadline: u64,
        range: RangeInclusive<u64>,
        mut rows: VerifiedRows,
    ) -> Result<(VerifiedRows, Option<u64>)> {
        let mut retry = None;
        let mut pins = BTreeMap::new();
        for &owner in plan.designated() {
            let slot =
                DurableIntent::<u64>::new(self.checkpoints.scope(format!("verified-{owner}")));
            pins.insert(u64::from(owner), (slot.restore().await?, slot));
        }
        let group = scoped_task_group(&self.runtime.task_scope, plan.e3_id());
        let mut pages = crate::history::E3HistoryPages::new(&self.journal, plan.e3_id(), range);
        while let Some(page) = pages.next().await? {
            for event in page {
                let seq = event.seq();
                let Data::DecryptionshareCreated(bundle) = event.into_data() else {
                    continue;
                };
                let Some((saved, slot)) = pins.get(&bundle.party_id) else {
                    continue;
                };
                if rows.contains_key(&bundle.party_id) || saved.is_some_and(|s| s != seq) {
                    continue;
                }
                let (plan, keys, ct, prover) = (
                    plan.clone(),
                    self.keys.clone(),
                    ct.clone(),
                    self.runtime.prover.clone(),
                );
                let job = plan.e3_id().to_string();
                self.runtime
                    .open_deadline(plan.e3_id(), Some(deadline))
                    .await?;
                let verified = self
                    .runtime
                    .pool
                    .spawn_in_group(
                        group.clone(),
                        "verify designated C6".into(),
                        TaskTimeouts::default(),
                        move || {
                            plan.check_current(&keys, &ct)?;
                            Ok::<_, anyhow::Error>(
                                verify_contribution(&prover, &plan, &bundle, &job)?
                                    .then_some(bundle),
                            )
                        },
                    )
                    .await?;
                match verified {
                    Ok(Some(bundle)) => {
                        slot.record(&seq).await?;
                        rows.insert(bundle.party_id, (seq, bundle));
                    }
                    Ok(None) => {
                        ensure!(saved.is_none(), "previously verified C6 no longer verifies")
                    }
                    Err(error) => {
                        // Retry inconclusive bodies without blocking a corrected later candidate.
                        retry.get_or_insert(seq);
                        tracing::warn!(%error,seq,"local C6 verification incomplete");
                    }
                }
            }
        }
        ensure!(
            pages.reached_end(),
            "history ended before the observed contribution sequence"
        );
        self.runtime
            .open_deadline(plan.e3_id(), Some(deadline))
            .await?;
        Ok((rows, retry))
    }
}

pub struct FixedSetPlaintext {
    bus: BusHandle,
    id: E3id,
    keys: CanonicalPublicKeys,
    runtime: DecryptionRuntime,
    journal: Recipient<EventStoreQueryBy<SeqAgg>>,
    checkpoints: DataStore,
    active: bool,
    effects: bool,
    running: Option<SpawnHandle>,
    retry: Option<SpawnHandle>,
    failures: u32,
    ended: bool,
    published: bool,
    ready: bool,
    standby_waiting: bool,
    checked: u64,
    deadline: Option<u64>,
    rows: VerifiedRows,
}

impl FixedSetPlaintext {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        bus: BusHandle,
        id: E3id,
        keys: CanonicalPublicKeys,
        runtime: DecryptionRuntime,
        journal: Recipient<EventStoreQueryBy<SeqAgg>>,
        checkpoints: DataStore,
        active: bool,
        effects: bool,
    ) -> Self {
        Self {
            bus,
            id,
            keys,
            runtime,
            journal,
            checkpoints,
            active,
            effects,
            running: None,
            retry: None,
            failures: 0,
            ended: false,
            published: false,
            ready: false,
            standby_waiting: false,
            checked: 0,
            deadline: None,
            rows: BTreeMap::new(),
        }
    }

    fn drive(&mut self, ctx: &mut Context<Self>) -> Result<()> {
        if !self.effects
            || self.bus.is_shutting_down()
            || self.ended
            || self.running.is_some()
            || self.retry.is_some()
            || self.published
            || (self.standby_waiting && !self.active)
        {
            return Ok(());
        }
        let Some((first, through)) = self.keys.synchronized_candidates(&self.id) else {
            return Ok(());
        };
        if self.rows.is_empty() && self.checked >= through {
            return Ok(());
        }
        let Some((ct, ec)) = self.keys.synchronized_opening(&self.id) else {
            return Ok(());
        };
        let Some(key) = self.keys.get(&self.id) else {
            return Ok(());
        };
        let Some(plan) = self.keys.synchronized_decryption_definition(
            &self.id,
            key.params_profile,
            std::slice::from_ref(&ct),
        )?
        else {
            return Ok(());
        };
        let Some(deadline) = self.deadline else {
            let runtime = self.runtime.clone();
            let id = self.id.clone();
            self.running = Some(
                ctx.spawn(
                    async move { runtime.open_deadline(&id, None).await }
                        .into_actor(self)
                        .map(|result, actor, ctx| {
                            actor.running = None;
                            match result {
                                Ok(deadline) => {
                                    actor.deadline = Some(deadline);
                                    actor.wake(ctx);
                                }
                                Err(error) => actor.defer(ctx, error),
                            }
                        }),
                ),
            );
            return Ok(());
        };
        // The chain failure watch marks DecryptionTimeout. It starts from CiphertextReady,
        // independently of our role or readiness; promotion never creates another window.
        let pinned_count = plan.designated().len();
        if self.rows.len() < pinned_count {
            if self.checked >= through {
                return Ok(());
            }
            let range = first.max(self.checked + 1)..=through;
            let collection = Collection {
                journal: self.journal.clone(),
                keys: self.keys.clone(),
                checkpoints: self.checkpoints.clone(),
                runtime: self.runtime.clone(),
            };
            let rows = self.rows.clone();
            self.running = Some(
                ctx.spawn(
                    async move { collection.admit(plan, ct, deadline, range, rows).await }
                        .into_actor(self)
                        .map(move |result, actor, ctx| {
                            actor.running = None;
                            match result {
                                Ok((rows, retry)) => {
                                    actor.rows = rows;
                                    actor.checked = retry.map_or(through, |seq| seq - 1);
                                    if retry.is_none() || actor.rows.len() == pinned_count {
                                        actor.failures = 0;
                                        actor.wake(ctx);
                                    } else {
                                        actor.back_off(ctx);
                                    }
                                }
                                Err(error) => actor.defer(ctx, error),
                            }
                        }),
                ),
            );
            return Ok(());
        }
        if !self.ready {
            self.bus.publish(
                AggregationInputsReady {
                    e3_id: self.id.clone(),
                    phase: AggregationPhase::Plaintext,
                },
                ec.clone(),
            )?;
            self.ready = true;
        }
        let owner = ctx.address().recipient::<StartNewBatch>();
        let start = self.started_slot();
        let output = DurableIntent::<PlaintextAggregated>::new(self.checkpoints.scope("result"));
        let (sequences, bundles): (Vec<_>, Vec<_>) = self.rows.values().cloned().unzip();
        let keys = self.keys.clone();
        let rt = self.runtime.clone();
        let group = scoped_task_group(&rt.task_scope, &self.id);
        let job = plan.e3_id().to_string();
        self.running = Some(
            ctx.spawn(
                async move {
                    rt.open_deadline(plan.e3_id(), Some(deadline)).await?;
                    plan.check_current(&keys, &ct)?;
                    if let Some(saved) = DurableIntent::<Vec<u64>>::new(start.clone())
                        .restore()
                        .await?
                    {
                        ensure!(
                            saved == sequences,
                            "recorded batch differs from admitted sequences"
                        );
                        // A previous insert may have succeeded without acknowledging its flush.
                        start.flush_sync().await?;
                    } else if !owner.send(StartNewBatch(sequences)).await?? {
                        return Ok(None);
                    }
                    let saved = output.restore().await?;
                    let current_plan = plan.clone();
                    let bytes = ct.clone();
                    let prover = rt.prover.clone();
                    let result = rt
                        .pool
                        .spawn_in_group(
                            group,
                            "synchronized reconstruction and final proof".into(),
                            TaskTimeouts::default(),
                            move || {
                                plan.check_current(&keys, &ct)?;
                                if let Some(saved) = saved {
                                    ensure!(
                                        verify_saved_result(
                                            &prover, &plan, &bundles, &saved, &job
                                        )?,
                                        "saved proof differs from admitted batch"
                                    );
                                    Ok(saved)
                                } else {
                                    reconstruct(&prover, &plan, &ct, &bundles, &job)
                                }
                            },
                        )
                        .await??;
                    output.record(&result).await?;
                    rt.open_deadline(current_plan.e3_id(), Some(deadline))
                        .await?;
                    Ok::<_, anyhow::Error>(Some((current_plan, bytes, result)))
                }
                .into_actor(self)
                .map(move |result, actor, ctx| {
                    actor.running = None;
                    match result {
                        Ok(Some((plan, ct, intent))) => {
                            if actor.bus.is_shutting_down() {
                                return;
                            }
                            let result = plan
                                .check_current(&actor.keys, &ct)
                                .and_then(|_| actor.bus.publish(intent, ec));
                            match result {
                                Ok(()) => actor.published = true,
                                Err(error) => actor.defer(ctx, error),
                            }
                        }
                        Ok(None) if actor.active => actor.wake(ctx),
                        Ok(None) => actor.standby_waiting = true,
                        Err(error) => actor.defer(ctx, error),
                    }
                }),
            ),
        );
        Ok(())
    }

    fn wake(&mut self, ctx: &mut Context<Self>) {
        if let Err(error) = self.drive(ctx) {
            self.defer(ctx, error);
        }
    }

    fn started_slot(&self) -> DataStore {
        self.checkpoints.scope("started")
    }

    fn defer(&mut self, ctx: &mut Context<Self>, error: anyhow::Error) {
        tracing::warn!(e3_id=%self.id, %error, "synchronized collection deferred");
        self.back_off(ctx);
    }

    fn back_off(&mut self, ctx: &mut Context<Self>) {
        self.failures = self.failures.saturating_add(1);
        let delay = e3_utils::backoff_delay(
            Duration::from_secs(2),
            self.failures,
            Duration::from_secs(60),
        );
        self.retry = Some(ctx.run_later(delay, |actor, ctx| {
            actor.retry = None;
            actor.wake(ctx);
        }));
    }

    fn retire(&mut self, ctx: &mut Context<Self>) {
        self.ended = true;
        if let Some(handle) = self.running.take() {
            ctx.cancel_future(handle);
        }
        let store = self.checkpoints.clone();
        ctx.wait(
            async move {
                // Include the slash: similarly named sibling scopes are not part of this E3.
                for key in store
                    .keys_with_prefix(store.scope("").scope_bytes().to_vec())
                    .await?
                {
                    store.base(key).remove_sync().await?;
                }
                Ok::<_, anyhow::Error>(())
            }
            .into_actor(self)
            .map(|result, actor, ctx| match result {
                Ok(()) => ctx.stop(),
                Err(error) => {
                    tracing::warn!(%error, e3_id=%actor.id, "retrying terminal plaintext cleanup");
                    ctx.run_later(Duration::from_secs(2), Self::retire);
                }
            }),
        );
    }
}

#[derive(Message)]
#[rtype(result = "Result<bool>")]
struct StartNewBatch(Vec<u64>);

impl Handler<StartNewBatch> for FixedSetPlaintext {
    type Result = AtomicResponse<Self, Result<bool>>;

    fn handle(&mut self, batch: StartNewBatch, _: &mut Context<Self>) -> Self::Result {
        if !self.active || self.ended || self.bus.is_shutting_down() {
            return AtomicResponse::new(Box::pin(actix::fut::ready(Ok(false))));
        }
        // Only the first checkpoint write excludes role changes; RPC and proving stay interruptible.
        let slot = DurableIntent::new(self.started_slot());
        AtomicResponse::new(Box::pin(
            async move {
                slot.record(&batch.0).await?;
                Ok(true)
            }
            .into_actor(self),
        ))
    }
}

impl Actor for FixedSetPlaintext {
    type Context = Context<Self>;
    fn started(&mut self, ctx: &mut Context<Self>) {
        if self.effects {
            self.wake(ctx);
            ctx.run_interval(Duration::from_secs(10), Self::wake);
        }
    }
}

impl Handler<InterfoldEvent> for FixedSetPlaintext {
    type Result = ();
    fn handle(&mut self, event: InterfoldEvent, ctx: &mut Context<Self>) {
        if event.get_e3_id().is_some_and(|id| id != self.id) {
            return;
        }
        match event.get_data() {
            Data::EffectsEnabled(_) if event.source() == EventSource::Local => {
                if !self.effects {
                    self.effects = true;
                    ctx.run_interval(Duration::from_secs(10), Self::wake);
                }
            }
            Data::AggregatorChanged(role)
                if event.source() == EventSource::Local && role.e3_id == self.id =>
            {
                self.active = role.is_aggregator;
                if self.active {
                    self.standby_waiting = false;
                }
            }
            Data::DecryptionshareCreated(b) if b.e3_id == self.id => (),
            Data::E3StageChanged(stage)
                if stage.new_stage.is_terminal() && event.source() == EventSource::Evm =>
            {
                self.retire(ctx);
                return;
            }
            Data::E3RequestComplete(_) if event.source() != EventSource::Net => {
                self.retire(ctx);
                return;
            }
            Data::E3Failed(_) if event.source() == EventSource::Evm => {
                self.retire(ctx);
                return;
            }
            Data::E3Failed(_) | Data::Shutdown(_) if event.source() != EventSource::Net => {
                ctx.stop();
                return;
            }
            Data::CiphertextOutputPublished(_) | Data::E3StageChanged(_) => (),
            _ => return,
        }
        self.wake(ctx);
    }
}

#[cfg(test)]
#[path = "tests/synchronized_role.rs"]
mod role_tests;
