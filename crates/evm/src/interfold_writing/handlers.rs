// SPDX-License-Identifier: LGPL-3.0-only

//! Message routing and actor lifecycle.

use super::effects::*;
use super::*;
use e3_events::EventSource;
use std::collections::HashSet;

const PUBLICATION_RETRY_DELAY: std::time::Duration = std::time::Duration::from_secs(30);
const FAILURE_RETRY_DELAY: Duration = Duration::from_secs(30);
const FAILURE_PARTY_STAGGER_SECS: u64 = 15;

impl<P: Provider + WalletProvider + Clone + 'static> InterfoldSolWriter<P> {
    fn try_start_plaintext(&mut self, e3_id: &E3id, ctx: &mut actix::Context<Self>) {
        if !self.is_active_aggregator_for(e3_id) {
            return;
        }
        if let Some(intent) = self.publication.start(e3_id) {
            ctx.notify(SubmitPlaintext(intent));
        }
    }

    fn try_start_pending_plaintexts(&mut self, ctx: &mut actix::Context<Self>) {
        for e3_id in self.publication.pending_keys() {
            self.try_start_plaintext(&e3_id, ctx);
        }
    }

    fn try_start_failure_watch(&self, e3_id: &E3id, ctx: &mut actix::Context<Self>) {
        if !self.effects_enabled {
            return;
        }
        let Some(stage) = self.failure_stages.get(e3_id).cloned() else {
            return;
        };
        if stage == E3Stage::Requested && !self.request_registries.contains_key(e3_id) {
            return;
        }
        ctx.notify(ResolveFailureDeadline {
            e3_id: e3_id.clone(),
            stage,
        });
    }

    fn try_start_failure_watches(&self, ctx: &mut actix::Context<Self>) {
        for e3_id in self.failure_stages.keys() {
            self.try_start_failure_watch(e3_id, ctx);
        }
        let discovery_ids = self
            .committee_party_ids
            .keys()
            .chain(self.request_registries.keys())
            .cloned()
            .collect::<HashSet<_>>();
        for e3_id in discovery_ids {
            ctx.notify(DiscoverFailureStage { e3_id });
        }
        for e3_id in self.failure_settlements.pending_keys() {
            ctx.notify(ProcessFailedE3 { e3_id });
        }
    }

    fn clear_failure_watch(&mut self, e3_id: &E3id, ctx: &mut actix::Context<Self>) {
        self.failure_stage_discoveries.invalidate(e3_id);
        self.failure_stages.remove(e3_id);
        if let Some(handle) = self.failure_timers.remove(e3_id) {
            ctx.cancel_future(handle);
        }
    }

    fn arm_failure_timer(
        &mut self,
        e3_id: E3id,
        stage: E3Stage,
        schedule: FailureSchedule,
        ctx: &mut actix::Context<Self>,
    ) {
        if self.failure_stages.get(&e3_id) != Some(&stage) {
            return;
        }
        if let Some(handle) = self.failure_timers.remove(&e3_id) {
            ctx.cancel_future(handle);
        }

        let party_id =
            failure_watch_party_id(&stage, self.committee_party_ids.get(&e3_id).copied());
        let delay = failure_watch_delay(
            Self::now_unix_secs(),
            schedule.deadline,
            party_id,
            schedule.permissionless_grace,
            FAILURE_PARTY_STAGGER_SECS,
        );
        let timer_e3_id = e3_id.clone();
        let timer_stage = stage.clone();
        let handle = ctx.run_later(delay, move |actor, ctx| {
            actor.failure_timers.remove(&timer_e3_id);
            ctx.notify(MarkFailedAtDeadline {
                e3_id: timer_e3_id,
                stage: timer_stage,
            });
        });
        self.failure_timers.insert(e3_id, handle);
    }
}

impl<P: Provider + WalletProvider + Clone + 'static> Handler<InterfoldEvent>
    for InterfoldSolWriter<P>
{
    type Result = ();

    fn handle(&mut self, msg: InterfoldEvent, ctx: &mut Self::Context) -> Self::Result {
        let source = msg.source();
        match msg.into_data() {
            InterfoldEventData::EffectsEnabled(data) => self.notify_sync(ctx, data),
            InterfoldEventData::AggregatorChanged(data) => self.notify_sync(ctx, data),
            InterfoldEventData::CiphernodeSelected(data) => self.notify_sync(ctx, data),
            InterfoldEventData::DkgFoldAttestationContextEstablished(data) => {
                if self.provider.chain_id() == data.e3_id.chain_id() {
                    ctx.notify(data);
                }
            }
            InterfoldEventData::PlaintextAggregated(data) => {
                // Only a locally computed result is a publication intent. Peer results are
                // inputs for protocol observers and must not cross the EVM write boundary.
                if source == EventSource::Local && self.provider.chain_id() == data.e3_id.chain_id()
                {
                    ctx.notify(data);
                }
            }
            InterfoldEventData::E3StageChanged(data) => {
                if self.provider.chain_id() == data.e3_id.chain_id() {
                    ctx.notify(data);
                }
            }
            InterfoldEventData::E3RequestComplete(data) => self.notify_sync(ctx, data),
            InterfoldEventData::Shutdown(data) => self.notify_sync(ctx, data),
            _ => (),
        }
    }
}

impl<P: Provider + WalletProvider + Clone + 'static> Handler<EffectsEnabled>
    for InterfoldSolWriter<P>
{
    type Result = ();

    fn handle(&mut self, _: EffectsEnabled, ctx: &mut Self::Context) -> Self::Result {
        self.effects_enabled = true;
        self.publication.enable_effects();
        self.failure_settlements.enable_effects();
        self.try_start_pending_plaintexts(ctx);
        self.try_start_failure_watches(ctx);
    }
}

impl<P: Provider + WalletProvider + Clone + 'static> Handler<CiphernodeSelected>
    for InterfoldSolWriter<P>
{
    type Result = ();

    fn handle(&mut self, msg: CiphernodeSelected, ctx: &mut Self::Context) -> Self::Result {
        if self.provider.chain_id() != msg.e3_id.chain_id() {
            return;
        }
        self.committee_party_ids
            .insert(msg.e3_id.clone(), msg.party_id);
        self.try_start_failure_watch(&msg.e3_id, ctx);
        if self.effects_enabled {
            ctx.notify(DiscoverFailureStage { e3_id: msg.e3_id });
        }
    }
}

impl<P: Provider + WalletProvider + Clone + 'static> Handler<DkgFoldAttestationContextEstablished>
    for InterfoldSolWriter<P>
{
    type Result = ();

    fn handle(
        &mut self,
        msg: DkgFoldAttestationContextEstablished,
        ctx: &mut Self::Context,
    ) -> Self::Result {
        if msg.schema_version != DKG_FOLD_ATTESTATION_CONTEXT_SCHEMA_VERSION {
            self.request_registries.remove(&msg.e3_id);
            self.bus.err(
                EType::Evm,
                anyhow::anyhow!(
                    "unsupported DKG attestation context schema {} for E3 {}",
                    msg.schema_version,
                    msg.e3_id
                ),
            );
            return;
        }
        self.request_registries
            .insert(msg.e3_id.clone(), msg.context.registry);
        self.try_start_failure_watch(&msg.e3_id, ctx);
        if self.effects_enabled {
            ctx.notify(DiscoverFailureStage { e3_id: msg.e3_id });
        }
    }
}

impl<P: Provider + WalletProvider + Clone + 'static> Handler<AggregatorChanged>
    for InterfoldSolWriter<P>
{
    type Result = ();

    fn handle(&mut self, msg: AggregatorChanged, ctx: &mut Self::Context) -> Self::Result {
        let e3_id = msg.e3_id;
        self.active_aggregators
            .insert(e3_id.clone(), msg.is_aggregator);
        if msg.is_aggregator {
            self.try_start_plaintext(&e3_id, ctx);
        }
    }
}

impl<P: Provider + WalletProvider + Clone + 'static> Handler<E3RequestComplete>
    for InterfoldSolWriter<P>
{
    type Result = ();

    fn handle(&mut self, msg: E3RequestComplete, ctx: &mut Self::Context) -> Self::Result {
        self.active_aggregators.remove(&msg.e3_id);
        self.committee_party_ids.remove(&msg.e3_id);
        self.request_registries.remove(&msg.e3_id);
        self.clear_failure_watch(&msg.e3_id, ctx);
    }
}

impl<P: Provider + WalletProvider + Clone + 'static> Handler<PlaintextAggregated>
    for InterfoldSolWriter<P>
{
    type Result = ();

    fn handle(&mut self, msg: PlaintextAggregated, ctx: &mut Self::Context) -> Self::Result {
        let e3_id = msg.e3_id.clone();
        // Replay retains the durable local intent while the persisted aggregator role is restored.
        // Live results still require the active role when they enter the outbox, and every
        // submission attempt is role-gated by `try_start_plaintext`.
        if self.effects_enabled && !self.is_active_aggregator_for(&e3_id) {
            info!(e3_id = %e3_id, "Ignoring plaintext result while this node is not the active aggregator");
            return;
        }
        self.publication.record(e3_id.clone(), msg);
        self.try_start_plaintext(&e3_id, ctx);
    }
}

#[derive(Message)]
#[rtype(result = "()")]
struct SubmitPlaintext(PlaintextAggregated);

impl<P: Provider + WalletProvider + Clone + 'static> Handler<SubmitPlaintext>
    for InterfoldSolWriter<P>
{
    type Result = ResponseActFuture<Self, ()>;

    fn handle(&mut self, command: SubmitPlaintext, _ctx: &mut Self::Context) -> Self::Result {
        let msg = command.0;
        if !self.is_active_aggregator_for(&msg.e3_id) || !self.publication.contains(&msg.e3_id) {
            self.publication.finish(&msg.e3_id, false);
            return Box::pin(async {}.into_actor(self));
        }

        Box::pin(
            {
            let e3_id = msg.e3_id.clone();
            let decrypted_output = msg.decrypted_output.clone();
            let contract_address = self.contract_address;
            let provider = self.provider.clone();
            let bus = self.bus.clone();
            async move {
                // The event can represent multiple ciphertext outputs, but the contract accepts one
                // plaintext output per E3. Validation rejects multi-output results before indexing.
                if let Err(msg_err) = validate_plaintext_output(
                    &e3_id,
                    &decrypted_output,
                    &msg.decryption_aggregator_proofs,
                ) {
                    bus.err(EType::Evm, anyhow::anyhow!(msg_err));
                    return (e3_id, true);
                }
                // Safe: `validate_plaintext_output` guarantees exactly one output.
                let decrypted = &decrypted_output[0];
                match should_publish_plaintext(provider.clone(), contract_address, e3_id.clone())
                    .await
                {
                    Ok(false) => {
                        info!(e3_id = %e3_id, "Skipping publishPlaintextOutput; plaintext already published");
                        return (e3_id, true);
                    }
                    Err(err) => {
                        bus.err(
                            EType::Evm,
                            anyhow::anyhow!(
                                "Error preflighting plaintext publication: {}",
                                format_evm_error(&err)
                            ),
                        );
                        return (e3_id, false);
                    }
                    Ok(true) => {}
                }

                let result = publish_plaintext_output(
                    provider,
                    contract_address,
                    e3_id.clone(),
                    decrypted.extract_bytes(),
                    msg.decryption_aggregator_proofs.first(),
                )
                .await;
                match result {
                    Ok(receipt) => {
                        info!(tx=%receipt.transaction_hash, "Published plaintext output");
                        (e3_id, true)
                    }
                    Err(err) => {
                        bus.err(
                            EType::Evm,
                            anyhow::anyhow!(
                                "Error publishing plaintext output: {}",
                                format_evm_error(&err)
                            ),
                        );
                        (e3_id, false)
                    }
                }
            }
        }
            .into_actor(self)
            .map(|(e3_id, terminal), actor, ctx| {
                actor.publication.finish(&e3_id, terminal);
                if !terminal {
                    ctx.run_later(PUBLICATION_RETRY_DELAY, move |actor, ctx| {
                        actor.try_start_plaintext(&e3_id, ctx);
                    });
                }
            }),
        )
    }
}

impl<P: Provider + WalletProvider + Clone + 'static> Handler<Shutdown> for InterfoldSolWriter<P> {
    type Result = ();

    fn handle(&mut self, _: Shutdown, ctx: &mut Self::Context) -> Self::Result {
        for (_, handle) in self.failure_timers.drain() {
            ctx.cancel_future(handle);
        }
        ctx.stop();
    }
}

impl<P: Provider + WalletProvider + Clone + 'static> Handler<E3StageChanged>
    for InterfoldSolWriter<P>
{
    type Result = ();

    fn handle(&mut self, msg: E3StageChanged, ctx: &mut Self::Context) -> Self::Result {
        let e3_id = msg.e3_id.clone();
        self.failure_stage_discoveries.invalidate(&e3_id);
        match &msg.new_stage {
            E3Stage::Requested
            | E3Stage::CommitteeFinalized
            | E3Stage::KeyPublished
            | E3Stage::CiphertextReady => {
                self.failure_stages
                    .insert(e3_id.clone(), msg.new_stage.clone());
                self.try_start_failure_watch(&e3_id, ctx);
            }
            _ => self.clear_failure_watch(&e3_id, ctx),
        }

        if msg.new_stage == E3Stage::Failed {
            self.failure_settlements.record(e3_id.clone(), ());
            if self.effects_enabled {
                ctx.notify(ProcessFailedE3 { e3_id });
            }
        }
    }
}

impl<P: Provider + WalletProvider + Clone + 'static> Handler<ProcessFailedE3>
    for InterfoldSolWriter<P>
{
    type Result = ResponseActFuture<Self, ()>;

    fn handle(&mut self, msg: ProcessFailedE3, _ctx: &mut Self::Context) -> Self::Result {
        if self.failure_settlements.start(&msg.e3_id).is_none() {
            return Box::pin(async {}.into_actor(self));
        }

        let provider = self.provider.clone();
        let contract_address = self.contract_address;
        let e3_id = msg.e3_id;
        Box::pin(
            async move {
                let result = process_e3_failure(provider, contract_address, e3_id.clone()).await;
                (e3_id, result)
            }
            .into_actor(self)
            .map(|(e3_id, result), actor, ctx| {
                let terminal = match &result {
                    Ok(_) => true,
                    Err(error) => failure_settlement_error_is_terminal(error),
                };
                actor.failure_settlements.finish(&e3_id, terminal);

                match result {
                    Ok(receipt) => {
                        info!(
                            tx = %receipt.transaction_hash,
                            e3_id = %e3_id,
                            "Called processE3Failure"
                        );
                    }
                    Err(_) if terminal => {
                        info!(e3_id = %e3_id, "Failure settlement was already processed");
                    }
                    Err(error) => {
                        actor.bus.err(EType::Evm, error);
                        ctx.notify_later(ProcessFailedE3 { e3_id }, FAILURE_RETRY_DELAY);
                    }
                }
            }),
        )
    }
}

impl<P: Provider + WalletProvider + Clone + 'static> Handler<ResolveFailureDeadline>
    for InterfoldSolWriter<P>
{
    type Result = ResponseActFuture<Self, ()>;

    fn handle(&mut self, msg: ResolveFailureDeadline, _ctx: &mut Self::Context) -> Self::Result {
        if !self.effects_enabled || self.failure_stages.get(&msg.e3_id) != Some(&msg.stage) {
            return Box::pin(async {}.into_actor(self));
        }

        let provider = self.provider.clone();
        let contract_address = self.contract_address;
        let request_registry = self.request_registries.get(&msg.e3_id).copied();
        let request = msg.clone();
        Box::pin(
            async move {
                let result = read_failure_deadline(
                    provider,
                    contract_address,
                    request.e3_id.clone(),
                    request.stage.clone(),
                    request_registry,
                )
                .await;
                (request, result)
            }
            .into_actor(self)
            .map(|(request, result), actor, ctx| match result {
                Ok(schedule) if schedule.deadline > 0 => {
                    actor.arm_failure_timer(request.e3_id, request.stage, schedule, ctx);
                }
                Ok(_) => {
                    actor.bus.err(
                        EType::Evm,
                        anyhow::anyhow!("canonical failure deadline is zero"),
                    );
                    ctx.notify_later(request, FAILURE_RETRY_DELAY);
                }
                Err(error) => {
                    actor.bus.err(EType::Evm, error);
                    ctx.notify_later(request, FAILURE_RETRY_DELAY);
                }
            }),
        )
    }
}

impl<P: Provider + WalletProvider + Clone + 'static> Handler<DiscoverFailureStage>
    for InterfoldSolWriter<P>
{
    type Result = ResponseActFuture<Self, ()>;

    fn handle(&mut self, msg: DiscoverFailureStage, _ctx: &mut Self::Context) -> Self::Result {
        if !self.effects_enabled {
            return Box::pin(async {}.into_actor(self));
        }

        let provider = self.provider.clone();
        let contract_address = self.contract_address;
        let e3_id = msg.e3_id;
        let generation = self.failure_stage_discoveries.start(e3_id.clone());
        Box::pin(
            async move {
                let result =
                    read_watched_failure_stage(provider, contract_address, e3_id.clone()).await;
                (e3_id, generation, result)
            }
            .into_actor(self)
            .map(|(e3_id, generation, result), actor, ctx| {
                if !actor.failure_stage_discoveries.complete(&e3_id, generation) {
                    return;
                }
                match result {
                    Ok(Some(stage)) => {
                        actor.failure_stages.insert(e3_id.clone(), stage);
                        actor.try_start_failure_watch(&e3_id, ctx);
                    }
                    Ok(None) => actor.clear_failure_watch(&e3_id, ctx),
                    Err(error) => {
                        actor.bus.err(EType::Evm, error);
                        ctx.notify_later(DiscoverFailureStage { e3_id }, FAILURE_RETRY_DELAY);
                    }
                }
            }),
        )
    }
}

impl<P: Provider + WalletProvider + Clone + 'static> Handler<MarkFailedAtDeadline>
    for InterfoldSolWriter<P>
{
    type Result = ResponseActFuture<Self, ()>;

    fn handle(&mut self, msg: MarkFailedAtDeadline, _ctx: &mut Self::Context) -> Self::Result {
        if !self.effects_enabled || self.failure_stages.get(&msg.e3_id) != Some(&msg.stage) {
            return Box::pin(async {}.into_actor(self));
        }

        let provider = self.provider.clone();
        let contract_address = self.contract_address;
        let request = msg.clone();
        Box::pin(
            async move {
                let result = mark_e3_failed_if_due(
                    provider,
                    contract_address,
                    request.e3_id.clone(),
                    request.stage.clone(),
                )
                .await;
                (request, result)
            }
            .into_actor(self)
            .map(|(request, result), actor, ctx| match result {
                Ok(MarkFailureOutcome::Marked) => {
                    info!(e3_id = %request.e3_id, "Marked E3 failed after its canonical deadline");
                    actor.failure_stages.remove(&request.e3_id);
                }
                Ok(MarkFailureOutcome::StageAdvanced) => {
                    actor.clear_failure_watch(&request.e3_id, ctx);
                }
                Ok(MarkFailureOutcome::NotDue) => {
                    ctx.notify_later(request, FAILURE_RETRY_DELAY);
                }
                Err(error) => {
                    actor.bus.err(EType::Evm, error);
                    ctx.notify_later(request, FAILURE_RETRY_DELAY);
                }
            }),
        )
    }
}
