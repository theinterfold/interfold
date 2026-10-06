// SPDX-License-Identifier: LGPL-3.0-only

//! Message routing and actor lifecycle.

use super::effects::*;
use super::*;
use e3_events::EventSource;
use std::collections::HashSet;
use tracing::debug;

const PUBLICATION_RETRY_DELAY: std::time::Duration = std::time::Duration::from_secs(30);
const FAILURE_RETRY_DELAY: Duration = Duration::from_secs(30);
const FAILURE_PARTY_STAGGER_SECS: u64 = 15;

impl<P: Provider + WalletProvider + Clone + 'static> InterfoldSolWriter<P> {
    /// Return false only when canonical authority is still unavailable.
    fn admit_plaintext(&mut self, intent: PlaintextAggregated) -> bool {
        if self.terminal_e3s.contains(&intent.e3_id) {
            return true;
        }
        if let Err(error) = validate_plaintext_output(
            &intent.e3_id,
            &intent.decrypted_output,
            &intent.decryption_aggregator_proofs,
        ) {
            tracing::warn!(e3_id = %intent.e3_id, %error, "Discarding invalid plaintext publication intent");
            return true;
        }
        match plaintext_has_canonical_domain(&intent, &self.canonical_keys, self.contract_address) {
            Some(true) => self.publication.record(intent.e3_id.clone(), intent),
            Some(false) => {
                tracing::warn!(e3_id = %intent.e3_id, "Discarding plaintext publication intent with a noncanonical domain");
            }
            None => return false,
        }
        true
    }

    /// Submit a locally computed plaintext. The node that computed it submits it even after a
    /// failover demoted it: failover promotes a standby after a fixed budget, also while an
    /// honest aggregator is still proving. The submission skips a plaintext that is already on
    /// chain, so the first valid result wins.
    fn try_start_plaintext(&mut self, e3_id: &E3id, ctx: &mut actix::Context<Self>) {
        if self.terminal_e3s.contains(e3_id) {
            return;
        }
        if let Some(intent) = self.publication.start(e3_id) {
            ctx.notify(SubmitPlaintext(intent));
        }
    }

    fn try_start_pending_plaintexts(&mut self, ctx: &mut actix::Context<Self>) {
        for e3_id in self.deferred_plaintexts.keys().cloned().collect::<Vec<_>>() {
            self.try_resume_deferred_plaintexts(&e3_id, ctx);
        }
        for e3_id in self.publication.pending_keys() {
            self.try_start_plaintext(&e3_id, ctx);
        }
    }

    fn try_resume_deferred_plaintexts(&mut self, e3_id: &E3id, ctx: &mut Context<Self>) {
        if self.terminal_e3s.contains(e3_id)
            || self.canonical_keys.decryption_domains(e3_id).is_none()
        {
            return;
        }
        let Some(range) = self.deferred_plaintexts.get(e3_id).cloned() else {
            return;
        };
        if !self.plaintext_reads.insert(e3_id.clone()) {
            return;
        }
        let store = self.eventstore.clone();
        let id = e3_id.clone();
        ctx.spawn(
            async move {
                let result = read_plaintext_intents(&store, &id, range).await;
                (id, result)
            }
            .into_actor(self)
            .map(|(id, result), actor, ctx| {
                actor.plaintext_reads.remove(&id);
                if actor.terminal_e3s.contains(&id)
                    || actor.canonical_keys.decryption_domains(&id).is_none()
                {
                    return;
                }
                match result {
                    Ok((intents, next)) => {
                        for intent in intents {
                            actor.admit_plaintext(intent);
                        }
                        if let Some(range) = actor.deferred_plaintexts.remove(&id) {
                            if next <= *range.end() {
                                actor
                                    .deferred_plaintexts
                                    .insert(id.clone(), next..=*range.end());
                            }
                        }
                        actor.try_start_plaintext(&id, ctx);
                        actor.try_resume_deferred_plaintexts(&id, ctx);
                    }
                    Err(error) => {
                        actor.bus.err(EType::Evm, error);
                        ctx.run_later(PUBLICATION_RETRY_DELAY, move |actor, ctx| {
                            actor.try_resume_deferred_plaintexts(&id, ctx);
                        });
                    }
                }
            }),
        );
    }

    fn retire_plaintext(&mut self, e3_id: &E3id) {
        self.terminal_e3s.insert(e3_id.clone());
        self.deferred_plaintexts.remove(e3_id);
        self.publication.finish(e3_id, true);
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
        let sequence = msg.seq();
        let confirmed = source == EventSource::Evm && msg.block().is_some();
        let e3_id = msg.get_e3_id();
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
                    let id = data.e3_id.clone();
                    if self.admit_plaintext(data) {
                        self.try_start_plaintext(&id, ctx);
                    } else {
                        self.deferred_plaintexts
                            .entry(id)
                            .and_modify(|range| {
                                *range =
                                    (*range.start()).min(sequence)..=(*range.end()).max(sequence);
                            })
                            .or_insert(sequence..=sequence);
                    }
                }
            }
            InterfoldEventData::CiphertextOutputPublished(_)
            | InterfoldEventData::EvmLogObserved(_)
            | InterfoldEventData::CommitteePublished(_)
                if source != EventSource::Net =>
            {
                if let Some(id) = e3_id {
                    if id.chain_id() == self.provider.chain_id() {
                        self.try_resume_deferred_plaintexts(&id, ctx);
                    }
                }
            }
            InterfoldEventData::E3StageChanged(data) => {
                if confirmed && self.provider.chain_id() == data.e3_id.chain_id() {
                    self.notify_sync(ctx, data);
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
        if msg.is_aggregator {
            self.try_start_plaintext(&msg.e3_id, ctx);
        }
    }
}

impl<P: Provider + WalletProvider + Clone + 'static> Handler<E3RequestComplete>
    for InterfoldSolWriter<P>
{
    type Result = ();

    fn handle(&mut self, msg: E3RequestComplete, ctx: &mut Self::Context) -> Self::Result {
        // Local work can stop before the contract reaches a terminal stage.
        // Keep the chain deadline watch until E3StageChanged confirms settlement.
        self.try_start_failure_watch(&msg.e3_id, ctx);
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
        if !self.publication.contains(&msg.e3_id) {
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
                if !terminal && !actor.terminal_e3s.contains(&e3_id) {
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
        if msg.new_stage.is_terminal() {
            self.retire_plaintext(&e3_id);
        } else if self.terminal_e3s.contains(&e3_id) {
            return;
        }
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
            _ => {
                self.clear_failure_watch(&e3_id, ctx);
                self.request_registries.remove(&e3_id);
                self.committee_party_ids.remove(&e3_id);
            }
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
                    Ok(FailureSettlementOutcome::Submitted(_)
                    | FailureSettlementOutcome::Completed) => true,
                    Ok(FailureSettlementOutcome::Pending | FailureSettlementOutcome::Blocked) => {
                        false
                    }
                    Err(error) => failure_settlement_error_is_terminal(error),
                };
                actor.failure_settlements.finish(&e3_id, terminal);
                if terminal {
                    actor.blocked_settlements.clear(&e3_id);
                }

                match result {
                    Ok(FailureSettlementOutcome::Submitted(receipt)) => {
                        info!(
                            tx = %receipt.transaction_hash,
                            e3_id = %e3_id,
                            "Called processE3Failure"
                        );
                    }
                    Ok(FailureSettlementOutcome::Completed) => {
                        info!(e3_id = %e3_id, "E3 completed on-chain; no failure settlement needed");
                    }
                    Ok(FailureSettlementOutcome::Pending) => {
                        ctx.notify_later(ProcessFailedE3 { e3_id }, FAILURE_RETRY_DELAY);
                    }
                    Ok(FailureSettlementOutcome::Blocked) => {
                        let (delay, first) = actor.blocked_settlements.record(&e3_id);
                        if first {
                            info!(
                                e3_id = %e3_id,
                                retry_in_secs = delay.as_secs(),
                                "Failure settlement is blocked until the accusation window closes \
                                 and committee proposals resolve"
                            );
                        } else {
                            debug!(
                                e3_id = %e3_id,
                                retry_in_secs = delay.as_secs(),
                                "Failure settlement is still blocked"
                            );
                        }
                        ctx.notify_later(ProcessFailedE3 { e3_id }, delay);
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

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::{
        network::EthereumWallet, providers::ProviderBuilder, signers::local::PrivateKeySigner,
        sol_types::SolValue, transports::mock::Asserter,
    };
    use e3_ciphernode_builder::EventSystem;
    use e3_events::TakeEvents;

    #[actix::test]
    async fn replay_discards_noncanonical_plaintext_before_corrected_publication() -> Result<()> {
        use alloy::{
            primitives::B256,
            rpc::{
                client::RpcClient,
                json_rpc::{RequestPacket, Response, ResponsePacket, ResponsePayload},
            },
            sol_types::SolCall,
            transports::TransportErrorKind,
        };
        use e3_data::{InMemEventLog, InMemSequenceIndex};
        use e3_events::{
            CiphertextOutputPublished, CircuitName, EventBusFanout, EventStore, EventStoreRouter,
            Unsequenced,
        };
        use e3_fhe_params::BfvPreset;
        use e3_request::canonical_key::CanonicalPublicKey;
        use e3_utils::ArcBytes;
        use e3_zk_helpers::CiphernodesCommitteeSize;
        use std::sync::{Arc, Mutex};

        for authority_after_replay in [false, true] {
            let captured = Arc::new(Mutex::new(Vec::new()));
            let calls = captured.clone();
            // Capture the production writer's transaction calldata at gas estimation.
            let transport = tower::service_fn(
                move |packet: RequestPacket| -> alloy::transports::TransportFut<'static> {
                    let calls = calls.clone();
                    Box::pin(async move {
                        let RequestPacket::Single(request) = packet else {
                            panic!("unexpected RPC batch")
                        };
                        let result = match request.method() {
                            "eth_chainId" => serde_json::json!("0x1"),
                            "eth_getTransactionCount" => serde_json::json!("0x0"),
                            "eth_call" => {
                                let params: serde_json::Value =
                                    serde_json::from_str(request.params().unwrap().get()).unwrap();
                                let input = params[0]["input"]
                                    .as_str()
                                    .or_else(|| params[0]["data"].as_str())
                                    .unwrap();
                                let bytes = hex::decode(input.trim_start_matches("0x")).unwrap();
                                if bytes.starts_with(&IInterfold::getE3StageCall::SELECTOR) {
                                    serde_json::json!(Bytes::from(U256::from(4).abi_encode()))
                                } else {
                                    assert!(bytes.starts_with(&IInterfold::getE3Call::SELECTOR));
                                    let e3 = IInterfold::E3 {
                                        seed: U256::ZERO,
                                        committeeSize: 0,
                                        requestBlock: U256::ZERO,
                                        inputWindow: [U256::ZERO; 2],
                                        encryptionSchemeId: B256::ZERO,
                                        e3Program: Address::ZERO,
                                        paramSet: 0,
                                        customParams: Bytes::new(),
                                        decryptionVerifier: Address::ZERO,
                                        pkVerifier: Address::ZERO,
                                        committeePublicKey: B256::ZERO,
                                        ciphertextOutput: B256::ZERO,
                                        plaintextOutput: Bytes::new(),
                                        requester: Address::ZERO,
                                        ciphertextCommitment: B256::ZERO,
                                    };
                                    serde_json::json!(Bytes::from((e3,).abi_encode_params()))
                                }
                            }
                            "eth_estimateGas" => {
                                let params: serde_json::Value =
                                    serde_json::from_str(request.params().unwrap().get()).unwrap();
                                let input = params[0]["input"]
                                    .as_str()
                                    .or_else(|| params[0]["data"].as_str())
                                    .unwrap();
                                calls
                                    .lock()
                                    .unwrap()
                                    .push(hex::decode(input.trim_start_matches("0x")).unwrap());
                                return Err(TransportErrorKind::custom_str("submission captured"));
                            }
                            _ => {
                                return Err(TransportErrorKind::custom_str(
                                    "unexpected publication RPC",
                                ))
                            }
                        };
                        Ok(ResponsePacket::Single(Response {
                            id: request.id().clone(),
                            payload: ResponsePayload::Success(
                                serde_json::value::RawValue::from_string(result.to_string())
                                    .unwrap(),
                            ),
                        }))
                    })
                },
            );
            let provider = EthProvider::new(
                ProviderBuilder::new()
                    .disable_recommended_fillers()
                    .with_gas_estimation()
                    .wallet(EthereumWallet::from(PrivateKeySigner::random()))
                    .connect_client(RpcClient::new(transport, true)),
            )
            .await?;
            let system = EventSystem::new().with_fresh_bus();
            let bus = system.handle()?.enable("plaintext-replay");
            let keys = CanonicalPublicKeys::default();
            let id = E3id::new("42", 1);
            let contract = Address::repeat_byte(9);
            let key = CanonicalPublicKey {
                pk_commitment: [7; 32],
                committee: vec![Address::repeat_byte(1); 3],
                honest_committee: vec![Address::repeat_byte(1); 2],
                params_preset: BfvPreset::InsecureThreshold512,
                committee_size: CiphernodesCommitteeSize::Minimum,
                interfold_address: contract,
                sk_agg_commits: vec![],
                esm_agg_commits: vec![],
            };
            let ciphertext = vec![ArcBytes::from_bytes(&[3])];
            keys.insert(id.clone(), key.clone())?;
            keys.remember_ciphertexts(&id, &ciphertext)?;
            let domain = keys.decryption_domains(&id).unwrap()[0];
            let mut signals = vec![0; 7 * 32];
            signals[4 * 32..5 * 32].copy_from_slice(&U256::from(domain.hi).to_be_bytes::<32>());
            signals[5 * 32..6 * 32].copy_from_slice(&U256::from(domain.lo).to_be_bytes::<32>());
            let corrected = PlaintextAggregated {
                e3_id: id.clone(),
                decrypted_output: vec![ArcBytes::from_bytes(&[4])],
                decryption_aggregator_proofs: vec![Proof::new(
                    CircuitName::DecryptionAggregator,
                    ArcBytes::from_bytes(&[1]),
                    ArcBytes::from_bytes(&signals),
                )],
            };
            signals[5 * 32] ^= 1;
            let mut old = corrected.clone();
            old.decryption_aggregator_proofs[0].public_signals = ArcBytes::from_bytes(&signals);
            if authority_after_replay {
                keys.remove(&id);
            }
            let mut log = EventStore::new(InMemSequenceIndex::new(), InMemEventLog::new())?;
            let mut events = Vec::new();
            for (index, intent) in [old, corrected.clone()].into_iter().enumerate() {
                events.push(
                    log.store_event(InterfoldEvent::<Unsequenced>::new_with_timestamp(
                        intent.into(),
                        None,
                        index as u128 + 1,
                        None,
                        EventSource::Local,
                    ))?
                    .unwrap(),
                );
            }
            let eventstore = EventStoreRouter::new(HashMap::from([(1, log.start())]))
                .start()
                .recipient();
            let writer = InterfoldSolWriter::new_with_recovery(
                &bus,
                provider,
                contract,
                HashMap::new(),
                HashMap::new(),
                HashMap::new(),
                HashSet::new(),
                HashSet::new(),
                keys.clone(),
                eventstore,
            )?
            .start();
            bus.subscribe(EventType::All, writer.clone().recipient());
            for event in events {
                bus.event_bus().send(EventBusFanout(event)).await??;
            }
            // A mailbox barrier completes event routing before effects resume.
            writer.send(E3RequestComplete { e3_id: id.clone() }).await?;
            assert!(
                captured.lock().unwrap().is_empty(),
                "replay released a transaction"
            );
            writer.send(EffectsEnabled::new()).await?;
            if authority_after_replay {
                assert!(
                    captured.lock().unwrap().is_empty(),
                    "missing authority released a transaction"
                );
                keys.insert(id.clone(), key)?;
                keys.remember_ciphertexts(&id, &ciphertext)?;
                writer
                    .send(
                        InterfoldEvent::<Unsequenced>::new_with_timestamp(
                            CiphertextOutputPublished {
                                e3_id: id.clone(),
                                ciphertext_output: ciphertext,
                                ciphertext_commitment: [0; 32],
                            }
                            .into(),
                            None,
                            3,
                            Some(3),
                            EventSource::Evm,
                        )
                        .into_sequenced(3),
                    )
                    .await?;
            }
            tokio::time::timeout(Duration::from_secs(5), async {
                while captured.lock().unwrap().is_empty() {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await?;
            let submissions = captured.lock().unwrap();
            assert_eq!(submissions.len(), 1);
            let call = IInterfold::publishPlaintextOutputCall::abi_decode(&submissions[0])?;
            assert_eq!(call.e3Id, U256::from(42));
            assert_eq!(call.plaintextOutput.as_ref(), &[4]);
            assert_eq!(
                call.proof,
                encode_zk_proof(&corrected.decryption_aggregator_proofs[0])?,
                "the writer released the retained noncanonical proof"
            );
        }
        Ok(())
    }

    #[actix::test]
    async fn blocked_settlement_sends_no_transaction_and_no_error() -> Result<()> {
        let system = EventSystem::new().with_fresh_bus();
        let bus = system.handle()?.enable("blocked-settlement");
        let errors = bus.errors();

        let asserter = Asserter::new();
        asserter.push_success(&"0x1");
        let provider = EthProvider::new(
            ProviderBuilder::new()
                .wallet(EthereumWallet::from(PrivateKeySigner::random()))
                .connect_mocked_client(asserter.clone()),
        )
        .await?;
        // `getE3Stage` reports Failed, then the `processE3Failure` simulation reverts with
        // `SettlementBlocked()`. The mock has no response for a nonce read or a transaction.
        asserter.push_success(&Bytes::from(U256::from(6).abi_encode()));
        asserter.push_failure(serde_json::from_str(
            r#"{"code":3,"message":"execution reverted","data":"0xf51125bb"}"#,
        )?);

        let writer = InterfoldSolWriter::new_with_recovery(
            &bus,
            provider,
            Address::ZERO,
            HashMap::new(),
            HashMap::new(),
            HashMap::new(),
            HashSet::from([E3id::new("7", 1)]),
            HashSet::new(),
            CanonicalPublicKeys::default(),
            system.eventstore_reader()?.seq(),
        )?
        .start();
        writer.send(EffectsEnabled::new()).await?;

        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let consumed = asserter.read_q().is_empty();
                if consumed {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await?;
        let received = errors.send(TakeEvents::new(1)).await?;
        assert!(
            received.timed_out,
            "a blocked settlement must not emit InterfoldError: {:?}",
            received.events
        );
        Ok(())
    }
}
