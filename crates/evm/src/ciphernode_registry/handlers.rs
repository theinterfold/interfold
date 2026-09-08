// SPDX-License-Identifier: LGPL-3.0-only

//! Actix routing and lifecycle handlers for the registry writer.

use super::effects::*;
use super::*;
use e3_events::EventSource;
use std::collections::{HashMap, HashSet};

const PUBLICATION_RETRY_DELAY: std::time::Duration = std::time::Duration::from_secs(30);

fn update_request_registry(
    registries: &mut HashMap<E3id, Address>,
    event: &DkgFoldAttestationContextEstablished,
) -> bool {
    if event.schema_version != DKG_FOLD_ATTESTATION_CONTEXT_SCHEMA_VERSION {
        registries.remove(&event.e3_id);
        return false;
    }

    registries.insert(event.e3_id.clone(), event.context.registry);
    true
}

fn mark_request_complete(
    active_aggregators: &mut HashMap<E3id, bool>,
    completed_requests: &mut HashSet<E3id>,
    request_registries: &mut HashMap<E3id, Address>,
    e3_id: E3id,
    publication_pending: bool,
) {
    if publication_pending {
        completed_requests.insert(e3_id);
    } else {
        active_aggregators.remove(&e3_id);
        request_registries.remove(&e3_id);
    }
}

/// Settle the publication gate for a completed request and report whether an
/// intent survives.
///
/// A completed request that arrives before effects are enabled comes from event
/// replay. Its key candidate reached the chain in an earlier run, so the
/// replayed intent must go; otherwise the writer publishes the same candidate
/// again after every restart. A completed request that arrives while effects
/// run can still overtake an in-flight publication, so that intent stays.
fn settle_publication_for_completed_request(
    publication: &mut ReplaySubmissionGate<E3id, PublicKeyAggregated>,
    e3_id: &E3id,
    effects_enabled: bool,
) -> bool {
    if !effects_enabled {
        publication.finish(e3_id, true);
    }

    publication.contains(e3_id)
}

fn finish_completed_publication(
    active_aggregators: &mut HashMap<E3id, bool>,
    completed_requests: &mut HashSet<E3id>,
    e3_id: &E3id,
) {
    if completed_requests.remove(e3_id) {
        active_aggregators.remove(e3_id);
    }
}

impl<P: Provider + WalletProvider + Clone + 'static> CiphernodeRegistrySolWriter<P> {
    fn try_start_public_key(&mut self, e3_id: &E3id, ctx: &mut actix::Context<Self>) {
        if !self.is_active_aggregator_for(e3_id) || !self.request_registries.contains_key(e3_id) {
            return;
        }

        if let Some(intent) = self.publication.start(e3_id) {
            ctx.notify(SubmitPublicKey(intent));
        }
    }

    fn try_start_pending_public_keys(&mut self, ctx: &mut actix::Context<Self>) {
        for e3_id in self.publication.pending_keys() {
            self.try_start_public_key(&e3_id, ctx);
        }
    }

    fn try_start_ticket(&mut self, e3_id: &E3id, ctx: &mut actix::Context<Self>) {
        if let Some(intent) = self.ticket_submissions.start(e3_id) {
            ctx.notify(SubmitTicket(intent));
        }
    }

    fn try_start_pending_tickets(&mut self, ctx: &mut actix::Context<Self>) {
        for e3_id in self.ticket_submissions.pending_keys() {
            self.try_start_ticket(&e3_id, ctx);
        }
    }

    fn try_start_finalization(&mut self, e3_id: &E3id, ctx: &mut actix::Context<Self>) {
        if let Some(intent) = self.committee_finalizations.start(e3_id) {
            ctx.notify(SubmitCommitteeFinalization(intent));
        }
    }

    fn try_start_pending_finalizations(&mut self, ctx: &mut actix::Context<Self>) {
        for e3_id in self.committee_finalizations.pending_keys() {
            self.try_start_finalization(&e3_id, ctx);
        }
    }
}

impl<P: Provider + WalletProvider + Clone + 'static> Actor for CiphernodeRegistrySolWriter<P> {
    type Context = actix::Context<Self>;

    fn started(&mut self, ctx: &mut Self::Context) {
        ctx.set_mailbox_capacity(MAILBOX_LIMIT)
    }
}

impl<P: Provider + WalletProvider + Clone + 'static> Handler<InterfoldEvent>
    for CiphernodeRegistrySolWriter<P>
{
    type Result = ();

    fn handle(&mut self, msg: InterfoldEvent, ctx: &mut Self::Context) -> Self::Result {
        let source = msg.source();
        match msg.into_data() {
            InterfoldEventData::EffectsEnabled(data) => self.notify_sync(ctx, data),
            InterfoldEventData::AggregatorChanged(data) => self.notify_sync(ctx, data),
            InterfoldEventData::DkgFoldAttestationContextEstablished(data) => {
                if self.provider.chain_id() == data.e3_id.chain_id() {
                    ctx.notify(data);
                }
            }
            InterfoldEventData::PublicKeyAggregated(data) => {
                if source == EventSource::Local && self.provider.chain_id() == data.e3_id.chain_id()
                {
                    ctx.notify(data);
                }
            }
            InterfoldEventData::CommitteeFinalizeRequested(data) => {
                if self.provider.chain_id() == data.e3_id.chain_id() {
                    ctx.notify(data);
                }
            }
            InterfoldEventData::TicketGenerated(data) => {
                // Submit ticket if chain matches
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
    for CiphernodeRegistrySolWriter<P>
{
    type Result = ();

    fn handle(&mut self, _: EffectsEnabled, ctx: &mut Self::Context) -> Self::Result {
        self.effects_enabled = true;
        self.publication.enable_effects();
        self.ticket_submissions.enable_effects();
        self.committee_finalizations.enable_effects();
        self.try_start_pending_public_keys(ctx);
        self.try_start_pending_tickets(ctx);
        self.try_start_pending_finalizations(ctx);
    }
}

impl<P: Provider + WalletProvider + Clone + 'static> Handler<AggregatorChanged>
    for CiphernodeRegistrySolWriter<P>
{
    type Result = ();

    fn handle(&mut self, msg: AggregatorChanged, ctx: &mut Self::Context) -> Self::Result {
        let e3_id = msg.e3_id;
        self.active_aggregators
            .insert(e3_id.clone(), msg.is_aggregator);
        if msg.is_aggregator {
            self.try_start_public_key(&e3_id, ctx);
        }
    }
}

impl<P: Provider + WalletProvider + Clone + 'static> Handler<DkgFoldAttestationContextEstablished>
    for CiphernodeRegistrySolWriter<P>
{
    type Result = ();

    fn handle(
        &mut self,
        msg: DkgFoldAttestationContextEstablished,
        ctx: &mut Self::Context,
    ) -> Self::Result {
        if !update_request_registry(&mut self.request_registries, &msg) {
            error!(
                e3_id = %msg.e3_id,
                schema_version = msg.schema_version,
                expected_schema_version = DKG_FOLD_ATTESTATION_CONTEXT_SCHEMA_VERSION,
                "Rejected DKG attestation context with an unsupported schema version"
            );
            return;
        }
        self.try_start_public_key(&msg.e3_id, ctx);
    }
}

impl<P: Provider + WalletProvider + Clone + 'static> Handler<E3RequestComplete>
    for CiphernodeRegistrySolWriter<P>
{
    type Result = ();

    fn handle(&mut self, msg: E3RequestComplete, _: &mut Self::Context) -> Self::Result {
        let publication_pending = settle_publication_for_completed_request(
            &mut self.publication,
            &msg.e3_id,
            self.effects_enabled,
        );
        self.ticket_submissions.finish(&msg.e3_id, true);
        self.committee_finalizations.finish(&msg.e3_id, true);
        mark_request_complete(
            &mut self.active_aggregators,
            &mut self.completed_requests,
            &mut self.request_registries,
            msg.e3_id,
            publication_pending,
        );
    }
}

impl<P: Provider + WalletProvider + Clone + 'static> Handler<TicketGenerated>
    for CiphernodeRegistrySolWriter<P>
{
    type Result = ();

    fn handle(&mut self, msg: TicketGenerated, ctx: &mut Self::Context) -> Self::Result {
        let e3_id = msg.e3_id.clone();
        self.ticket_submissions.record(e3_id.clone(), msg);
        self.try_start_ticket(&e3_id, ctx);
    }
}

#[derive(Message)]
#[rtype(result = "()")]
struct SubmitTicket(TicketGenerated);

impl<P: Provider + WalletProvider + Clone + 'static> Handler<SubmitTicket>
    for CiphernodeRegistrySolWriter<P>
{
    type Result = ResponseActFuture<Self, ()>;

    fn handle(&mut self, command: SubmitTicket, _: &mut Self::Context) -> Self::Result {
        match command.0.ticket_id {
            TicketId::Score(ticket_id) => {
                let e3_id = command.0.e3_id;
                info!(
                    "Score sortition ticket generated for E3 {:?}, submitting to contract",
                    e3_id
                );

                let contract_address = self.contract_address;
                let provider = self.provider.clone();
                let bus = self.bus.clone();

                Box::pin(
                    async move {
                    info!("Submitting ticket {} for E3 {:?}", ticket_id, e3_id);

                    let terminal = match submit_ticket_to_registry(
                        provider,
                        contract_address,
                        e3_id.clone(),
                        ticket_id,
                    )
                    .await
                    {
                        Ok(TxOutcome::Mined(receipt)) => {
                            info!(tx=%receipt.transaction_hash, "Ticket submitted to registry");
                            true
                        }
                        Ok(TxOutcome::AlreadySettled) => {
                            info!(e3_id = %e3_id, "Ticket already recorded on chain; skipping submission");
                            true
                        }
                        Err(err) => {
                            let terminal = ticket_submission_error_is_terminal(&err);
                            error!("Failed to submit ticket: {}", format_evm_error(&err));
                            bus.err(EType::Evm, err);
                            terminal
                        }
                    };
                    (e3_id, terminal)
                }
                    .into_actor(self)
                    .map(|(e3_id, terminal), actor, ctx| {
                        actor.ticket_submissions.finish(&e3_id, terminal);
                        if !terminal {
                            ctx.run_later(PUBLICATION_RETRY_DELAY, move |actor, ctx| {
                                actor.try_start_ticket(&e3_id, ctx);
                            });
                        }
                    }),
                )
            }
        }
    }
}

impl<P: Provider + WalletProvider + Clone + 'static> Handler<CommitteeFinalizeRequested>
    for CiphernodeRegistrySolWriter<P>
{
    type Result = ();

    fn handle(&mut self, msg: CommitteeFinalizeRequested, ctx: &mut Self::Context) -> Self::Result {
        let e3_id = msg.e3_id.clone();
        self.committee_finalizations.record(e3_id.clone(), msg);
        self.try_start_finalization(&e3_id, ctx);
    }
}

#[derive(Message)]
#[rtype(result = "()")]
struct SubmitCommitteeFinalization(CommitteeFinalizeRequested);

impl<P: Provider + WalletProvider + Clone + 'static> Handler<SubmitCommitteeFinalization>
    for CiphernodeRegistrySolWriter<P>
{
    type Result = ResponseActFuture<Self, ()>;

    fn handle(
        &mut self,
        command: SubmitCommitteeFinalization,
        _: &mut Self::Context,
    ) -> Self::Result {
        let e3_id = command.0.e3_id;
        let contract_address = self.contract_address;
        let provider = self.provider.clone();
        let bus = self.bus.clone();

        Box::pin(
            async move {
            info!("Finalizing committee for E3 {:?}", e3_id);

            let terminal = match finalize_committee_on_registry(
                provider,
                contract_address,
                e3_id.clone(),
            )
            .await
            {
                Ok(TxOutcome::Mined(receipt)) => {
                    info!(tx=%receipt.transaction_hash, "Committee finalized on registry");
                    true
                }
                Ok(TxOutcome::AlreadySettled) => {
                    info!(e3_id = %e3_id, "Committee finalization already reached a terminal chain state");
                    true
                }
                Err(err) => {
                    error!("Failed to finalize committee: {}", format_evm_error(&err));
                    bus.err(EType::Evm, err);
                    false
                }
            };
            (e3_id, terminal)
        }
            .into_actor(self)
            .map(|(e3_id, terminal), actor, ctx| {
                actor.committee_finalizations.finish(&e3_id, terminal);
                if !terminal {
                    ctx.run_later(PUBLICATION_RETRY_DELAY, move |actor, ctx| {
                        actor.try_start_finalization(&e3_id, ctx);
                    });
                }
            }),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::{
        finish_completed_publication, mark_request_complete,
        settle_publication_for_completed_request, update_request_registry, ReplaySubmissionGate,
    };
    use alloy::primitives::Address;
    use e3_events::{
        DkgFoldAttestationContext, DkgFoldAttestationContextEstablished, E3id, OrderedSet,
        PublicKeyAggregated, DKG_FOLD_ATTESTATION_CONTEXT_SCHEMA_VERSION,
    };
    use e3_utils::ArcBytes;
    use std::collections::{HashMap, HashSet};

    #[test]
    fn valid_context_records_the_request_time_registry() {
        let e3_id = E3id::new("7", 1);
        let registry = Address::repeat_byte(0x11);
        let event = DkgFoldAttestationContextEstablished {
            schema_version: DKG_FOLD_ATTESTATION_CONTEXT_SCHEMA_VERSION,
            e3_id: e3_id.clone(),
            context: DkgFoldAttestationContext {
                registry,
                verifying_contract: Address::repeat_byte(0x22),
            },
        };
        let mut registries = HashMap::new();

        assert!(update_request_registry(&mut registries, &event));
        assert_eq!(registries.get(&e3_id), Some(&registry));
    }

    #[test]
    fn unsupported_context_removes_the_cached_registry() {
        let e3_id = E3id::new("8", 1);
        let registry = Address::repeat_byte(0x33);
        let event = DkgFoldAttestationContextEstablished {
            schema_version: DKG_FOLD_ATTESTATION_CONTEXT_SCHEMA_VERSION + 1,
            e3_id: e3_id.clone(),
            context: DkgFoldAttestationContext {
                registry,
                verifying_contract: Address::repeat_byte(0x44),
            },
        };
        let mut registries = HashMap::from([(e3_id.clone(), registry)]);

        assert!(!update_request_registry(&mut registries, &event));
        assert!(!registries.contains_key(&e3_id));
    }

    fn publication_intent(e3_id: &E3id) -> PublicKeyAggregated {
        PublicKeyAggregated {
            pubkey: ArcBytes::from_bytes(&[1, 2, 3]),
            e3_id: e3_id.clone(),
            nodes: OrderedSet::from(vec![]),
            committee_addresses: vec![],
            honest_committee_addresses: vec![],
            pk_commitment: [7u8; 32],
            dkg_aggregator_proof: None,
            dkg_attestation_bundle: None,
        }
    }

    #[test]
    fn replayed_completion_drops_the_publication_intent() {
        let e3_id = E3id::new("10", 1);
        let mut publication = ReplaySubmissionGate::new();
        publication.record(e3_id.clone(), publication_intent(&e3_id));

        // Effects are disabled while the commit log replays.
        let pending = settle_publication_for_completed_request(&mut publication, &e3_id, false);

        assert!(!pending);
        assert!(!publication.contains(&e3_id));

        publication.enable_effects();
        assert!(publication.start(&e3_id).is_none());
    }

    #[test]
    fn live_completion_retains_the_publication_intent() {
        let e3_id = E3id::new("11", 1);
        let mut publication = ReplaySubmissionGate::new();
        publication.record(e3_id.clone(), publication_intent(&e3_id));
        publication.enable_effects();

        let pending = settle_publication_for_completed_request(&mut publication, &e3_id, true);

        assert!(pending);
        assert!(publication.start(&e3_id).is_some());
    }

    #[test]
    fn completion_retains_retryable_publication_state_until_terminal_outcome() {
        let e3_id = E3id::new("9", 1);
        let registry = Address::repeat_byte(0x55);
        let mut active = HashMap::from([(e3_id.clone(), true)]);
        let mut completed = HashSet::new();
        let mut registries = HashMap::from([(e3_id.clone(), registry)]);

        mark_request_complete(
            &mut active,
            &mut completed,
            &mut registries,
            e3_id.clone(),
            true,
        );

        assert_eq!(active.get(&e3_id), Some(&true));
        assert_eq!(registries.get(&e3_id), Some(&registry));
        assert!(completed.contains(&e3_id));

        finish_completed_publication(&mut active, &mut completed, &e3_id);
        registries.remove(&e3_id);

        assert!(!active.contains_key(&e3_id));
        assert!(!completed.contains(&e3_id));
        assert!(!registries.contains_key(&e3_id));
    }
}

impl<P: Provider + WalletProvider + Clone + 'static> Handler<PublicKeyAggregated>
    for CiphernodeRegistrySolWriter<P>
{
    type Result = ();

    fn handle(&mut self, msg: PublicKeyAggregated, ctx: &mut Self::Context) -> Self::Result {
        let e3_id = msg.e3_id.clone();
        if self.effects_enabled && !self.is_active_aggregator_for(&e3_id) {
            info!(e3_id = %e3_id, "Ignoring public-key result while this node is not the active aggregator");
            return;
        }
        self.publication.record(e3_id.clone(), msg);
        self.try_start_public_key(&e3_id, ctx);
    }
}

#[derive(Message)]
#[rtype(result = "()")]
struct SubmitPublicKey(PublicKeyAggregated);

impl<P: Provider + WalletProvider + Clone + 'static> Handler<SubmitPublicKey>
    for CiphernodeRegistrySolWriter<P>
{
    type Result = ResponseActFuture<Self, ()>;

    fn handle(&mut self, command: SubmitPublicKey, _ctx: &mut Self::Context) -> Self::Result {
        let msg = command.0;
        if !self.is_active_aggregator_for(&msg.e3_id) || !self.publication.contains(&msg.e3_id) {
            self.publication.finish(&msg.e3_id, false);
            return Box::pin(async {}.into_actor(self));
        }
        let Some(contract_address) = self.request_registries.get(&msg.e3_id).copied() else {
            self.publication.finish(&msg.e3_id, false);
            return Box::pin(async {}.into_actor(self));
        };

        let e3_id = msg.e3_id.clone();
        let pubkey = msg.pubkey.clone();
        let pk_commitment = msg.pk_commitment;
        let dkg_aggregator_proof = msg.dkg_aggregator_proof.clone();
        let dkg_attestation_bundle = msg.dkg_attestation_bundle.clone();
        let provider = self.provider.clone();
        let bus = self.bus.clone();

        Box::pin(
            async move {
                let should_publish = match should_publish_committee(
                    provider.clone(),
                    contract_address,
                    e3_id.clone(),
                    pk_commitment,
                )
                .await
                {
                    Ok(false) => {
                        info!(e3_id = %e3_id, "Committee proof already published; publishing the key candidate");
                        false
                    }
                    Err(err) => {
                        let terminal = committee_publication_error_is_terminal(&err);
                        error!(
                            "Failed to preflight publishCommittee: {}",
                            format_evm_error(&err)
                        );
                        if terminal {
                            error!(e3_id = %e3_id, "Committee publication failed permanently; stopping retries");
                        }
                        bus.err(EType::Evm, err);
                        return (e3_id, terminal);
                    }
                    Ok(true) => true,
                };

                let result: Result<()> = async {
                    if should_publish {
                        let outcome = publish_committee_to_registry(
                            provider.clone(),
                            contract_address,
                            e3_id.clone(),
                            pk_commitment,
                            dkg_aggregator_proof.as_ref(),
                            dkg_attestation_bundle.as_ref().map(|b| b.as_ref()),
                        )
                        .await?;
                        match outcome.receipt() {
                            Some(receipt) => {
                                info!(tx=%receipt.transaction_hash, "Committee proof published to registry")
                            }
                            None => {
                                info!(e3_id = %e3_id, "Committee proof published by another aggregator; publishing the key candidate")
                            }
                        }
                    }

                    let receipt = publish_committee_public_key_to_registry(
                        provider,
                        contract_address,
                        e3_id.clone(),
                        pubkey,
                    )
                    .await?;
                    info!(tx=%receipt.transaction_hash, "Committee public-key candidate published to registry");
                    Ok(())
                }
                .await;

                match result {
                    Ok(()) => (e3_id, true),
                    Err(err) => {
                        let terminal = committee_publication_error_is_terminal(&err);
                        error!(
                            "Failed to publish committee data: {}",
                            format_evm_error(&err)
                        );
                        if terminal {
                            error!(e3_id = %e3_id, "Committee publication failed permanently; stopping retries");
                        }
                        bus.err(EType::Evm, err);
                        (e3_id, terminal)
                    }
                }
            }
            .into_actor(self)
            .map(|(e3_id, terminal), actor, ctx| {
                actor.publication.finish(&e3_id, terminal);
                if terminal {
                    actor.request_registries.remove(&e3_id);
                    finish_completed_publication(
                        &mut actor.active_aggregators,
                        &mut actor.completed_requests,
                        &e3_id,
                    );
                } else {
                    ctx.run_later(PUBLICATION_RETRY_DELAY, move |actor, ctx| {
                        actor.try_start_public_key(&e3_id, ctx);
                    });
                }
            }),
        )
    }
}

impl<P: Provider + WalletProvider + Clone + 'static> Handler<Shutdown>
    for CiphernodeRegistrySolWriter<P>
{
    type Result = ();

    fn handle(&mut self, _: Shutdown, ctx: &mut Self::Context) -> Self::Result {
        ctx.stop();
    }
}
