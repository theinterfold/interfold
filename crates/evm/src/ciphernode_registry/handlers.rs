// SPDX-License-Identifier: LGPL-3.0-only

//! Actix routing and lifecycle handlers for the registry writer.

use super::effects::*;
use super::*;
use e3_events::EventSource;
use std::collections::HashMap;

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

/// Forget the registry of a completed request. A publication that is still pending keeps it: its
/// terminal outcome removes the registry.
fn mark_request_complete(
    request_registries: &mut HashMap<E3id, Address>,
    e3_id: &E3id,
    publication_pending: bool,
) {
    if !publication_pending {
        request_registries.remove(e3_id);
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

impl<P: Provider + WalletProvider + Clone + 'static> CiphernodeRegistrySolWriter<P> {
    /// Start this node's own key publication. The router admits only local results, and a local
    /// result exists only when this node computed the key as the active aggregator. A failover that
    /// demotes the node later does not stop the publication: the chain accepts the first valid one.
    fn try_start_public_key(&mut self, e3_id: &E3id, ctx: &mut actix::Context<Self>) {
        if !self.request_registries.contains_key(e3_id) {
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
            InterfoldEventData::CommitteePublished(data) => {
                if self.provider.chain_id() == data.e3_id.chain_id() {
                    self.notify_sync(ctx, data);
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
            &mut self.request_registries,
            &msg.e3_id,
            publication_pending,
        );
        self.settled_keys.insert(msg.e3_id);
    }
}

/// Every node assembles the key from the chain's chunks and then publishes `CommitteePublished`.
/// With the whole key on chain, this node's own publication adds nothing: the writer drops it,
/// also when a restart replays it or the aggregator sends its saved publication again.
impl<P: Provider + WalletProvider + Clone + 'static> Handler<CommitteePublished>
    for CiphernodeRegistrySolWriter<P>
{
    type Result = ();

    fn handle(&mut self, msg: CommitteePublished, _: &mut Self::Context) -> Self::Result {
        self.publication.finish(&msg.e3_id, true);
        self.settled_keys.insert(msg.e3_id);
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
        mark_request_complete, settle_publication_for_completed_request, update_request_registry,
        CiphernodeRegistrySolWriter, EthProvider, ReplaySubmissionGate,
    };
    use actix::Actor;
    use alloy::{
        network::EthereumWallet, primitives::Address, providers::ProviderBuilder,
        signers::local::PrivateKeySigner, transports::mock::Asserter,
    };
    use e3_events::prelude::*;
    use e3_events::{
        DkgFoldAttestationContext, DkgFoldAttestationContextEstablished, E3id, EffectsEnabled,
        EventSource, InterfoldEvent, OrderedSet, PublicKeyAggregated, TakeEvents, Unsequenced,
        DKG_FOLD_ATTESTATION_CONTEXT_SCHEMA_VERSION,
    };
    use e3_test_helpers::get_common_setup;
    use e3_utils::ArcBytes;
    use std::collections::HashMap;

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
    fn completion_keeps_the_registry_of_a_pending_publication() {
        let e3_id = E3id::new("9", 1);
        let registry = Address::repeat_byte(0x55);
        let mut registries = HashMap::from([(e3_id.clone(), registry)]);

        mark_request_complete(&mut registries, &e3_id, true);
        assert_eq!(registries.get(&e3_id), Some(&registry));

        mark_request_complete(&mut registries, &e3_id, false);
        assert!(!registries.contains_key(&e3_id));
    }

    fn local_event(data: impl Into<e3_events::InterfoldEventData>, seq: u64) -> InterfoldEvent {
        InterfoldEvent::<Unsequenced>::new_with_timestamp(
            data.into(),
            None,
            seq as u128,
            None,
            EventSource::Local,
        )
        .into_sequenced(seq)
    }

    /// Number of key results that the writer keeps for publication.
    #[derive(actix::Message)]
    #[rtype(result = "usize")]
    struct RetainedPublications;

    impl<P: alloy::providers::Provider + alloy::providers::WalletProvider + Clone + 'static>
        actix::Handler<RetainedPublications> for CiphernodeRegistrySolWriter<P>
    {
        type Result = usize;

        fn handle(&mut self, _: RetainedPublications, _: &mut Self::Context) -> usize {
            self.publication.pending_keys().len()
        }
    }

    async fn mocked_writer(
        bus: &e3_events::BusHandle,
        e3_id: &E3id,
    ) -> anyhow::Result<
        actix::Addr<
            CiphernodeRegistrySolWriter<
                impl alloy::providers::Provider + alloy::providers::WalletProvider + Clone + 'static,
            >,
        >,
    > {
        let asserter = Asserter::new();
        asserter.push_success(&"0x1");
        let provider = EthProvider::new(
            ProviderBuilder::new()
                .wallet(EthereumWallet::from(PrivateKeySigner::random()))
                .connect_mocked_client(asserter),
        )
        .await?;
        Ok(CiphernodeRegistrySolWriter::new_with_recovery(
            bus,
            provider,
            Address::repeat_byte(0x44),
            HashMap::from([(e3_id.clone(), Address::repeat_byte(0x33))]),
            HashMap::new(),
        )?
        .start())
    }

    #[actix::test]
    async fn a_key_result_after_its_request_completed_is_not_kept() -> anyhow::Result<()> {
        let (bus, _rng, _seed, _params, _crp, _errors, _history) = get_common_setup(None)?;
        let e3_id = E3id::new("13", 1);
        let writer = mocked_writer(&bus, &e3_id).await?;
        writer.send(local_event(EffectsEnabled::new(), 1)).await?;

        // The request completes; a demoted aggregator finishes its key afterwards.
        writer
            .send(local_event(
                e3_events::E3RequestComplete {
                    e3_id: e3_id.clone(),
                },
                2,
            ))
            .await?;
        writer
            .send(local_event(publication_intent(&e3_id), 3))
            .await?;

        assert_eq!(writer.send(RetainedPublications).await?, 0);
        Ok(())
    }

    /// A restart replays this node's key result and then the key that the node assembled from the
    /// chain's chunks. The writer keeps no publication, so it sends no chunk again, also when the
    /// aggregator sends its saved publication again once effects run.
    #[actix::test]
    async fn a_key_on_chain_ends_the_publication() -> anyhow::Result<()> {
        let (bus, _rng, _seed, _params, _crp, _errors, _history) = get_common_setup(None)?;
        let e3_id = E3id::new("14", 1);
        let writer = mocked_writer(&bus, &e3_id).await?;

        writer
            .send(local_event(publication_intent(&e3_id), 1))
            .await?;
        assert_eq!(writer.send(RetainedPublications).await?, 1);
        writer
            .send(local_event(
                e3_events::CommitteePublished {
                    e3_id: e3_id.clone(),
                    nodes: vec![],
                    public_key: ArcBytes::from_bytes(&[1, 2, 3]),
                    proof: ArcBytes::from_bytes(&[]),
                },
                2,
            ))
            .await?;
        assert_eq!(writer.send(RetainedPublications).await?, 0);

        writer.send(local_event(EffectsEnabled::new(), 3)).await?;
        writer
            .send(local_event(publication_intent(&e3_id), 4))
            .await?;
        assert_eq!(writer.send(RetainedPublications).await?, 0);
        Ok(())
    }

    #[actix::test]
    async fn submits_its_own_key_without_being_the_active_aggregator() -> anyhow::Result<()> {
        let (bus, _rng, _seed, _params, _crp, errors, _history) = get_common_setup(None)?;
        let asserter = Asserter::new();
        asserter.push_success(&"0x1");
        let provider = EthProvider::new(
            ProviderBuilder::new()
                .wallet(EthereumWallet::from(PrivateKeySigner::random()))
                .connect_mocked_client(asserter),
        )
        .await?;
        let e3_id = E3id::new("12", 1);
        let writer = CiphernodeRegistrySolWriter::new_with_recovery(
            &bus,
            provider,
            Address::repeat_byte(0x44),
            HashMap::from([(e3_id.clone(), Address::repeat_byte(0x33))]),
            HashMap::new(),
        )?
        .start();

        // No AggregatorChanged arrives: a failover demoted this node after it computed the key.
        writer.send(local_event(EffectsEnabled::new(), 1)).await?;
        writer
            .send(local_event(publication_intent(&e3_id), 2))
            .await?;

        // The submission starts with the chain preflight, which the empty mock transport fails.
        let failure = errors.send(TakeEvents::<InterfoldEvent>::new(1)).await?;
        assert!(
            !failure.timed_out,
            "the writer did not submit this node's own key"
        );
        Ok(())
    }
}

impl<P: Provider + WalletProvider + Clone + 'static> Handler<PublicKeyAggregated>
    for CiphernodeRegistrySolWriter<P>
{
    type Result = ();

    fn handle(&mut self, msg: PublicKeyAggregated, ctx: &mut Self::Context) -> Self::Result {
        let e3_id = msg.e3_id.clone();
        if self.settled_keys.contains(&e3_id) {
            info!(e3_id = %e3_id, "Ignoring a public-key result: the key is on chain or the request completed");
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
        if !self.publication.contains(&msg.e3_id) {
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
