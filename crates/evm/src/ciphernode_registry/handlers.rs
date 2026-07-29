// SPDX-License-Identifier: LGPL-3.0-only

//! Actix routing and lifecycle handlers for the registry writer.

use super::effects::*;
use super::*;

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
        match msg.into_data() {
            InterfoldEventData::EffectsEnabled(data) => self.notify_sync(ctx, data),
            InterfoldEventData::AggregatorChanged(data) => self.notify_sync(ctx, data),
            InterfoldEventData::PublicKeyAggregated(data) => {
                // Only publish if the src and destination chains match
                if self.provider.chain_id() == data.e3_id.chain_id() {
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
            InterfoldEventData::EffectRetry(retry) => match retry.into_effect() {
                InterfoldEventData::PublicKeyAggregated(data)
                    if self.provider.chain_id() == data.e3_id.chain_id() =>
                {
                    ctx.notify(data);
                }
                InterfoldEventData::CommitteeFinalizeRequested(data)
                    if self.provider.chain_id() == data.e3_id.chain_id() =>
                {
                    ctx.notify(data);
                }
                InterfoldEventData::TicketGenerated(data)
                    if self.provider.chain_id() == data.e3_id.chain_id() =>
                {
                    ctx.notify(data);
                }
                _ => {}
            },
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

    fn handle(&mut self, _: EffectsEnabled, _: &mut Self::Context) -> Self::Result {
        self.effects_enabled = true;
    }
}

impl<P: Provider + WalletProvider + Clone + 'static> Handler<AggregatorChanged>
    for CiphernodeRegistrySolWriter<P>
{
    type Result = ();

    fn handle(&mut self, msg: AggregatorChanged, _: &mut Self::Context) -> Self::Result {
        self.active_aggregators.insert(msg.e3_id, msg.is_aggregator);
    }
}

impl<P: Provider + WalletProvider + Clone + 'static> Handler<E3RequestComplete>
    for CiphernodeRegistrySolWriter<P>
{
    type Result = ();

    fn handle(&mut self, msg: E3RequestComplete, _: &mut Self::Context) -> Self::Result {
        self.active_aggregators.remove(&msg.e3_id);
        self.submitting.remove(&msg.e3_id);
    }
}

impl<P: Provider + WalletProvider + Clone + 'static> Handler<TicketGenerated>
    for CiphernodeRegistrySolWriter<P>
{
    type Result = ResponseFuture<()>;

    fn handle(&mut self, msg: TicketGenerated, _: &mut Self::Context) -> Self::Result {
        if !self.effects_enabled {
            return Box::pin(async {});
        }

        match msg.ticket_id {
            TicketId::Score(ticket_id) => {
                info!(
                    "Score sortition ticket generated for E3 {:?}, submitting to contract",
                    msg.e3_id
                );

                let e3_id = msg.e3_id.clone();
                let contract_address = self.contract_address;
                let provider = self.provider.clone();
                let bus = self.bus.clone();

                Box::pin(async move {
                    info!("Submitting ticket {} for E3 {:?}", ticket_id, e3_id);

                    match should_submit_ticket(
                        provider.clone(),
                        contract_address,
                        e3_id.clone(),
                        ticket_id,
                    )
                    .await
                    {
                        Ok(false) => {
                            info!(e3_id = %e3_id, "Skipping submitTicket; on-chain state already makes the intent terminal");
                            return;
                        }
                        Err(err) => {
                            error!(
                                "Failed to preflight submitTicket: {}",
                                format_evm_error(&err)
                            );
                            bus.err(EType::Evm, err);
                            return;
                        }
                        Ok(true) => {}
                    }

                    let result =
                        submit_ticket_to_registry(provider, contract_address, e3_id, ticket_id)
                            .await;
                    match result {
                        Ok(receipt) => {
                            info!(tx=%receipt.transaction_hash, "Ticket submitted to registry");
                        }
                        Err(err) => {
                            error!("Failed to submit ticket: {}", format_evm_error(&err));
                            bus.err(EType::Evm, err);
                        }
                    }
                })
            }
        }
    }
}

impl<P: Provider + WalletProvider + Clone + 'static> Handler<CommitteeFinalizeRequested>
    for CiphernodeRegistrySolWriter<P>
{
    type Result = ResponseFuture<()>;

    fn handle(&mut self, msg: CommitteeFinalizeRequested, _: &mut Self::Context) -> Self::Result {
        if !self.effects_enabled {
            return Box::pin(async {});
        }

        let e3_id = msg.e3_id.clone();
        let contract_address = self.contract_address;
        let provider = self.provider.clone();
        let bus = self.bus.clone();

        Box::pin(async move {
            match should_finalize_committee(provider.clone(), contract_address, e3_id.clone()).await
            {
                Ok(false) => {
                    info!(e3_id = %e3_id, "Skipping finalizeCommittee; on-chain state is not finalizable");
                    return;
                }
                Err(err) => {
                    error!(
                        "Failed to preflight finalizeCommittee: {}",
                        format_evm_error(&err)
                    );
                    return;
                }
                Ok(true) => {}
            }

            info!("Finalizing committee for E3 {:?}", e3_id);

            let result = finalize_committee_on_registry(provider, contract_address, e3_id).await;
            match result {
                Ok(receipt) => {
                    info!(tx=%receipt.transaction_hash, "Committee finalized on registry");
                }
                Err(err) => {
                    error!("Failed to finalize committee: {}", format_evm_error(&err));
                    bus.err(EType::Evm, err);
                }
            }
        })
    }
}

impl<P: Provider + WalletProvider + Clone + 'static> Handler<PublicKeyAggregated>
    for CiphernodeRegistrySolWriter<P>
{
    type Result = ResponseFuture<()>;

    fn handle(&mut self, msg: PublicKeyAggregated, ctx: &mut Self::Context) -> Self::Result {
        if !self.effects_enabled || !self.is_active_aggregator_for(&msg.e3_id) {
            return Box::pin(async {});
        }

        // Don't fire a second on-chain submission for an E3 whose publishCommittee
        // tx is already in flight (H13). The on-chain preflight below is still the
        // authoritative idempotency guard across restarts.
        if !self.submitting.insert(msg.e3_id.clone()) {
            info!(e3_id = %msg.e3_id, "publishCommittee already in flight; skipping duplicate submission");
            return Box::pin(async {});
        }

        let e3_id = msg.e3_id.clone();
        let pubkey = msg.pubkey.clone();
        let pk_commitment = msg.pk_commitment;
        let dkg_aggregator_proof = msg.dkg_aggregator_proof.clone();
        let dkg_attestation_bundle = msg.dkg_attestation_bundle.clone();
        let contract_address = self.contract_address;
        let provider = self.provider.clone();
        let bus = self.bus.clone();
        let self_addr = ctx.address();

        Box::pin(async move {
            match should_publish_committee(provider.clone(), contract_address, e3_id.clone()).await
            {
                Ok(false) => {
                    info!(e3_id = %e3_id, "Skipping publishCommittee; committee public key already published");
                    return;
                }
                Err(err) => {
                    error!(
                        "Failed to preflight publishCommittee: {}",
                        format_evm_error(&err)
                    );
                    // Transient read failure: allow a later event to retry.
                    self_addr.do_send(ClearSubmitting(e3_id));
                    return;
                }
                Ok(true) => {}
            }

            let result = publish_committee_to_registry(
                provider,
                contract_address,
                e3_id.clone(),
                pubkey,
                pk_commitment,
                dkg_aggregator_proof.as_ref(),
                dkg_attestation_bundle.as_ref().map(|b| b.as_ref()),
            )
            .await;
            match result {
                Ok(receipt) => {
                    info!(tx=%receipt.transaction_hash, "Committee published to registry");
                }
                Err(err) => {
                    error!("Failed to publish committee: {}", format_evm_error(&err));
                    // Submission failed: clear the in-flight marker so a retry can proceed.
                    self_addr.do_send(ClearSubmitting(e3_id));
                    bus.err(EType::Evm, err);
                }
            }
        })
    }
}

/// Internal message: clear the in-flight `publishCommittee` marker for an E3 so
/// a subsequent submission attempt is allowed after a failure (H13).
#[derive(Message)]
#[rtype(result = "()")]
struct ClearSubmitting(E3id);

impl<P: Provider + WalletProvider + Clone + 'static> Handler<ClearSubmitting>
    for CiphernodeRegistrySolWriter<P>
{
    type Result = ();

    fn handle(&mut self, msg: ClearSubmitting, _: &mut Self::Context) -> Self::Result {
        self.submitting.remove(&msg.0);
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
