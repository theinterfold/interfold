// SPDX-License-Identifier: LGPL-3.0-only

//! Durable admission, replay, and transaction routing for the Interfold writer.

use super::effects::*;
use super::*;
use crate::{reconcile_dispatched, DispatchReconciliation, OutboxAdmission};

#[derive(Message)]
#[rtype(result = "()")]
struct InterfoldEffectFinished(String);

impl<P: Provider + WalletProvider + Clone + 'static> InterfoldSolWriter<P> {
    fn admit_effect(&mut self, effect: InterfoldEffect, ctx: &mut Context<Self>) {
        let key = effect.key();
        let outbox = self.outbox.clone();
        let bus = self.bus.clone();
        ctx.wait(
            async move { outbox.admit(key, effect).await }
                .into_actor(self)
                .map(move |result, _, ctx| match result {
                    Ok(OutboxAdmission::AlreadyTerminal) => {}
                    Ok(OutboxAdmission::Inserted | OutboxAdmission::AlreadyPending) => {
                        ctx.notify(DrainInterfoldOutbox);
                    }
                    Err(error) => bus.err(EType::Evm, error),
                }),
        );
    }

    fn can_execute(&self, effect: &InterfoldEffect) -> bool {
        self.effects_enabled
            && match effect {
                InterfoldEffect::PublishPlaintext(event) => {
                    self.is_active_aggregator_for(&event.e3_id)
                }
                InterfoldEffect::ProcessFailure(_)
                | InterfoldEffect::RefreshFailoverLease(_)
                | InterfoldEffect::MarkFailure(_) => true,
            }
    }
}

impl<P: Provider + WalletProvider + Clone + 'static> Handler<InterfoldEvent>
    for InterfoldSolWriter<P>
{
    type Result = ();

    fn handle(&mut self, msg: InterfoldEvent, ctx: &mut Self::Context) -> Self::Result {
        match msg.into_data() {
            InterfoldEventData::EffectsEnabled(data) => self.notify_sync(ctx, data),
            InterfoldEventData::AggregatorChanged(data) => self.notify_sync(ctx, data),
            InterfoldEventData::PlaintextAggregated(data)
                if self.provider.chain_id() == data.e3_id.chain_id() =>
            {
                self.admit_effect(InterfoldEffect::PublishPlaintext(data), ctx)
            }
            InterfoldEventData::E3StageChanged(data)
                if data.new_stage == E3Stage::Failed
                    && self.provider.chain_id() == data.e3_id.chain_id() =>
            {
                self.admit_effect(InterfoldEffect::ProcessFailure(data), ctx)
            }
            InterfoldEventData::CommitteeFinalized(data)
                if self.provider.chain_id() == data.e3_id.chain_id() =>
            {
                self.admit_effect(
                    InterfoldEffect::RefreshFailoverLease(FailoverLeaseRefresh {
                        e3_id: data.e3_id,
                        phase: AggregatorPhase::AwaitingPublicKey,
                    }),
                    ctx,
                )
            }
            InterfoldEventData::CiphertextOutputPublished(data)
                if self.provider.chain_id() == data.e3_id.chain_id() =>
            {
                self.admit_effect(
                    InterfoldEffect::RefreshFailoverLease(FailoverLeaseRefresh {
                        e3_id: data.e3_id,
                        phase: AggregatorPhase::AwaitingPlaintext,
                    }),
                    ctx,
                )
            }
            InterfoldEventData::AggregatorFailoverExhausted(data)
                if self.provider.chain_id() == data.e3_id.chain_id() =>
            {
                self.admit_effect(InterfoldEffect::MarkFailure(data), ctx)
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
        ctx.notify(DrainInterfoldOutbox);
    }
}

impl<P: Provider + WalletProvider + Clone + 'static> Handler<AggregatorChanged>
    for InterfoldSolWriter<P>
{
    type Result = ();

    fn handle(&mut self, msg: AggregatorChanged, ctx: &mut Self::Context) -> Self::Result {
        let became_active = msg.is_aggregator;
        self.active_aggregators.insert(msg.e3_id, msg.is_aggregator);
        if became_active && self.effects_enabled {
            ctx.notify(DrainInterfoldOutbox);
        }
    }
}

impl<P: Provider + WalletProvider + Clone + 'static> Handler<E3RequestComplete>
    for InterfoldSolWriter<P>
{
    type Result = ();

    fn handle(&mut self, msg: E3RequestComplete, _: &mut Self::Context) -> Self::Result {
        self.active_aggregators.remove(&msg.e3_id);
    }
}

impl<P: Provider + WalletProvider + Clone + 'static> Handler<PlaintextAggregated>
    for InterfoldSolWriter<P>
{
    type Result = ();

    fn handle(&mut self, msg: PlaintextAggregated, ctx: &mut Self::Context) -> Self::Result {
        self.admit_effect(InterfoldEffect::PublishPlaintext(msg), ctx);
    }
}

impl<P: Provider + WalletProvider + Clone + 'static> Handler<E3StageChanged>
    for InterfoldSolWriter<P>
{
    type Result = ();

    fn handle(&mut self, msg: E3StageChanged, ctx: &mut Self::Context) -> Self::Result {
        self.admit_effect(InterfoldEffect::ProcessFailure(msg), ctx);
    }
}

impl<P: Provider + WalletProvider + Clone + 'static> Handler<DrainInterfoldOutbox>
    for InterfoldSolWriter<P>
{
    type Result = ();

    fn handle(&mut self, _: DrainInterfoldOutbox, ctx: &mut Self::Context) -> Self::Result {
        if !self.effects_enabled {
            return;
        }
        let outbox = self.outbox.clone();
        ctx.wait(async move { outbox.pending().await }.into_actor(self).map(
            |pending, actor, ctx| {
                for (key, effect, status) in pending {
                    if actor.can_execute(&effect) && actor.submitting.insert(key.clone()) {
                        ctx.notify(ExecuteInterfoldEffect {
                            key,
                            effect,
                            status,
                        });
                    }
                }
            },
        ));
    }
}

impl<P: Provider + WalletProvider + Clone + 'static> Handler<ExecuteInterfoldEffect>
    for InterfoldSolWriter<P>
{
    type Result = ResponseFuture<()>;

    fn handle(&mut self, msg: ExecuteInterfoldEffect, ctx: &mut Self::Context) -> Self::Result {
        let provider = self.provider.clone();
        let contract_address = self.contract_address;
        let outbox = self.outbox.clone();
        let bus = self.bus.clone();
        let address = ctx.address();

        Box::pin(async move {
            let ExecuteInterfoldEffect {
                key,
                effect,
                status,
            } = msg;
            let result: Result<()> = async {
                match reconcile_dispatched(&provider, &outbox, &key, &status).await? {
                    DispatchReconciliation::Pending | DispatchReconciliation::Terminal => {
                        return Ok(())
                    }
                    DispatchReconciliation::NotDispatched | DispatchReconciliation::Retry => {}
                }

                match effect {
                    InterfoldEffect::PublishPlaintext(event) => {
                        let publication = validate_plaintext_output(
                            &event.e3_id,
                            event.decrypted_output,
                            event.decryption_aggregator_proofs,
                        )
                        .map_err(anyhow::Error::msg)?;
                        if !should_publish_plaintext(
                            provider.clone(),
                            contract_address,
                            event.e3_id.clone(),
                        )
                        .await?
                        {
                            outbox.mark_terminal(&key).await?;
                            return Ok(());
                        }
                        let receipt = publish_plaintext_output(
                            provider.clone(),
                            contract_address,
                            event.e3_id,
                            publication.decrypted_output.extract_bytes(),
                            Some(&publication.proof),
                            &outbox,
                            &key,
                        )
                        .await?;
                        info!(tx=%receipt.transaction_hash, "Published plaintext output");
                    }
                    InterfoldEffect::ProcessFailure(event) => {
                        if !should_process_e3_failure(
                            provider.clone(),
                            contract_address,
                            event.e3_id.clone(),
                        )
                        .await?
                        {
                            outbox.mark_terminal(&key).await?;
                            return Ok(());
                        }
                        let receipt = process_e3_failure(
                            provider.clone(),
                            contract_address,
                            event.e3_id.clone(),
                            &outbox,
                            &key,
                        )
                        .await?;
                        info!(tx=%receipt.transaction_hash, e3_id=%event.e3_id, "Called processE3Failure");
                    }
                    InterfoldEffect::RefreshFailoverLease(event) => {
                        if let Some(lease) = read_failover_lease(
                            provider.clone(),
                            contract_address,
                            event.e3_id,
                            event.phase,
                        )
                        .await?
                        {
                            bus.publish_without_context(lease)?;
                        }
                    }
                    InterfoldEffect::MarkFailure(event) => {
                        match should_mark_e3_failed(
                            provider.clone(),
                            contract_address,
                            event.e3_id.clone(),
                            event.phase,
                        )
                        .await?
                        {
                            MarkFailurePreflight::Terminal => {
                                outbox.mark_terminal(&key).await?;
                                return Ok(());
                            }
                            MarkFailurePreflight::Retry => return Ok(()),
                            MarkFailurePreflight::Submit => {}
                        }
                        let receipt = mark_e3_failed(
                            provider.clone(),
                            contract_address,
                            event.e3_id.clone(),
                            &outbox,
                            &key,
                        )
                        .await?;
                        info!(tx=%receipt.transaction_hash, e3_id=%event.e3_id, "Called markE3Failed after aggregator exhaustion");
                    }
                }
                outbox.mark_terminal(&key).await?;
                Ok(())
            }
            .await;

            if let Err(error) = result {
                bus.err(
                    EType::Evm,
                    anyhow::anyhow!(
                        "Durable Interfold effect {key} remains pending: {}",
                        format_evm_error(&error)
                    ),
                );
            }
            if let Err(error) = address.send(InterfoldEffectFinished(key)).await {
                tracing::error!(%error, "Interfold writer stopped before clearing in-flight effect");
            }
        })
    }
}

impl<P: Provider + WalletProvider + Clone + 'static> Handler<InterfoldEffectFinished>
    for InterfoldSolWriter<P>
{
    type Result = ();

    fn handle(&mut self, msg: InterfoldEffectFinished, _: &mut Self::Context) -> Self::Result {
        self.submitting.remove(&msg.0);
    }
}

impl<P: Provider + WalletProvider + Clone + 'static> Handler<Shutdown> for InterfoldSolWriter<P> {
    type Result = ();

    fn handle(&mut self, _: Shutdown, ctx: &mut Self::Context) -> Self::Result {
        ctx.stop();
    }
}
