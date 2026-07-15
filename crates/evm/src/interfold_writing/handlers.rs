// SPDX-License-Identifier: LGPL-3.0-only

//! Message routing and actor lifecycle.

use super::effects::*;
use super::*;

impl<P: Provider + WalletProvider + Clone + 'static> Handler<InterfoldEvent>
    for InterfoldSolWriter<P>
{
    type Result = ();

    fn handle(&mut self, msg: InterfoldEvent, ctx: &mut Self::Context) -> Self::Result {
        match msg.into_data() {
            InterfoldEventData::EffectsEnabled(data) => self.notify_sync(ctx, data),
            InterfoldEventData::AggregatorChanged(data) => self.notify_sync(ctx, data),
            InterfoldEventData::PlaintextAggregated(data) => {
                // Only publish if the src and destination chains match
                if self.provider.chain_id() == data.e3_id.chain_id() {
                    ctx.notify(data);
                }
            }
            InterfoldEventData::E3StageChanged(data) => {
                // When an E3 transitions to Failed on-chain, call processE3Failure
                // to finalize refund distribution automatically.
                if data.new_stage == E3Stage::Failed
                    && self.provider.chain_id() == data.e3_id.chain_id()
                {
                    ctx.notify(data);
                }
            }
            InterfoldEventData::EffectRetry(retry) => match retry.into_effect() {
                InterfoldEventData::PlaintextAggregated(data)
                    if self.provider.chain_id() == data.e3_id.chain_id() =>
                {
                    ctx.notify(data);
                }
                InterfoldEventData::E3StageChanged(data)
                    if data.new_stage == E3Stage::Failed
                        && self.provider.chain_id() == data.e3_id.chain_id() =>
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
    for InterfoldSolWriter<P>
{
    type Result = ();

    fn handle(&mut self, _: EffectsEnabled, _: &mut Self::Context) -> Self::Result {
        self.effects_enabled = true;
    }
}

impl<P: Provider + WalletProvider + Clone + 'static> Handler<AggregatorChanged>
    for InterfoldSolWriter<P>
{
    type Result = ();

    fn handle(&mut self, msg: AggregatorChanged, _: &mut Self::Context) -> Self::Result {
        self.active_aggregators.insert(msg.e3_id, msg.is_aggregator);
    }
}

impl<P: Provider + WalletProvider + Clone + 'static> Handler<E3RequestComplete>
    for InterfoldSolWriter<P>
{
    type Result = ();

    fn handle(&mut self, msg: E3RequestComplete, _: &mut Self::Context) -> Self::Result {
        self.active_aggregators.remove(&msg.e3_id);
        self.submitting.remove(&msg.e3_id);
    }
}

impl<P: Provider + WalletProvider + Clone + 'static> Handler<PlaintextAggregated>
    for InterfoldSolWriter<P>
{
    type Result = ResponseFuture<()>;

    fn handle(&mut self, msg: PlaintextAggregated, ctx: &mut Self::Context) -> Self::Result {
        if !self.effects_enabled || !self.is_active_aggregator_for(&msg.e3_id) {
            return Box::pin(async {});
        }

        // Don't fire a second on-chain submission for an E3 whose
        // publishPlaintextOutput tx is already in flight (H13).
        if !self.submitting.insert(msg.e3_id.clone()) {
            info!(e3_id = %msg.e3_id, "publishPlaintextOutput already in flight; skipping duplicate submission");
            return Box::pin(async {});
        }
        let self_addr = ctx.address();

        Box::pin({
            let e3_id = msg.e3_id.clone();
            let decrypted_output = msg.decrypted_output.clone();
            let contract_address = self.contract_address;
            let provider = self.provider.clone();
            let bus = self.bus.clone();
            async move {
                // HACK: plaintext format is now a Vec of ArcBytes for legacy tests for now we are extracting
                // the first entry and writing this will change once we make our legacy tests catch up
                if let Err(msg_err) = validate_plaintext_output(
                    &e3_id,
                    &decrypted_output,
                    &msg.decryption_aggregator_proofs,
                ) {
                    self_addr.do_send(ClearSubmitting(e3_id.clone()));
                    bus.err(EType::Evm, anyhow::anyhow!(msg_err));
                    return;
                }
                // Safe: `validate_plaintext_output` guarantees exactly one output.
                let decrypted = &decrypted_output[0];
                match should_publish_plaintext(provider.clone(), contract_address, e3_id.clone())
                    .await
                {
                    Ok(false) => {
                        info!(e3_id = %e3_id, "Skipping publishPlaintextOutput; plaintext already published");
                        return;
                    }
                    Err(err) => {
                        self_addr.do_send(ClearSubmitting(e3_id.clone()));
                        bus.err(
                            EType::Evm,
                            anyhow::anyhow!(
                                "Error preflighting plaintext publication: {}",
                                format_evm_error(&err)
                            ),
                        );
                        return;
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
                    }
                    Err(err) => {
                        self_addr.do_send(ClearSubmitting(e3_id));
                        bus.err(
                            EType::Evm,
                            anyhow::anyhow!(
                                "Error publishing plaintext output: {}",
                                format_evm_error(&err)
                            ),
                        );
                    }
                }
            }
        })
    }
}

/// Internal message: clear the in-flight `publishPlaintextOutput` marker for an
/// E3 so a subsequent submission attempt is allowed after a failure (H13).
#[derive(Message)]
#[rtype(result = "()")]
struct ClearSubmitting(E3id);

impl<P: Provider + WalletProvider + Clone + 'static> Handler<ClearSubmitting>
    for InterfoldSolWriter<P>
{
    type Result = ();

    fn handle(&mut self, msg: ClearSubmitting, _: &mut Self::Context) -> Self::Result {
        self.submitting.remove(&msg.0);
    }
}

impl<P: Provider + WalletProvider + Clone + 'static> Handler<Shutdown> for InterfoldSolWriter<P> {
    type Result = ();

    fn handle(&mut self, _: Shutdown, ctx: &mut Self::Context) -> Self::Result {
        ctx.stop();
    }
}

impl<P: Provider + WalletProvider + Clone + 'static> Handler<E3StageChanged>
    for InterfoldSolWriter<P>
{
    type Result = ResponseFuture<()>;

    fn handle(&mut self, msg: E3StageChanged, _: &mut Self::Context) -> Self::Result {
        if !self.effects_enabled {
            return Box::pin(async {});
        }

        Box::pin({
            let e3_id = msg.e3_id.clone();
            let contract_address = self.contract_address;
            let provider = self.provider.clone();
            let bus = self.bus.clone();
            async move {
                match should_process_e3_failure(provider.clone(), contract_address, e3_id.clone())
                    .await
                {
                    Ok(false) => {
                        info!(e3_id = %e3_id, "Skipping processE3Failure; refund was already processed");
                        return;
                    }
                    Err(err) => {
                        bus.err(
                            EType::Evm,
                            anyhow::anyhow!(
                                "Error preflighting E3 failure processing: {}",
                                format_evm_error(&err)
                            ),
                        );
                        return;
                    }
                    Ok(true) => {}
                }
                let result = process_e3_failure(provider, contract_address, e3_id.clone()).await;
                match result {
                    Ok(receipt) => {
                        info!(
                            tx=%receipt.transaction_hash,
                            e3_id = %e3_id,
                            "Called processE3Failure"
                        );
                    }
                    Err(err) => {
                        info!(
                            e3_id = %e3_id,
                            "processE3Failure did not succeed (may already be processed): {}",
                            format_evm_error(&err)
                        );
                    }
                }
            }
        })
    }
}
