// SPDX-License-Identifier: LGPL-3.0-only

//! Durable slash-intent admission, replay, and submission-outcome handlers.

use super::effects::{should_submit_slash_proposal, submit_slash_proposal};
use super::*;
use crate::{reconcile_dispatched, DispatchReconciliation, OutboxAdmission};

impl<P: Provider + WalletProvider + Clone + 'static> SlashingManagerSolWriter<P> {
    fn admit_intent(&mut self, event: AccusationQuorumReached, ctx: &mut Context<Self>) {
        let key = match SlashIntentKey::from_quorum(&event) {
            Ok(key) => key.storage_key(),
            Err(error) => {
                self.bus.err(EType::Evm, error);
                return;
            }
        };
        let outbox = self.outbox.clone();
        let bus = self.bus.clone();
        ctx.wait(
            async move { outbox.admit(key, event).await }
                .into_actor(self)
                .map(move |result, _, ctx| match result {
                    Ok(OutboxAdmission::AlreadyTerminal) => {}
                    Ok(OutboxAdmission::Inserted | OutboxAdmission::AlreadyPending) => {
                        ctx.notify(DrainSlashOutbox);
                    }
                    Err(error) => bus.err(EType::Evm, error),
                }),
        );
    }
}

impl<P: Provider + WalletProvider + Clone + 'static> Handler<InterfoldEvent>
    for SlashingManagerSolWriter<P>
{
    type Result = ();

    fn handle(&mut self, msg: InterfoldEvent, ctx: &mut Self::Context) -> Self::Result {
        match msg.into_data() {
            InterfoldEventData::AccusationQuorumReached(data) => {
                let my_addr = self.provider.provider().default_signer_address();
                let rank = submission_rank(data.votes_for.iter().map(|vote| vote.voter), my_addr);
                if !should_submit_slash(
                    self.provider.chain_id() == data.e3_id.chain_id(),
                    &data.outcome,
                    rank,
                ) {
                    return;
                }
                if encode_attestation_evidence(&data).is_none() {
                    self.bus.err(
                        EType::Evm,
                        anyhow::anyhow!(
                            "Refusing malformed slash intent for E3 {}: votes or evidence are empty",
                            data.e3_id
                        ),
                    );
                    return;
                }
                self.admit_intent(data, ctx);
            }
            InterfoldEventData::EffectsEnabled(_) => {
                self.effects_enabled = true;
                ctx.notify(DrainSlashOutbox);
            }
            InterfoldEventData::Shutdown(data) => self.notify_sync(ctx, data),
            _ => (),
        }
    }
}

impl<P: Provider + WalletProvider + Clone + 'static> Handler<DrainSlashOutbox>
    for SlashingManagerSolWriter<P>
{
    type Result = ();

    fn handle(&mut self, _: DrainSlashOutbox, ctx: &mut Self::Context) -> Self::Result {
        if !self.effects_enabled {
            return;
        }
        let outbox = self.outbox.clone();
        let my_addr = self.provider.provider().default_signer_address();
        let chain_id = self.provider.chain_id();
        ctx.wait(async move { outbox.pending().await }.into_actor(self).map(
            move |pending, actor, ctx| {
                for (key, event, status) in pending {
                    let rank =
                        submission_rank(event.votes_for.iter().map(|vote| vote.voter), my_addr);
                    if should_submit_slash(chain_id == event.e3_id.chain_id(), &event.outcome, rank)
                        && actor.submitting.insert(key.clone())
                    {
                        ctx.notify(ExecuteSlashIntent { key, event, status });
                    }
                }
            },
        ));
    }
}

impl<P: Provider + WalletProvider + Clone + 'static> Handler<ExecuteSlashIntent>
    for SlashingManagerSolWriter<P>
{
    type Result = ResponseFuture<()>;

    fn handle(&mut self, msg: ExecuteSlashIntent, ctx: &mut Self::Context) -> Self::Result {
        let contract_address = self.contract_address;
        let provider = self.provider.clone();
        let outbox = self.outbox.clone();
        let bus = self.bus.clone();
        let my_addr = self.provider.provider().default_signer_address();
        let address = ctx.address();

        Box::pin(async move {
            let ExecuteSlashIntent { key, event, status } = msg;
            let result: Result<()> = async {
                match reconcile_dispatched(&provider, &outbox, &key, &status).await? {
                    DispatchReconciliation::Pending | DispatchReconciliation::Terminal => {
                        return Ok(())
                    }
                    DispatchReconciliation::NotDispatched | DispatchReconciliation::Retry => {}
                }

                let rank = submission_rank(event.votes_for.iter().map(|vote| vote.voter), my_addr)
                    .unwrap_or(0);
                if rank > 0 {
                    let delay = submission_delay(rank);
                    info!("Fallback submitter (rank {rank}): waiting {delay:?} before submission attempt");
                    tokio::time::sleep(delay).await;
                }

                if !should_submit_slash_proposal(
                    provider.clone(),
                    contract_address,
                    event.clone(),
                )
                .await?
                {
                    outbox.mark_terminal(&key).await?;
                    return Ok(());
                }

                let receipt = submit_slash_proposal(
                    provider.clone(),
                    contract_address,
                    event,
                    &outbox,
                    &key,
                )
                .await?;
                info!(tx=%receipt.transaction_hash, "Submitted attestation-based slash proposal on-chain");
                outbox.mark_terminal(&key).await?;
                Ok(())
            }
            .await;

            if let Err(error) = result {
                let decoded = format_evm_error(&error);
                let benign = decoded.contains("OperatorNotInCommittee")
                    || decoded.contains("VoterNotInCommittee")
                    || decoded.contains("DuplicateEvidence");
                if benign {
                    if let Err(persist_error) = outbox.mark_terminal(&key).await {
                        bus.err(EType::Evm, persist_error);
                    }
                    warn!(effect_key=%key, "Slash submission reconciled as terminal: {decoded}");
                } else {
                    bus.err(
                        EType::Evm,
                        anyhow::anyhow!("Durable slash effect {key} remains pending: {decoded}"),
                    );
                }
            }
            if let Err(error) = address.send(SlashSubmissionFinished { key }).await {
                warn!(%error, "Slashing writer stopped before clearing in-flight effect");
            }
        })
    }
}

impl<P: Provider + WalletProvider + Clone + 'static> Handler<SlashSubmissionFinished>
    for SlashingManagerSolWriter<P>
{
    type Result = ();

    fn handle(&mut self, msg: SlashSubmissionFinished, _: &mut Self::Context) -> Self::Result {
        self.submitting.remove(&msg.key);
    }
}

impl<P: Provider + WalletProvider + Clone + 'static> Handler<Shutdown>
    for SlashingManagerSolWriter<P>
{
    type Result = ();

    fn handle(&mut self, _: Shutdown, ctx: &mut Self::Context) -> Self::Result {
        ctx.stop();
    }
}
