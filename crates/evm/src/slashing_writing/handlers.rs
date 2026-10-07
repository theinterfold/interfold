// SPDX-License-Identifier: LGPL-3.0-only

//! Admission, scheduling, and submission-outcome handlers.

use super::effects::{read_slash_policy, submit_slash_proposal};
use super::*;

impl<P: Provider + WalletProvider + Clone + 'static> Handler<InterfoldEvent>
    for SlashingManagerSolWriter<P>
{
    type Result = ();

    fn handle(&mut self, msg: InterfoldEvent, ctx: &mut Self::Context) -> Self::Result {
        let (msg, event_context) = msg.into_components();
        match msg {
            InterfoldEventData::AccusationQuorumReached(data) => {
                // Every node evaluates the policy after quorum. Only the first three voters send
                // a transaction when Lane A is enabled, but all nodes need the same disabled-policy
                // decision so they can derive the same E3-scoped exclusion.
                if self.provider.chain_id() == data.e3_id.chain_id()
                    && is_slashable_outcome(&data.outcome)
                {
                    let recovery = &mut self.recovery;
                    let decision = self.submissions.record_and_admit(data.clone(), |event| {
                        if let Some(recovery) = recovery.as_mut() {
                            recovery.try_mutate(&event_context, |mut recovery| {
                                recovery.record(event.clone())?;
                                Ok(recovery)
                            })?;
                        }
                        Ok(())
                    });
                    match decision {
                        Ok((key, SlashSubmissionDecision::Submit)) => {
                            ctx.notify(SubmitSlashIntent { key, event: data });
                        }
                        Ok((_, SlashSubmissionDecision::Defer)) => {
                            info!(e3_id = %data.e3_id, "Deferred slash intent until effects are enabled");
                        }
                        Ok((_, SlashSubmissionDecision::IgnoreDuplicate)) => {
                            info!(e3_id = %data.e3_id, "Ignored duplicate slash intent");
                        }
                        Err(error) => self.bus.with_ec(&event_context).err(EType::Evm, error),
                    }
                }
            }
            InterfoldEventData::CommitteeMemberExcluded(data) => {
                if data.e3_id.chain_id() == self.provider.chain_id() {
                    match SlashIntentKey::from_exclusion(&data) {
                        Ok(key) => {
                            if let Some(recovery) = self.recovery.as_mut() {
                                if let Err(error) =
                                    recovery.try_mutate(&event_context, |mut recovery| {
                                        recovery.acknowledge(&key);
                                        Ok(recovery)
                                    })
                                {
                                    self.bus.with_ec(&event_context).err(EType::Evm, error);
                                }
                            }
                            self.submissions.mark_completed(key);
                        }
                        Err(error) => self.bus.err(EType::Evm, error),
                    }
                }
            }
            InterfoldEventData::SlashExecuted(data) => {
                if data.e3_id.chain_id() == self.provider.chain_id() {
                    match SlashIntentKey::from_execution(&data) {
                        Ok(Some(key)) => {
                            if let Some(recovery) = self.recovery.as_mut() {
                                if let Err(error) =
                                    recovery.try_mutate(&event_context, |mut recovery| {
                                        recovery.acknowledge(&key);
                                        Ok(recovery)
                                    })
                                {
                                    self.bus.with_ec(&event_context).err(EType::Evm, error);
                                }
                            }
                            self.submissions.mark_completed(key);
                        }
                        Ok(None) => {}
                        Err(error) => self.bus.err(EType::Evm, error),
                    }
                }
            }
            InterfoldEventData::EffectsEnabled(_) => {
                let deferred = self.submissions.enable_effects();
                if !deferred.is_empty() {
                    info!(
                        intents = deferred.len(),
                        "Releasing deferred slash intents after startup reconciliation"
                    );
                    let address = ctx.address();
                    ctx.spawn(
                        async move {
                            for (key, event) in deferred {
                                if let Err(error) =
                                    address.send(SubmitSlashIntent { key, event }).await
                                {
                                    warn!(%error, "Slashing writer stopped with deferred intents pending");
                                    break;
                                }
                            }
                        }
                        .into_actor(self),
                    );
                }
            }
            InterfoldEventData::Shutdown(data) => self.notify_sync(ctx, data),
            _ => (),
        }
    }
}

impl<P: Provider + WalletProvider + Clone + 'static> Handler<SubmitSlashIntent>
    for SlashingManagerSolWriter<P>
{
    type Result = ResponseFuture<()>;

    fn handle(&mut self, msg: SubmitSlashIntent, ctx: &mut Self::Context) -> Self::Result {
        Box::pin({
            let contract_address = self.contract_address;
            let provider = self.provider.clone();
            let bus = self.bus.clone();
            let my_addr = self.provider.provider().default_signer_address();
            let address = ctx.address();
            async move {
                let SubmitSlashIntent { key, event } = msg;
                // The workflow decides; this loop only runs the effect of each step.
                let (submission, mut step) = SlashSubmission::new(event, my_addr);
                let end = loop {
                    step = match step {
                        SubmissionStep::ReadPolicy => {
                            let policy = read_slash_policy(
                                provider.clone(),
                                contract_address,
                                submission.event().proof_type,
                            )
                            .await
                            .map(|policy| {
                                classify_slash_policy(policy.enabled, policy.requiresProof)
                            })
                            .map_err(|error| {
                                warn!(%error, "Could not read slash policy before submission");
                                error.to_string()
                            });
                            submission.policy_read(policy)
                        }
                        SubmissionStep::Exclude(exclusion) => {
                            info!(
                                e3_id = %exclusion.e3_id,
                                accused = %exclusion.node,
                                proof_type = %exclusion.proof_type,
                                reason = %slash_reason(exclusion.proof_type),
                                "Slash policy is disabled; excluding the faulted member from local E3 work"
                            );
                            let published = bus
                                .publish_without_context(exclusion)
                                .map(|_| ())
                                .map_err(|error| format!("{error:#}"));
                            submission.exclusion_published(published)
                        }
                        SubmissionStep::Wait { rank, delay } => {
                            info!(
                                "Fallback submitter (rank {rank}): waiting {delay:?} before submission attempt"
                            );
                            tokio::time::sleep(delay).await;
                            SubmissionStep::Submit { rank }
                        }
                        SubmissionStep::Submit { rank } => {
                            let result = submit_slash_proposal(
                                provider.clone(),
                                contract_address,
                                submission.event().clone(),
                            )
                            .await;
                            if let Ok(receipt) = &result {
                                info!(tx=%receipt.transaction_hash, "Submitted attestation-based slash proposal on-chain");
                            }
                            submission.submitted(
                                rank,
                                result.map(|_| ()).map_err(|error| format_evm_error(&error)),
                            )
                        }
                        SubmissionStep::End { end, report } => {
                            match report {
                                Some(SubmissionReport::Error(error)) => {
                                    bus.err(EType::Evm, anyhow::anyhow!(error))
                                }
                                Some(SubmissionReport::Skipped(message)) => warn!("{message}"),
                                None => {}
                            }
                            break end;
                        }
                    };
                };
                if let Err(error) = address
                    .send(SlashSubmissionFinished {
                        key,
                        terminal: end.terminal,
                        acknowledge_recovery: end.acknowledge_recovery,
                        retry_event: end.retry.then(|| submission.event().clone()),
                    })
                    .await
                {
                    warn!(%error, "Slashing writer stopped before recording submission outcome");
                }
            }
        })
    }
}

impl<P: Provider + WalletProvider + Clone + 'static> Handler<SlashSubmissionFinished>
    for SlashingManagerSolWriter<P>
{
    type Result = ();

    fn handle(&mut self, msg: SlashSubmissionFinished, ctx: &mut Self::Context) -> Self::Result {
        if msg.acknowledge_recovery {
            if let Some(recovery) = self.recovery.as_mut() {
                if let Err(error) = recovery.try_mutate_without_context(|mut recovery| {
                    recovery.acknowledge(&msg.key);
                    Ok(recovery)
                }) {
                    self.bus.err(EType::Evm, error);
                }
            }
        }
        self.submissions.finish(&msg.key, msg.terminal);
        let Some(event) = msg.retry_event else {
            return;
        };

        ctx.run_later(SLASH_SUBMISSION_RETRY_DELAY, move |actor, ctx| match actor
            .submissions
            .admit(event.clone())
        {
            Ok((key, SlashSubmissionDecision::Submit)) => {
                ctx.notify(SubmitSlashIntent { key, event });
            }
            Ok((_, SlashSubmissionDecision::Defer)) => {}
            Ok((_, SlashSubmissionDecision::IgnoreDuplicate)) => {}
            Err(error) => actor.bus.err(EType::Evm, error),
        });
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
