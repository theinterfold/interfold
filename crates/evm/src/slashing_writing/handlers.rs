// SPDX-License-Identifier: LGPL-3.0-only

//! Admission, scheduling, and submission-outcome handlers.

use super::effects::{slash_evidence_consumed, submit_slash_proposal};
use super::*;

impl<P: Provider + WalletProvider + Clone + 'static> Handler<InterfoldEvent>
    for SlashingManagerSolWriter<P>
{
    type Result = ();

    fn handle(&mut self, msg: InterfoldEvent, ctx: &mut Self::Context) -> Self::Result {
        let data = match msg.into_data() {
            InterfoldEventData::EffectRetry(retry) => retry.into_effect(),
            data => data,
        };
        match data {
            InterfoldEventData::AccusationQuorumReached(data) => {
                // Only submit if:
                // 1. This is the right chain
                // 2. The quorum decided the accused is at fault OR equivocated
                // 3. This node is among the top MAX_SLASH_SUBMITTERS voters
                //    (sorted ascending by address). The lowest-address voter
                //    submits immediately; higher-ranked fallback voters wait
                //    progressively longer (rank * SUBMITTER_DELAY_SECS) before
                //    attempting submission. On-chain DuplicateEvidence protection
                //    ensures at most one slash executes.
                let my_addr = self.provider.provider().default_signer_address();
                let rank = submission_rank(data.votes_for.iter().map(|v| v.voter), my_addr);

                if should_submit_slash(
                    self.provider.chain_id() == data.e3_id.chain_id(),
                    &data.outcome,
                    rank,
                ) {
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
                    match self.submissions.admit(data.clone()) {
                        Ok((key, SlashSubmissionDecision::Submit)) => {
                            ctx.notify(SubmitSlashIntent { key, event: data });
                        }
                        Ok((_, SlashSubmissionDecision::Defer)) => {
                            info!(e3_id = %data.e3_id, "Deferred slash intent until effects are enabled");
                        }
                        Ok((_, SlashSubmissionDecision::IgnoreDuplicate)) => {
                            info!(e3_id = %data.e3_id, "Ignored duplicate slash intent");
                        }
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
            InterfoldEventData::EvmLogObserved(observation) => {
                if let Some(key) = SlashIntentKey::from_observation(&observation) {
                    self.submissions.complete_observed(key);
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
                let SubmitSlashIntent { key, event: msg } = msg;
                // Compute this node's submission rank for staggered fallback
                let rank =
                    submission_rank(msg.votes_for.iter().map(|v| v.voter), my_addr).unwrap_or(0);

                // Fallback submitters wait before attempting, giving the primary
                // submitter time to land the transaction on-chain.
                if rank > 0 {
                    let delay = submission_delay(rank);
                    info!(
                        "Fallback submitter (rank {rank}): waiting {delay:?} before submission attempt"
                    );
                    tokio::time::sleep(delay).await;
                }

                let terminal = match slash_evidence_consumed(
                    provider.clone(),
                    contract_address,
                    &key,
                )
                .await
                {
                    Ok(true) => {
                        info!(e3_id = %msg.e3_id, "Skipping slash intent; evidence is already consumed on-chain");
                        true
                    }
                    Err(err) => {
                        bus.err(
                            EType::Evm,
                            anyhow::anyhow!(
                                "Error preflighting slash evidence replay: {}",
                                format_evm_error(&err)
                            ),
                        );
                        false
                    }
                    Ok(false) => match submit_slash_proposal(provider, contract_address, msg).await
                    {
                        Ok(receipt) => {
                            info!(tx=%receipt.transaction_hash, "Submitted attestation-based slash proposal on-chain");
                            true
                        }
                        Err(err) => {
                            let decoded = format_evm_error(&err);
                            let benign = decoded.contains("OperatorNotInCommittee")
                                || decoded.contains("VoterNotInCommittee")
                                || decoded.contains("DuplicateEvidence");
                            if benign {
                                // Fallback submitters expect DuplicateEvidence reverts
                                // when the primary submitter has already landed the tx.
                                // Operator/VoterNotInCommittee indicate a stale off-chain accusation
                                // (e.g. cross-E3 race) — not a node-local fault.
                                warn!("Slash submission skipped (rank {rank}): {decoded}");
                            } else {
                                bus.err(
                                    EType::Evm,
                                    anyhow::anyhow!("Error submitting slash proposal: {decoded}"),
                                );
                            }
                            benign
                        }
                    },
                };
                if let Err(error) = address
                    .send(SlashSubmissionFinished { key, terminal })
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

    fn handle(&mut self, msg: SlashSubmissionFinished, _: &mut Self::Context) -> Self::Result {
        self.submissions.finish(&msg.key, msg.terminal);
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
