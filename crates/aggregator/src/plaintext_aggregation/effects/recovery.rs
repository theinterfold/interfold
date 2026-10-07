// SPDX-License-Identifier: LGPL-3.0-only

//! Restart recovery for persisted plaintext aggregation phases.

use super::*;
use crate::TrBfvPlaintextRepositoryFactory;
use e3_data::{AutoPersist, Repositories};
use e3_events::{AggregateId, EventStoreQueryBy, EventStoreQueryResponse, SeqAgg};
use std::collections::HashMap;

/// Read the full E3 history, including events covered by snapshot cursors.
pub(crate) async fn visit_plaintext_history(
    store: &Recipient<EventStoreQueryBy<SeqAgg>>,
    e3_id: &E3id,
    mut visit: impl FnMut(&InterfoldEvent) -> Result<()>,
) -> Result<()> {
    visit_plaintext_history_range(store, e3_id, 1..=u64::MAX, |event| {
        std::future::ready(visit(&event))
    })
    .await
}

pub(crate) async fn visit_plaintext_history_range<F, Fut>(
    store: &Recipient<EventStoreQueryBy<SeqAgg>>,
    e3_id: &E3id,
    range: std::ops::RangeInclusive<u64>,
    mut visit: F,
) -> Result<()>
where
    F: FnMut(InterfoldEvent) -> Fut,
    Fut: std::future::Future<Output = Result<()>>,
{
    let aggregate = AggregateId::from_chain_id(Some(e3_id.chain_id()));
    let mut cursor = *range.start();
    while cursor <= *range.end() {
        let (recipient, response) = e3_utils::actix::channel::oneshot::<EventStoreQueryResponse>();
        store
            .send(
                EventStoreQueryBy::<SeqAgg>::new(
                    CorrelationId::new(),
                    HashMap::from([(aggregate, cursor)]),
                    recipient,
                )
                .with_limit(1024)
                .with_max_bytes(16 * 1024 * 1024),
            )
            .await?;
        let events = response.await?.into_events()?;
        if events.is_empty() {
            return Ok(());
        }
        for event in events {
            if event.seq() > *range.end() {
                return Ok(());
            }
            ensure!(
                event.aggregate_id() == aggregate && event.seq() == cursor,
                "plaintext recovery event-store sequence gap"
            );
            cursor += 1;
            if event.get_e3_id().as_ref() == Some(e3_id) {
                visit(event).await?;
            }
        }
    }
    Ok(())
}

impl ThresholdPlaintextAggregator {
    fn recovered_c6_is_valid(&mut self, ciphertexts: &[ArcBytes]) -> Result<bool> {
        let proofs = self.recovery.try_get()?.honest_c6_proofs;
        for (party, proofs) in &proofs {
            if proofs.is_empty()
                || proofs.len() != ciphertexts.len()
                || !proofs
                    .iter()
                    .zip(ciphertexts)
                    .all(|(proof, ciphertext)| self.c6_has_canonical_domain(proof, ciphertext))
            {
                warn!(
                    party_id = party,
                    "Discarding retained C6 proofs with a noncanonical domain"
                );
                return Ok(false);
            }
        }
        let state = self.state.try_get()?;
        let shares = match state {
            ThresholdPlaintextAggregatorState::Collecting(state) => {
                return Ok(!state.shares.is_empty()
                    && state.shares.len() == state.c6_proofs.len()
                    && state.shares.iter().all(|(party, shares)| {
                        state.c6_proofs.get(party).is_some_and(|proofs| {
                            self.share_is_authenticated(*party, shares, proofs, ciphertexts)
                                .unwrap_or(false)
                        })
                    }));
            }
            ThresholdPlaintextAggregatorState::VerifyingC6(state) => {
                return Ok(state.shares.len() == state.c6_proofs.len()
                    && state.shares.iter().all(|(party, shares)| {
                        state.c6_proofs.get(party).is_some_and(|proofs| {
                            self.share_is_authenticated(*party, shares, proofs, ciphertexts)
                                .unwrap_or(false)
                        })
                    })
                    && state.queued_shares.iter().all(|(party, queued)| {
                        self.share_is_authenticated(
                            *party,
                            &queued.share,
                            &queued.proofs,
                            ciphertexts,
                        )
                        .unwrap_or(false)
                    }));
            }
            ThresholdPlaintextAggregatorState::Computing(state) => state.shares,
            ThresholdPlaintextAggregatorState::GeneratingC7Proof(state) => state.shares,
            ThresholdPlaintextAggregatorState::Complete(state) => state.shares,
        };
        Ok(!shares.is_empty()
            && shares.len() == proofs.len()
            && shares
                .iter()
                .zip(&proofs)
                .all(|((party, shares), (proof_party, proofs))| {
                    party == proof_party
                        && shares.len() == ciphertexts.len()
                        && proofs.len() == ciphertexts.len()
                }))
    }

    /// Rebuild invalid retained work from signed history before replay or effects can resume it.
    pub(crate) async fn repair_recovered_state(
        &mut self,
        initial: ThresholdPlaintextAggregatorState,
        store: &Recipient<EventStoreQueryBy<SeqAgg>>,
        repositories: &Repositories,
    ) -> Result<()> {
        let collecting: Collecting = initial.clone().try_into()?;
        if self.recovered_c6_is_valid(&collecting.ciphertext_output)? {
            let state = match self.state.try_get()? {
                ThresholdPlaintextAggregatorState::GeneratingC7Proof(state) => state,
                ThresholdPlaintextAggregatorState::Complete(state) => GeneratingC7Proof {
                    threshold_m: collecting.threshold_m,
                    threshold_n: collecting.threshold_n,
                    shares: state.shares,
                    plaintext: state.decrypted,
                },
                _ => return Ok(()),
            };
            let recovery = self.recovery.try_get()?;
            if recovery.c7_proofs.as_ref().is_some_and(|proofs| {
                c7_proofs_match_batch(
                    proofs,
                    &recovery.honest_c6_proofs,
                    &state.plaintext,
                    state.threshold_m as usize + 1,
                )
            }) {
                return Ok(());
            }
            // Keep canonical C6 work, but regenerate C7 and the final proof for this batch.
            self.state.stage();
            self.recovery.stage();
            self.state.try_mutate_without_context(|_| {
                Ok(ThresholdPlaintextAggregatorState::GeneratingC7Proof(state))
            })?;
            self.recovery.try_mutate_without_context(|mut recovery| {
                recovery.c7_proofs = None;
                recovery.decryption_aggregator_proofs = None;
                Ok(recovery)
            })?;
            self.pending.c7_proofs_pending = None;
            self.pending.decryption_aggregator_proofs = None;
            self.pending.decryption_aggregation_correlation = None;
            self.persist_repaired_state(repositories).await?;
            return Ok(());
        }
        warn!(e3_id = %self.e3_id, "Rebuilding plaintext work with canonical C6 shares");
        let mut retained = BTreeMap::new();
        let rejected = match self.state.try_get()? {
            ThresholdPlaintextAggregatorState::Collecting(state) => {
                for (party, share) in state.shares {
                    if let Some(proofs) = state.c6_proofs.get(&party) {
                        retained.insert(party, (share, proofs.clone()));
                    }
                }
                state.rejected_parties
            }
            ThresholdPlaintextAggregatorState::VerifyingC6(state) => {
                for (party, share) in state.shares {
                    if let Some(proofs) = state.c6_proofs.get(&party) {
                        retained.insert(party, (share, proofs.clone()));
                    }
                }
                for (party, queued) in state.queued_shares {
                    retained
                        .entry(party)
                        .or_insert((queued.share, queued.proofs));
                }
                state.rejected_parties
            }
            _ => BTreeSet::new(),
        };
        self.state.stage();
        self.recovery.stage();
        self.state.try_mutate_without_context(|_| Ok(initial))?;
        let ec = self.recovery.try_get()?.last_ec.ok_or_else(|| {
            anyhow!(
                "plaintext recovery for E3 {} has no event context",
                self.e3_id
            )
        })?;
        self.recovery.try_mutate_without_context(|_| {
            Ok(crate::new_threshold_plaintext_recovery(ec.clone()))
        })?;
        self.pending = PendingDecryptionWork {
            last_ec: Some(ec.clone()),
            ..Default::default()
        };
        self.started_as_aggregator = false;
        for party in rejected {
            self.handle_member_expelled(party, &ec)?;
        }
        let id = self.e3_id.clone();
        visit_plaintext_history(store, &id, |event| {
            match event.get_data() {
                InterfoldEventData::DecryptionshareCreated(share)
                    if self.node_owns_aggregated_pk_party_slot(&share.node, share.party_id) =>
                {
                    self.add_share(
                        share.party_id,
                        share.decryption_share.clone(),
                        share.signed_decryption_proofs.clone(),
                        event.get_ctx(),
                    )?;
                }
                InterfoldEventData::CommitteeMemberExpelled(data) => {
                    if let Some(party) = data.party_id {
                        self.handle_member_expelled(party, event.get_ctx())?;
                    }
                }
                InterfoldEventData::CommitteeMemberExcluded(data) => {
                    if let Some(party) = data.party_id {
                        self.handle_member_expelled(party, event.get_ctx())?;
                    }
                }
                _ => {}
            }
            Ok(())
        })
        .await?;
        for (party, (shares, proofs)) in retained {
            self.add_share(party, shares, proofs, &ec)?;
        }
        // Historical event contexts precede the snapshot watermark. Save the repaired values
        // without those contexts before the actor starts receiving the replay suffix.
        self.persist_repaired_state(repositories).await
    }

    async fn persist_repaired_state(&mut self, repositories: &Repositories) -> Result<()> {
        let state_repo = repositories.trbfv_plaintext(&self.e3_id);
        let recovery_repo = repositories.trbfv_plaintext_recovery(&self.e3_id);
        state_repo.write_sync(&self.state.try_get()?).await?;
        recovery_repo.write_sync(&self.recovery.try_get()?).await?;
        self.state = state_repo.load().await?;
        self.recovery = recovery_repo.load().await?;
        Ok(())
    }

    pub(in crate::actors::threshold_plaintext_aggregator) fn resume_in_flight_work(
        &mut self,
        effects_context: EventContext<Sequenced>,
    ) -> Result<()> {
        // The active aggregator resumes any phase. A demoted node resumes only the work that it
        // started, which is every phase after C6 verification.
        let started = self.state.get().as_ref().is_some_and(aggregation_started);
        if !(self.can_run_aggregation_effects()
            || (started && self.can_continue_aggregation_effects()))
        {
            return Ok(());
        }
        self.mark_started_as_aggregator();
        let recovery = self.recovery.try_get()?;
        ensure!(
            recovery.schema_version == THRESHOLD_PLAINTEXT_RECOVERY_SCHEMA_VERSION,
            "unsupported plaintext recovery schema version {} for E3 {}",
            recovery.schema_version,
            self.e3_id
        );
        let causal_context = recovery.last_ec.unwrap_or(effects_context.clone());
        self.pending.last_ec = Some(causal_context.clone());

        let Some(state) = self.state.get() else {
            return Ok(());
        };
        match state {
            ThresholdPlaintextAggregatorState::Collecting(_) => Ok(()),
            ThresholdPlaintextAggregatorState::VerifyingC6(state) => {
                self.dispatch_c6_verification(state.c6_proofs, effects_context)
            }
            ThresholdPlaintextAggregatorState::Computing(state) => {
                ensure!(
                    !self.proof_aggregation_enabled
                        || self.pending.honest_c6_proofs_for_agg.is_some(),
                    "plaintext aggregation for E3 {} cannot resume threshold decryption without verified C6 proofs",
                    self.e3_id
                );
                self.dispatch_threshold_decryption(&state, causal_context)
            }
            ThresholdPlaintextAggregatorState::GeneratingC7Proof(state) => {
                self.pending.decryption_aggregation_correlation = None;
                if self.pending.c7_proofs_pending.is_none() {
                    self.dispatch_c7_proof_request(
                        state.shares,
                        state.plaintext,
                        state.threshold_m,
                        state.threshold_n,
                        causal_context.clone(),
                    )?;
                }
                self.maybe_start_decryption_aggregation(&causal_context)?;
                self.try_publish_complete()
            }
            ThresholdPlaintextAggregatorState::Complete(state) => {
                let proofs = self
                    .pending
                    .decryption_aggregator_proofs
                    .clone()
                    .ok_or_else(|| {
                        anyhow!(
                            "plaintext aggregation for E3 {} completed without a recovery publication record",
                            self.e3_id
                        )
                    })?;
                self.bus.publish(
                    PlaintextAggregated {
                        e3_id: self.e3_id.clone(),
                        decrypted_output: format_decrypted_plaintext(&state.decrypted),
                        decryption_aggregator_proofs: proofs,
                    },
                    causal_context,
                )
            }
        }
    }
}
