// SPDX-License-Identifier: LGPL-3.0-only

//! Decryption-share collection and C6 verification.

use super::*;

impl ThresholdPlaintextAggregator {
    pub fn add_share(
        &mut self,
        party_id: u64,
        share: Vec<ArcBytes>,
        signed_decryption_proofs: Vec<SignedProofPayload>,
        ec: &EventContext<Sequenced>,
    ) -> Result<()> {
        let state = self.state.try_get()?;
        let ciphertexts = match &state {
            ThresholdPlaintextAggregatorState::Collecting(state) => {
                if state.shares.contains_key(&party_id)
                    || state.rejected_parties.contains(&party_id)
                {
                    return Ok(());
                }
                &state.ciphertext_output
            }
            ThresholdPlaintextAggregatorState::VerifyingC6(state) => {
                if state.shares.contains_key(&party_id)
                    || state.queued_shares.contains_key(&party_id)
                    || state.rejected_parties.contains(&party_id)
                {
                    return Ok(());
                }
                &state.ciphertext_output
            }
            _ => return Ok(()),
        };
        ensure!(
            !self.honest_committee_addresses.is_empty(),
            "honest committee addresses must not be empty before collecting decryption shares"
        );
        if !self.share_is_authenticated(party_id, &share, &signed_decryption_proofs, ciphertexts)? {
            warn!(
                party_id,
                "Ignoring a decryption bundle that does not match its signed party and ciphertext"
            );
            return Ok(());
        }
        self.state.try_mutate(ec, |state| {
            ThresholdPlaintextAggregation::add_share(
                state,
                party_id,
                share.clone(),
                signed_decryption_proofs.clone(),
            )
        })
    }

    pub fn handle_member_expelled(
        &mut self,
        party_id: u64,
        ec: &EventContext<Sequenced>,
    ) -> Result<()> {
        self.state.try_mutate(ec, |state| {
            ThresholdPlaintextAggregation::handle_member_expelled(state, party_id)
        })
    }

    pub(in crate::actors::threshold_plaintext_aggregator) fn c6_verification_request(
        &self,
        c6_proofs: BTreeMap<u64, Vec<SignedProofPayload>>,
    ) -> ShareVerificationDispatched {
        ShareVerificationDispatched {
            e3_id: self.e3_id.clone(),
            kind: VerificationKind::ThresholdDecryptionProofs,
            share_proofs: ThresholdPlaintextAggregation::plan_c6_dispatch(c6_proofs),
            decryption_proofs: vec![],
            pre_dishonest: BTreeSet::new(),
            params_preset: self.params_preset,
            committee_size: self.committee_size,
            lbfv_context: None,
            verification_id: None,
        }
    }

    /// Reuse a durable result, or dispatch verification for this exact batch.
    pub fn dispatch_c6_verification(
        &mut self,
        c6_proofs: BTreeMap<u64, Vec<SignedProofPayload>>,
        ec: EventContext<Sequenced>,
    ) -> Result<()> {
        let request = self.c6_verification_request(c6_proofs);
        let request_id = e3_events::EventId::hash(InterfoldEventData::from(request.clone()));
        if self
            .recovery
            .try_get()?
            .c6_outcomes
            .contains_key(&request_id.0)
        {
            return self.bus.publish(
                PlaintextVerificationResumed {
                    e3_id: self.e3_id.clone(),
                    request_id: request_id.0,
                    correlation_id: CorrelationId::new(),
                },
                ec,
            );
        }
        self.bus.publish(request, ec)
    }

    pub(in crate::actors::threshold_plaintext_aggregator) fn handle_c6_resume(
        &mut self,
        msg: TypedEvent<PlaintextVerificationResumed>,
    ) -> Result<()> {
        let (msg, ec) = msg.into_components();
        if !self.can_run_aggregation_effects()
            || msg.e3_id != self.e3_id
            || ec.source() != e3_events::EventSource::Local
        {
            return Ok(());
        }
        let Some(ThresholdPlaintextAggregatorState::VerifyingC6(batch)) = self.state.get() else {
            return Ok(());
        };
        let expected = e3_events::EventId::hash(InterfoldEventData::from(
            self.c6_verification_request(batch.c6_proofs),
        ));
        if expected.0 != msg.request_id {
            return Ok(());
        }
        self.apply_cached_c6_outcome(ec)
    }

    /// Retain local C6 results through replay and standby operation.
    pub fn handle_c6_verification_complete(
        &mut self,
        msg: TypedEvent<ShareVerificationComplete>,
    ) -> Result<()> {
        let (msg, ec) = msg.into_components();

        if msg.kind != VerificationKind::ThresholdDecryptionProofs
            || ec.source() != e3_events::EventSource::Local
            || msg.e3_id != self.e3_id
        {
            return Ok(());
        }

        if !matches!(
            self.state.get(),
            Some(
                ThresholdPlaintextAggregatorState::Collecting(_)
                    | ThresholdPlaintextAggregatorState::VerifyingC6(_)
            )
        ) {
            return Ok(());
        }
        // Each replacement batch removes at least one roster member. Retain the first result
        // per request so replay cannot replace an accepted outcome or grow this map unboundedly.
        let max_batches = self.honest_committee_addresses.len() + 1;
        self.recovery.try_mutate(&ec, |mut recovery| {
            if recovery.c6_outcomes.len() < max_batches {
                recovery
                    .c6_outcomes
                    .entry(ec.causation_id().0)
                    .or_insert(msg.dishonest_parties);
            }
            Ok(recovery)
        })?;
        self.apply_cached_c6_outcome(ec)
    }

    fn apply_cached_c6_outcome(&mut self, ec: EventContext<Sequenced>) -> Result<()> {
        if !self.can_run_aggregation_effects() {
            return Ok(());
        }
        let Some(ThresholdPlaintextAggregatorState::VerifyingC6(state)) = self.state.get() else {
            return Ok(());
        };
        let request_id = e3_events::EventId::hash(InterfoldEventData::from(
            self.c6_verification_request(state.c6_proofs.clone()),
        ));
        let Some(outcome) = self
            .recovery
            .try_get()?
            .c6_outcomes
            .get(&request_id.0)
            .cloned()
        else {
            return Ok(());
        };
        self.apply_c6_verification_outcome(state, outcome, ec)
    }

    fn apply_c6_verification_outcome(
        &mut self,
        state: VerifyingC6,
        outcome: BTreeSet<u64>,
        ec: EventContext<Sequenced>,
    ) -> Result<()> {
        let mut dishonest_parties = state.rejected_parties.clone();
        dishonest_parties.extend(outcome);
        if !dishonest_parties.is_empty() {
            warn!(
                "C6 verification: {} dishonest parties filtered: {:?}",
                dishonest_parties.len(),
                dishonest_parties
            );
        }

        let mut honest_shares: Vec<(u64, Vec<ArcBytes>)> = state
            .shares
            .iter()
            .filter(|(id, _)| !dishonest_parties.contains(id))
            .map(|(id, s)| (*id, s.clone()))
            .collect();

        // Recheck the saved share bytes against the verified proof before computation.
        let share_mismatch_parties =
            ThresholdPlaintextAggregation::verify_shares_match_c6_commitments(
                self.params_preset,
                &honest_shares,
                &state.c6_proofs,
            );
        if !share_mismatch_parties.is_empty() {
            warn!(
                "C6 share-commitment mismatch for {} parties: {:?} — excluding from aggregation",
                share_mismatch_parties.len(),
                share_mismatch_parties,
            );

            dishonest_parties.extend(&share_mismatch_parties);
            honest_shares.retain(|(id, _)| !share_mismatch_parties.contains(id));
        }

        if honest_shares.len() <= state.threshold_m as usize {
            return self.retry_c6_with_backups(state, dishonest_parties, ec);
        }

        info!(
            "C6 verification passed: {} honest parties, transitioning to Computing",
            honest_shares.len(),
        );

        // Keep the same ascending party order for shares and recursive proof inputs.
        let honest_c6: Vec<(u64, Vec<Proof>)> = state
            .c6_proofs
            .iter()
            .filter(|(id, _)| !dishonest_parties.contains(id))
            .map(|(id, signed)| {
                (
                    *id,
                    signed.iter().map(|s| s.payload.proof.clone()).collect(),
                )
            })
            .collect();

        self.recovery.try_mutate(&ec, |mut recovery| {
            recovery.honest_c6_proofs = honest_c6.clone();
            recovery.last_ec = Some(ec.clone());
            Ok(recovery)
        })?;

        let computing = Computing {
            shares: honest_shares,
            ciphertext_output: state.ciphertext_output,
            threshold_m: state.threshold_m,
            threshold_n: state.threshold_n,
            params: state.params,
        };
        // A failed publication leaves VerifyingC6 intact, so the same batch can retry.
        self.dispatch_threshold_decryption(&computing, ec.clone())?;
        self.pending.honest_c6_proofs_for_agg = Some(honest_c6);
        self.state.try_mutate(&ec, |_| {
            Ok(ThresholdPlaintextAggregatorState::Computing(computing))
        })?;
        self.pending.last_ec = Some(ec);
        Ok(())
    }

    fn retry_c6_with_backups(
        &mut self,
        state: VerifyingC6,
        dishonest_parties: BTreeSet<u64>,
        ec: EventContext<Sequenced>,
    ) -> Result<()> {
        let available = self
            .committee_addresses
            .iter()
            .enumerate()
            .filter(|(party, address)| {
                self.honest_committee_addresses.contains(address)
                    && !dishonest_parties.contains(&(*party as u64))
            })
            .count();
        if available <= state.threshold_m as usize {
            return self.fail_decryption_round(ec);
        }
        self.state.try_mutate(&ec, |_| {
            Ok(ThresholdPlaintextAggregation::retry_collection(
                state,
                dishonest_parties,
            ))
        })?;
        if let Some(ThresholdPlaintextAggregatorState::VerifyingC6(next)) = self.state.get() {
            self.publish_inputs_ready(ec.clone())?;
            self.dispatch_c6_verification(next.c6_proofs, ec)?;
        }
        Ok(())
    }

    pub(super) fn dispatch_threshold_decryption(
        &mut self,
        state: &Computing,
        ec: EventContext<Sequenced>,
    ) -> Result<()> {
        let correlation_id = CorrelationId::new();
        let request = ComputeRequest::trbfv(
            TrBFVRequest::CalculateThresholdDecryption(CalculateThresholdDecryptionRequest {
                ciphertexts: state.ciphertext_output.clone(),
                trbfv_config: TrBFVConfig::new(
                    state.params.clone(),
                    state.threshold_n,
                    state.threshold_m,
                ),
                d_share_polys: state.shares.clone(),
            }),
            correlation_id,
            self.e3_id.clone(),
        );
        self.bus.publish(request, ec)?;
        self.pending.threshold_decryption_correlation = Some(correlation_id);
        Ok(())
    }
}
