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
        // Collection closes at `VerifyingC6`. A share that arrives after that is a duplicate of
        // one already collected, not a fault: peers re-announce their in-flight document
        // pointers whenever a node (re)subscribes to the gossip topic, so a restart anywhere in
        // the committee re-delivers every decryption share to aggregators that have moved on.
        // Without this guard `TryInto<Collecting>` fails and the duplicate surfaces as
        // `InterfoldError("PlaintextState was expected to be Collecting but it was not.")` on a
        // node doing nothing wrong — the same defect that hit `add_keyshare` on the DKG side.
        if !matches!(
            self.state.get().as_ref(),
            Some(ThresholdPlaintextAggregatorState::Collecting(_))
        ) {
            debug!(
                party_id,
                "Ignoring a decryption share that arrived after collection closed"
            );
            return Ok(());
        }
        let required_shares = self.aggregated_committee_n();
        ensure!(
            required_shares > 0,
            "honest committee addresses must not be empty before collecting decryption shares"
        );
        self.state.try_mutate(ec, |state| {
            ThresholdPlaintextAggregation::add_share(
                state,
                party_id,
                share.clone(),
                signed_decryption_proofs.clone(),
                required_shares,
            )
        })
    }

    pub fn handle_member_expelled(
        &mut self,
        party_id: u64,
        ec: &EventContext<Sequenced>,
    ) -> Result<()> {
        let required_shares = self.aggregated_committee_n();
        self.state.try_mutate(ec, |state| {
            ThresholdPlaintextAggregation::handle_member_expelled(state, party_id, required_shares)
        })
    }

    /// Dispatch C6 proof verification through ShareVerificationActor.
    pub fn dispatch_c6_verification(
        &mut self,
        c6_proofs: BTreeMap<u64, Vec<SignedProofPayload>>,
        ec: EventContext<Sequenced>,
    ) -> Result<()> {
        let party_proofs = ThresholdPlaintextAggregation::plan_c6_dispatch(c6_proofs);

        self.bus.publish(
            ShareVerificationDispatched {
                e3_id: self.e3_id.clone(),
                kind: VerificationKind::ThresholdDecryptionProofs,
                share_proofs: party_proofs,
                decryption_proofs: vec![],
                pre_dishonest: BTreeSet::new(),
                params_preset: self.params_preset,
                committee_size: self.committee_size,
            },
            ec,
        )?;
        Ok(())
    }

    /// Handle ShareVerificationComplete for C6: filter dishonest parties, transition to Computing.
    pub fn handle_c6_verification_complete(
        &mut self,
        msg: TypedEvent<ShareVerificationComplete>,
    ) -> Result<()> {
        let (msg, ec) = msg.into_components();

        if msg.kind != VerificationKind::ThresholdDecryptionProofs {
            return Ok(());
        }

        if msg.e3_id != self.e3_id {
            return Ok(());
        }

        let state: VerifyingC6 = self
            .state
            .get()
            .ok_or(anyhow!("Could not get state"))?
            .try_into()?;

        let mut dishonest_parties = msg.dishonest_parties.clone();
        if !dishonest_parties.is_empty() {
            warn!(
                e3_id = %self.e3_id,
                "C6 verification: {} dishonest parties filtered: {:?}",
                dishonest_parties.len(),
                dishonest_parties
            );
        }

        // Filter shares to only honest parties
        let mut honest_shares: Vec<(u64, Vec<ArcBytes>)> = state
            .shares
            .iter()
            .filter(|(id, _)| !dishonest_parties.contains(id))
            .map(|(id, s)| (*id, s.clone()))
            .collect();

        if honest_shares.len() <= state.threshold_m as usize {
            warn!(
                e3_id = %self.e3_id,
                "Not enough honest shares after C6 verification: {} honest shares, {} required",
                honest_shares.len(),
                state.threshold_m + 1
            );
            return self.fail_decryption_round(ec);
        }

        // Verify each honest party's raw decryption share matches the
        // d_commitment attested by their verified C6 proof. Catches the attack
        // where a node sends a valid C6 proof for share d_A but broadcasts
        // different bytes d_B.
        let share_mismatch_parties =
            ThresholdPlaintextAggregation::verify_shares_match_c6_commitments(
                self.params_preset,
                &honest_shares,
                &state.c6_proofs,
            );
        if !share_mismatch_parties.is_empty() {
            warn!(
                e3_id = %self.e3_id,
                "C6 share-commitment mismatch for {} parties: {:?} — excluding from aggregation",
                share_mismatch_parties.len(),
                share_mismatch_parties,
            );

            dishonest_parties.extend(&share_mismatch_parties);
            honest_shares.retain(|(id, _)| !share_mismatch_parties.contains(id));
            if honest_shares.len() <= state.threshold_m as usize {
                warn!(
                    e3_id = %self.e3_id,
                    "Not enough honest shares after d_commitment check: {} honest, {} required",
                    honest_shares.len(),
                    state.threshold_m + 1
                );
                return self.fail_decryption_round(ec);
            }
        }

        info!(
            "C6 verification passed: {} honest parties, transitioning to Computing",
            honest_shares.len(),
        );

        // Collect honest C6 inner proofs (from signed payloads) for DecryptionAggregation.
        // BTreeMap iteration yields ascending party_id, matching the slot layout
        // used by honest_shares above and enforced by decryption_aggregator.nr.
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

        // Publish ComputeRequest before transitioning state so a publish
        // failure leaves us in VerifyingC6 (retryable) rather than
        // Computing (no retry path).
        // TrBFV scheme size stays N (`threshold_n`); only the share roster is restricted to the
        // H canonical honest parties in `PublicKeyAggregated` (see
        // `node_owns_aggregated_pk_party_slot`).
        let trbfv_config =
            TrBFVConfig::new(state.params.clone(), state.threshold_n, state.threshold_m);

        let correlation_id = CorrelationId::new();
        let event = ComputeRequest::trbfv(
            TrBFVRequest::CalculateThresholdDecryption(CalculateThresholdDecryptionRequest {
                ciphertexts: state.ciphertext_output.clone(),
                trbfv_config,
                d_share_polys: honest_shares.clone(),
            }),
            correlation_id,
            self.e3_id.clone(),
        );
        self.bus.publish(event, ec.clone())?;

        self.pending.honest_c6_proofs_for_agg = Some(honest_c6);
        self.pending.threshold_decryption_correlation = Some(correlation_id);

        self.state.try_mutate(&ec, |_| {
            Ok(ThresholdPlaintextAggregatorState::Computing(Computing {
                shares: honest_shares,
                ciphertext_output: state.ciphertext_output,
                threshold_m: state.threshold_m,
                threshold_n: state.threshold_n,
                params: state.params,
            }))
        })?;

        self.pending.last_ec = Some(ec.clone());

        Ok(())
    }
}
