// SPDX-License-Identifier: LGPL-3.0-only

//! Incoming accusation validation and local vote decisions.

use super::*;

impl AccusationVoting {
    /// Called when we receive an accusation from another node via gossip.
    pub(crate) fn on_accusation_received(
        &mut self,
        accusation: ProofFailureAccusation,
        ec: &EventContext<Sequenced>,
    ) -> Vec<VoteAction> {
        let mut actions = Vec::new();
        self.on_accusation_received_inner(accusation, ec, &mut actions);
        actions
    }

    pub(super) fn on_accusation_received_inner(
        &mut self,
        accusation: ProofFailureAccusation,
        ec: &EventContext<Sequenced>,
        actions: &mut Vec<VoteAction>,
    ) {
        let accusation = match self.admit_accusation(accusation) {
            Ok(accusation) => accusation.into_inner(),
            Err(rejection) => {
                rejection.log();
                return;
            }
        };

        let accusation_id = Self::accusation_id(&accusation);

        // Peers that detect the same fault accuse with their own windows; converge on the latest.
        if self.pending.contains_key(&accusation_id) {
            self.adopt_later_vote_window(accusation_id, accusation, ec, actions);
            return;
        }

        // Determine our position based on our local verification state.
        let key = (accusation.accused, accusation.proof_type);
        let our_data_hash = if let Some(received) = self.received_data.get(&key) {
            if received.verification_passed {
                info!(
                    "Local verification of {:?} from {} passed — abstaining \
                     (no disagreement vote on the wire)",
                    accusation.proof_type, accusation.accused
                );
                return;
            }
            received.data_hash
        } else if let Some(ref forwarded) = accusation.signed_payload {
            // C3a/C3b case: we didn't receive this proof directly.
            let forwarded_valid = match forwarded.recover_address() {
                Ok(addr) => {
                    if addr != accusation.accused {
                        warn!(
                            "Forwarded C3a/C3b payload signer {} != accused {} — cannot verify",
                            addr, accusation.accused
                        );
                        false
                    } else if forwarded.payload.e3_id != self.e3_id {
                        warn!("Forwarded C3a/C3b payload e3_id mismatch — cannot verify");
                        false
                    } else {
                        let expected = forwarded.payload.proof_type.circuit_names();
                        expected.contains(&forwarded.payload.proof.circuit)
                    }
                }
                Err(e) => {
                    warn!("Forwarded C3a/C3b payload signature invalid: {e} — cannot verify");
                    false
                }
            };

            if !forwarded_valid {
                // Can't trust the forwarded proof — abstain
                return;
            }

            // Bind the forwarded proof to the accusation.
            if forwarded.payload.proof_type != accusation.proof_type {
                warn!(
                    "Forwarded C3a/C3b proof_type {:?} != accusation proof_type {:?} — cannot verify",
                    forwarded.payload.proof_type, accusation.proof_type
                );
                return;
            }
            let computed_hash = Self::compute_payload_hash(forwarded);
            if computed_hash != accusation.data_hash {
                warn!(
                    "Forwarded C3a/C3b data_hash mismatch (len {} vs {}) — cannot verify",
                    computed_hash.len(),
                    accusation.data_hash.len()
                );
                return;
            }

            let data_hash = Self::compute_payload_hash(forwarded);
            let evidence: Bytes = (
                Bytes::copy_from_slice(&forwarded.payload.proof.data),
                Bytes::copy_from_slice(&forwarded.payload.proof.public_signals),
            )
                .abi_encode()
                .into();
            let accused_party_id = accusation.accused_party_id;
            let forwarded_clone = forwarded.clone();

            let committee_size = match CiphernodesCommitteeSize::from_threshold(
                self.circuit_threshold_t,
                self.committee_n,
            ) {
                Ok(c) => c,
                Err(e) => {
                    warn!("Cannot derive committee size for ZK re-verification: {e}");
                    return;
                }
            };

            // Create PendingAccusation without our vote — it arrives after ZK completes.
            actions.push(VoteAction::StartTimeout(accusation_id));
            self.pending.insert(
                accusation_id,
                PendingAccusation {
                    accusation,
                    votes_for: Vec::new(),
                    ec: ec.clone(),
                },
            );

            // Replay any buffered votes
            if let Some(buffered) = self.buffered_votes.remove(&accusation_id) {
                for vote in buffered {
                    self.on_vote_received_inner(vote, ec, actions);
                }
            }

            // Dispatch ZK re-verification
            let correlation_id = CorrelationId::new();
            self.pending_reverifications.insert(
                correlation_id,
                PendingReVerification {
                    accusation_id,
                    data_hash,
                    accused: key.0,
                    proof_type: key.1,
                    evidence,
                },
            );

            let party_proof = PartyProofsToVerify {
                sender_party_id: accused_party_id,
                signed_proofs: vec![forwarded_clone],
            };
            let request = ComputeRequest::zk(
                ZkRequest::ReverifyAccusedProof(VerifyShareProofsRequest {
                    party_proofs: vec![party_proof],
                    params_preset: self.params_preset,
                    committee_size,
                }),
                correlation_id,
                self.e3_id.clone(),
            );

            actions.push(VoteAction::DispatchZk {
                request,
                ec: ec.clone(),
                correlation_id,
            });

            // Vote deferred — return without falling through to the normal vote path
            return;
        } else {
            // We don't have the data and no payload was forwarded — abstain
            info!(
                "No local data for accused {} proof {:?} — abstaining from vote",
                accusation.accused, accusation.proof_type
            );
            return;
        };

        // We saw the proof fail locally — agree with the accusation.
        let mut vote = AccusationVote {
            e3_id: self.e3_id.clone(),
            accusation_id,
            voter: self.my_address,
            data_hash: our_data_hash,
            issued_at: accusation.issued_at,
            deadline: accusation.deadline,
            signature: ArcBytes::default(),
        };
        match self.sign_vote_digest(&vote) {
            Ok(sig) => vote.signature = ArcBytes::from_bytes(&sig),
            Err(err) => {
                error!("Failed to sign AccusationVote: {err}");
                return;
            }
        }

        info!(
            "Agreeing with accusation against {} for {:?}",
            accusation.accused, accusation.proof_type
        );

        // Broadcast vote via gossip
        actions.push(VoteAction::PublishVote {
            vote: vote.clone(),
            ec: ec.clone(),
        });

        // Start timeout for this accusation
        actions.push(VoteAction::StartTimeout(accusation_id));

        // Record in pending
        let pending = PendingAccusation {
            accusation,
            votes_for: vec![vote],
            ec: ec.clone(),
        };
        self.pending.insert(accusation_id, pending);

        // Replay any votes that arrived before this accusation
        if let Some(buffered) = self.buffered_votes.remove(&accusation_id) {
            for vote in buffered {
                self.on_vote_received_inner(vote, ec, actions);
            }
        }

        // Check quorum
        self.check_quorum(accusation_id, ec, actions);
    }

    /// Moves a pending accusation to a peer's later vote window, re-signing our vote,
    /// so every vote in the quorum shares the one window the contract verifies.
    fn adopt_later_vote_window(
        &mut self,
        accusation_id: [u8; 32],
        incoming: ProofFailureAccusation,
        ec: &EventContext<Sequenced>,
        actions: &mut Vec<VoteAction>,
    ) {
        let Some(pending) = self.pending.get(&accusation_id) else {
            return;
        };
        let held = &pending.accusation;
        // Only a later start and end from a peer other than the accused moves the window, and
        // each accuser moves it at most once: no one can shorten it or keep resetting the votes.
        if incoming.issued_at <= held.issued_at
            || incoming.deadline <= held.deadline
            || !self.window_movers.insert((accusation_id, incoming.accuser))
        {
            return;
        }
        let mut own_vote = pending
            .votes_for
            .iter()
            .find(|v| v.voter == self.my_address)
            .cloned();
        if let Some(vote) = own_vote.as_mut() {
            vote.issued_at = incoming.issued_at;
            vote.deadline = incoming.deadline;
            match self.sign_vote_digest(vote) {
                Ok(sig) => vote.signature = ArcBytes::from_bytes(&sig),
                Err(err) => {
                    error!("Failed to re-sign AccusationVote: {err}");
                    return;
                }
            }
            actions.push(VoteAction::PublishVote {
                vote: vote.clone(),
                ec: ec.clone(),
            });
        }
        let pending = self.pending.get_mut(&accusation_id).expect("checked above");
        pending.accusation = incoming;
        pending.votes_for = own_vote.into_iter().collect();
        // The adopted window starts a new vote collection with a full timeout.
        actions.push(VoteAction::CancelTimeout(accusation_id));
        actions.push(VoteAction::StartTimeout(accusation_id));

        // Replay peer votes that were signed for this window before we adopted it
        if let Some(buffered) = self.buffered_votes.remove(&accusation_id) {
            for vote in buffered {
                self.on_vote_received_inner(vote, ec, actions);
            }
        }
        self.check_quorum(accusation_id, ec, actions);
    }
}
