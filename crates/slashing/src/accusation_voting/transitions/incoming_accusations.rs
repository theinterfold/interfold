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
        // Ignore accusations for other E3s
        if accusation.e3_id != self.e3_id {
            return;
        }

        let now = self.clock.unix_now_secs();
        if !Self::is_peer_deadline_acceptable(
            accusation.issued_at,
            accusation.deadline,
            now,
            self.vote_validity_secs,
            self.accusation_deadline_skew_secs,
        ) {
            let max_deadline = now
                .saturating_add(self.vote_validity_secs)
                .saturating_add(self.accusation_deadline_skew_secs);
            warn!(
                e3_id = %self.e3_id,
                "Ignoring accusation from {} — deadline {} outside local validity window \
                 (now={}, vote_validity_secs={}, skew_secs={}, max_accepted_deadline={})",
                accusation.accuser,
                accusation.deadline,
                now,
                self.vote_validity_secs,
                self.accusation_deadline_skew_secs,
                max_deadline
            );
            return;
        }

        // Verify accuser is in committee
        if !self.committee.contains(&accusation.accuser) {
            warn!(
                e3_id = %self.e3_id,
                "Ignoring accusation from non-committee member {}",
                accusation.accuser
            );
            return;
        }

        // Verify accused is a committee member (defense-in-depth)
        if !self.committee.contains(&accusation.accused) {
            warn!(
                e3_id = %self.e3_id,
                "Ignoring accusation against non-committee member {}",
                accusation.accused
            );
            return;
        }

        // Ignore our own accusations (we already voted)
        if accusation.accuser == self.my_address {
            return;
        }

        // Verify accuser's ECDSA signature
        if !self.verify_accusation_signature(&accusation) {
            warn!(
                e3_id = %self.e3_id,
                "Invalid signature on accusation from {} — ignoring",
                accusation.accuser
            );
            return;
        }

        let accusation_id = Self::accusation_id(&accusation);

        // A duplicate of an accusation we already hold. The id is keyed on
        // `(chain, e3, accused, proof_type)`, so two honest nodes that both saw the fault
        // and accused a few seconds apart produce the same id with *different* signed
        // `(issued_at, deadline)` windows. Every vote is bound to one window and the
        // contract rejects a mixed set, so the committee must converge on a single window
        // or a 3-of-4 quorum can never form. Converge deterministically on the later
        // window; if the peer's wins, adopt it and re-sign our own vote against it.
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
                            e3_id = %self.e3_id,
                            "Forwarded C3a/C3b payload signer {} != accused {} — cannot verify",
                            addr, accusation.accused
                        );
                        false
                    } else if forwarded.payload.e3_id != self.e3_id {
                        warn!(
                            e3_id = %self.e3_id,
                            "Forwarded C3a/C3b payload e3_id mismatch — cannot verify"
                        );
                        false
                    } else {
                        let expected = forwarded.payload.proof_type.circuit_names();
                        expected.contains(&forwarded.payload.proof.circuit)
                    }
                }
                Err(e) => {
                    warn!(
                        e3_id = %self.e3_id,
                        "Forwarded C3a/C3b payload signature invalid: {e} — cannot verify"
                    );
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
                    e3_id = %self.e3_id,
                    "Forwarded C3a/C3b proof_type {:?} != accusation proof_type {:?} — cannot verify",
                    forwarded.payload.proof_type, accusation.proof_type
                );
                return;
            }
            let computed_hash = Self::compute_payload_hash(forwarded);
            if computed_hash != accusation.data_hash {
                warn!(
                    e3_id = %self.e3_id,
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
                    warn!(
                        e3_id = %self.e3_id,
                        "Cannot derive committee size for ZK re-verification: {e}"
                    );
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
                ZkRequest::VerifyShareProofs(VerifyShareProofsRequest {
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
                error!(
                    e3_id = %self.e3_id,
                    "Failed to sign AccusationVote: {err}"
                );
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

    /// Converge a pending accusation onto the winning vote window when a peer's duplicate
    /// arrives. See `on_accusation_received_inner` for why this is needed.
    ///
    /// Votes already collected against the losing window are dropped: they cannot appear
    /// in the same attestation as votes against the winning window. Their voters will
    /// re-vote on receiving the winning accusation, exactly as this node does here.
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
        let held_window = (held.issued_at, held.deadline);
        let incoming_window = (incoming.issued_at, incoming.deadline);
        // Same rule as the vote-side check in `on_vote_received_inner`, which only sees the
        // window: the later window wins. Equal windows are a plain duplicate.
        if incoming_window <= held_window {
            return;
        }

        info!(
            "Adopting the later vote window (issued_at {} → {}, accuser {}) for accusation \
             against {} {:?}; re-signing own vote",
            held.issued_at,
            incoming.issued_at,
            incoming.accuser,
            incoming.accused,
            incoming.proof_type
        );

        // Our position on the fault has not changed; only the window we sign it against.
        let Some(our_vote) = pending
            .votes_for
            .iter()
            .find(|v| v.voter == self.my_address)
        else {
            // We have not voted yet (pending a C3a/C3b re-verification); just switch the
            // window so the eventual vote signs against it.
            let pending = self.pending.get_mut(&accusation_id).expect("checked above");
            pending.accusation = incoming;
            pending.votes_for.clear();
            return;
        };
        let mut vote = AccusationVote {
            e3_id: self.e3_id.clone(),
            accusation_id,
            voter: self.my_address,
            data_hash: our_vote.data_hash,
            issued_at: incoming.issued_at,
            deadline: incoming.deadline,
            signature: ArcBytes::default(),
        };
        match self.sign_vote_digest(&vote) {
            Ok(sig) => vote.signature = ArcBytes::from_bytes(&sig),
            Err(err) => {
                error!(
                    e3_id = %self.e3_id,
                    "Failed to re-sign AccusationVote for the adopted window: {err}"
                );
                return;
            }
        }

        let pending = self.pending.get_mut(&accusation_id).expect("checked above");
        pending.accusation = incoming;
        pending.votes_for = vec![vote.clone()];
        pending.ec = ec.clone();

        actions.push(VoteAction::PublishVote {
            vote,
            ec: ec.clone(),
        });

        // Peers' votes against the new window may already have arrived and been buffered
        // (or rejected, in which case they will be re-sent when those peers converge too).
        if let Some(buffered) = self.buffered_votes.remove(&accusation_id) {
            for vote in buffered {
                self.on_vote_received_inner(vote, ec, actions);
            }
        }
        self.check_quorum(accusation_id, ec, actions);
    }
}
