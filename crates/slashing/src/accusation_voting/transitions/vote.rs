// SPDX-License-Identifier: LGPL-3.0-only

//! Vote admission, quorum decisions, timeouts, and terminal actions.

use super::*;

impl AccusationVoting {
    /// Called when we receive a vote from another node via gossip.
    pub(crate) fn on_vote_received(
        &mut self,
        vote: AccusationVote,
        ec: &EventContext<Sequenced>,
    ) -> Vec<VoteAction> {
        let mut actions = Vec::new();
        self.on_vote_received_inner(vote, ec, &mut actions);
        actions
    }

    pub(super) fn on_vote_received_inner(
        &mut self,
        vote: AccusationVote,
        ec: &EventContext<Sequenced>,
        actions: &mut Vec<VoteAction>,
    ) {
        // Ignore votes for other E3s
        if vote.e3_id != self.e3_id {
            return;
        }

        // Verify voter is in committee
        if !self.committee.contains(&vote.voter) {
            warn!(
                e3_id = %self.e3_id,
                "Ignoring vote from non-committee member {}", vote.voter
            );
            return;
        }

        // Ignore our own votes (already recorded)
        if vote.voter == self.my_address {
            return;
        }

        // Verify voter's ECDSA signature
        if !self.verify_vote_signature(&vote) {
            warn!(
                e3_id = %self.e3_id,
                "Invalid signature on vote from {} — ignoring", vote.voter
            );
            return;
        }

        let vote_accusation_id = vote.accusation_id;

        // Find the pending accusation
        let Some(pending) = self.pending.get(&vote_accusation_id) else {
            // Unknown accusation — buffer the vote for replay.
            let committee_len = self.committee.len();
            let buf = self.buffered_votes.entry(vote_accusation_id).or_default();
            if buf.len() < committee_len {
                buf.push(vote);
            } else {
                warn!(
                    e3_id = %self.e3_id,
                    "Buffered votes for unknown accusation {:?} reached committee-size cap — dropping vote",
                    vote_accusation_id
                );
            }
            return;
        };

        // A vote signed against a different window than the accusation we hold. Two honest
        // accusers produce the same accusation id with different windows and the committee
        // converges on the later one (see `adopt_later_vote_window`). A peer that converged
        // before us sends votes against the winning window while we still hold the losing
        // one; dropping them would lose the quorum. Buffer them: they are replayed when we
        // adopt the window. Votes against a window that *loses* to ours are simply stale.
        let held_window = (pending.accusation.issued_at, pending.accusation.deadline);
        if (vote.issued_at, vote.deadline) != held_window {
            if (vote.issued_at, vote.deadline) > held_window {
                let committee_len = self.committee.len();
                let buf = self.buffered_votes.entry(vote_accusation_id).or_default();
                if buf.len() < committee_len {
                    info!(
                        "Buffering vote from {} signed against a later window (issued_at {} vs held {}) until we converge",
                        vote.voter, vote.issued_at, held_window.0
                    );
                    buf.push(vote);
                }
            } else {
                warn!(
                    e3_id = %self.e3_id,
                    "Ignoring vote from {} — issued_at {} (expected {}) or deadline {} (expected {}) does not match the accusation",
                    vote.voter, vote.issued_at, held_window.0, vote.deadline, held_window.1
                );
            }
            return;
        }
        let pending = self
            .pending
            .get_mut(&vote_accusation_id)
            .expect("pending accusation checked above");

        // Reject votes from the accused party — conflict of interest
        if vote.voter == pending.accusation.accused {
            warn!(
                e3_id = %self.e3_id,
                "Ignoring vote from accused party {} on their own accusation",
                vote.voter
            );
            return;
        }

        // Dedup: don't count same voter twice
        let already_voted = pending.votes_for.iter().any(|v| v.voter == vote.voter);
        if already_voted {
            return;
        }

        // Accuser's vote data_hash must match the accusation's data_hash.
        if vote.voter == pending.accusation.accuser
            && vote.data_hash != pending.accusation.data_hash
        {
            warn!(
                e3_id = %self.e3_id,
                "Accuser {} sent vote with data_hash inconsistent with their accusation — rejecting vote",
                vote.voter
            );
            return;
        }

        // Every received `AccusationVote` is an agreement.
        pending.votes_for.push(vote);

        self.check_quorum(vote_accusation_id, ec, actions);
    }

    /// Evaluate whether we have enough agreeing votes to decide.
    pub(super) fn check_quorum(
        &mut self,
        accusation_id: [u8; 32],
        ec: &EventContext<Sequenced>,
        actions: &mut Vec<VoteAction>,
    ) {
        let Some(pending) = self.pending.get(&accusation_id) else {
            return;
        };

        let agree_count = pending.votes_for.len();
        if agree_count < self.vote_quorum_h {
            // Not yet at quorum.
            return;
        }

        // Reached `H` — decide between AccusedFaulted and Equivocation.
        let agree_hashes: HashSet<[u8; 32]> =
            pending.votes_for.iter().map(|v| v.data_hash).collect();
        if agree_hashes.len() > 1 {
            info!(
                "Equivocation detected at quorum: {} unique data hashes among {} agreeing voters for {} {:?}",
                agree_hashes.len(),
                agree_count,
                pending.accusation.accused,
                pending.accusation.proof_type
            );
            self.emit_quorum_reached(accusation_id, AccusationOutcome::Equivocation, ec, actions);
        } else {
            info!(
                "Quorum reached: {} votes confirm {} sent bad {:?} proof — AccusedFaulted",
                agree_count, pending.accusation.accused, pending.accusation.proof_type
            );
            self.emit_quorum_reached(
                accusation_id,
                AccusationOutcome::AccusedFaulted,
                ec,
                actions,
            );
        }
    }

    /// Called when the vote timeout expires for an accusation. Returns the
    /// terminal quorum event the actor must publish, if the accusation was
    /// still pending.
    pub(crate) fn on_vote_timeout(
        &mut self,
        accusation_id: [u8; 32],
    ) -> Option<(AccusationQuorumReached, EventContext<Sequenced>)> {
        let pending = self.pending.remove(&accusation_id)?; // Already resolved

        let outcome = if pending.votes_for.len() >= self.vote_quorum_h {
            let agree_hashes: HashSet<[u8; 32]> =
                pending.votes_for.iter().map(|v| v.data_hash).collect();
            if agree_hashes.len() > 1 {
                AccusationOutcome::Equivocation
            } else {
                AccusationOutcome::AccusedFaulted
            }
        } else {
            AccusationOutcome::Inconclusive
        };

        warn!(
            e3_id = %self.e3_id,
            "Accusation against {} for {:?} timed out with {} agreeing votes — outcome: {:?}",
            pending.accusation.accused,
            pending.accusation.proof_type,
            pending.votes_for.len(),
            outcome
        );

        let evidence = self
            .received_data
            .get(&(pending.accusation.accused, pending.accusation.proof_type))
            .map(|d| d.evidence.clone())
            .unwrap_or_default();
        Some((
            AccusationQuorumReached {
                e3_id: self.e3_id.clone(),
                accuser: pending.accusation.accuser,
                accused: pending.accusation.accused,
                proof_type: pending.accusation.proof_type,
                votes_for: pending.votes_for,
                outcome,
                evidence,
            },
            pending.ec,
        ))
    }

    pub(super) fn emit_quorum_reached(
        &mut self,
        accusation_id: [u8; 32],
        outcome: AccusationOutcome,
        ec: &EventContext<Sequenced>,
        actions: &mut Vec<VoteAction>,
    ) {
        let Some(pending) = self.pending.remove(&accusation_id) else {
            return;
        };

        // Cancel the timeout to avoid unnecessary timer fires
        actions.push(VoteAction::CancelTimeout(accusation_id));

        info!(
            "Accusation quorum reached for {} {:?}: {} agreeing votes — outcome: {}",
            pending.accusation.accused,
            pending.accusation.proof_type,
            pending.votes_for.len(),
            outcome
        );

        let evidence = self
            .received_data
            .get(&(pending.accusation.accused, pending.accusation.proof_type))
            .map(|d| d.evidence.clone())
            .unwrap_or_default();
        actions.push(VoteAction::PublishQuorum {
            quorum: AccusationQuorumReached {
                e3_id: self.e3_id.clone(),
                accuser: pending.accusation.accuser,
                accused: pending.accusation.accused,
                proof_type: pending.accusation.proof_type,
                votes_for: pending.votes_for,
                outcome,
                evidence,
            },
            ec: ec.clone(),
        });
    }
}
