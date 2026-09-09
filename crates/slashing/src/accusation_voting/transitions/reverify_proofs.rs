// SPDX-License-Identifier: LGPL-3.0-only

//! Slash cleanup and forwarded-proof re-verification results.

use super::*;

impl AccusationVoting {
    /// Handle an on-chain SlashExecuted event for this E3.
    pub(crate) fn on_slash_executed(&mut self, data: SlashExecuted) {
        if data.e3_id != self.e3_id {
            return;
        }
        let prev_len = self.committee.len();
        self.committee.retain(|addr| *addr != data.operator);
        if self.committee.len() < prev_len {
            info!(
                "Removed slashed operator {} from committee (now {} members)",
                data.operator,
                self.committee.len()
            );

            // Purge any votes from the expelled node in pending accusations
            for pending in self.pending.values_mut() {
                pending.votes_for.retain(|v| v.voter != data.operator);
            }

            // Purge from buffered votes
            for buf in self.buffered_votes.values_mut() {
                buf.retain(|v| v.voter != data.operator);
            }
        }
    }

    /// Handle ZK re-verification response for a forwarded C3a/C3b proof.
    pub(crate) fn handle_reverification_response(
        &mut self,
        msg: TypedEvent<ComputeResponse>,
    ) -> Vec<VoteAction> {
        let (msg, _ec) = msg.into_components();
        let mut actions = Vec::new();

        let correlation_id = msg.correlation_id;
        let Some(reverif) = self.pending_reverifications.remove(&correlation_id) else {
            return actions; // Not our correlation ID
        };

        let zk_passed = match msg.response {
            ComputeResponseKind::Zk(ZkResponse::VerifyShareProofs(r)) => {
                if r.party_results.is_empty() {
                    warn!(
                        e3_id = %self.e3_id,
                        "Empty ZK re-verification results — abstaining"
                    );
                    return actions;
                }
                r.party_results.first().is_some_and(|r| r.all_verified)
            }
            _ => {
                warn!(
                    e3_id = %self.e3_id,
                    "Unexpected ComputeResponse kind for C3a/C3b re-verification — abstaining"
                );
                return actions;
            }
        };

        // Cache the result for future accusations regardless of outcome.
        self.cache_verification_result(
            reverif.accused,
            reverif.proof_type,
            reverif.data_hash,
            zk_passed,
            reverif.evidence.clone(),
        );

        // ZK re-verification passed ⇒ proof is valid ⇒ we disagree ⇒ abstain.
        if zk_passed {
            info!(
                "C3a/C3b re-verification passed for {:?} — abstaining from vote",
                reverif.proof_type
            );
            return actions;
        }

        // ZK re-verification failed ⇒ we agree with the accusation.
        let (ec, issued_at, deadline) = match self.pending.get(&reverif.accusation_id) {
            Some(pending) => (
                pending.ec.clone(),
                pending.accusation.issued_at,
                pending.accusation.deadline,
            ),
            None => {
                // Accusation already resolved before ZK finished
                return actions;
            }
        };

        let mut vote = AccusationVote {
            e3_id: self.e3_id.clone(),
            accusation_id: reverif.accusation_id,
            voter: self.my_address,
            data_hash: reverif.data_hash,
            issued_at,
            deadline,
            signature: ArcBytes::default(),
        };
        match self.sign_vote_digest(&vote) {
            Ok(sig) => vote.signature = ArcBytes::from_bytes(&sig),
            Err(err) => {
                error!(
                    e3_id = %self.e3_id,
                    "Failed to sign C3a/C3b AccusationVote: {err}"
                );
                return actions;
            }
        }

        info!(
            "C3a/C3b re-verification confirmed failure for {:?} — agreeing with accusation",
            reverif.proof_type
        );

        // Broadcast vote via gossip
        actions.push(VoteAction::PublishVote {
            vote: vote.clone(),
            ec: ec.clone(),
        });

        // Record in pending
        if let Some(pending) = self.pending.get_mut(&reverif.accusation_id) {
            pending.votes_for.push(vote);
        }

        // Check quorum
        self.check_quorum(reverif.accusation_id, &ec, &mut actions);
        actions
    }

    /// Handle ZK re-verification error for a forwarded C3a/C3b proof.
    pub(crate) fn handle_reverification_error(&mut self, msg: TypedEvent<ComputeRequestError>) {
        let (msg, _ec) = msg.into_components();

        let correlation_id = msg.correlation_id();
        let Some(reverif) = self.pending_reverifications.remove(correlation_id) else {
            return; // Not our correlation ID
        };

        error!(
            e3_id = %self.e3_id,
            "C3a/C3b ZK re-verification failed for {:?} — abstaining from vote",
            reverif.proof_type
        );
        // Don't vote — effectively abstain
    }
}
