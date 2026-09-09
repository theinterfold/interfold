// SPDX-License-Identifier: LGPL-3.0-only

//! Local fault/consistency inputs and accusation creation.

use super::*;

impl AccusationVoting {
    /// Called when the local node detects a proof failure.
    pub(crate) fn on_local_proof_failure(
        &mut self,
        event: ProofVerificationFailed,
        ec: &EventContext<Sequenced>,
    ) -> Vec<VoteAction> {
        if event.e3_id != self.e3_id {
            return Vec::new();
        }

        let accused_address = if event.accused_address == Address::ZERO {
            if let Some(&addr) = self.committee.get(event.accused_party_id as usize) {
                warn!(
                    e3_id = %self.e3_id,
                    "Resolved Address::ZERO for party {} to committee address {}",
                    event.accused_party_id, addr
                );
                addr
            } else {
                error!(
                    e3_id = %self.e3_id,
                    "Cannot resolve address for party {} (out of committee bounds) — dropping accusation",
                    event.accused_party_id
                );
                return Vec::new();
            }
        } else {
            event.accused_address
        };

        if !self.committee.contains(&accused_address) {
            warn!(
                "Ignoring proof failure for {} — not on E3 {} committee",
                accused_address, self.e3_id
            );
            return Vec::new();
        }

        // Cache the failed verification result.
        let evidence = Bytes::from(
            (
                Bytes::copy_from_slice(&event.signed_payload.payload.proof.data),
                Bytes::copy_from_slice(&event.signed_payload.payload.proof.public_signals),
            )
                .abi_encode(),
        );
        self.received_data.insert(
            (accused_address, event.proof_type),
            ReceivedProofData {
                data_hash: event.data_hash,
                verification_passed: false,
                evidence,
            },
        );

        // For C3a/C3b, include the signed payload so other nodes can re-verify
        let forwarded_payload = match event.proof_type {
            ProofType::C3aSkShareEncryption | ProofType::C3bESmShareEncryption => {
                Some(event.signed_payload.clone())
            }
            _ => None,
        };

        let mut actions = Vec::new();
        self.initiate_accusation(
            accused_address,
            event.accused_party_id,
            event.proof_type,
            event.data_hash,
            forwarded_payload,
            ec,
            &mut actions,
        );
        actions
    }

    /// Called when the `CommitmentConsistencyChecker` detects a cross-circuit
    /// commitment mismatch for a party.
    pub(crate) fn on_consistency_violation(
        &mut self,
        data: CommitmentConsistencyViolation,
        ec: &EventContext<Sequenced>,
    ) -> Vec<VoteAction> {
        if data.e3_id != self.e3_id {
            return Vec::new();
        }

        if !self.committee.contains(&data.accused_address) {
            warn!(
                "Ignoring commitment violation for {} — not on E3 {} committee",
                data.accused_address, self.e3_id
            );
            return Vec::new();
        }

        self.received_data.insert(
            (data.accused_address, data.proof_type),
            ReceivedProofData {
                data_hash: data.data_hash,
                verification_passed: false,
                evidence: data.evidence.clone(),
            },
        );

        let mut actions = Vec::new();
        self.initiate_accusation(
            data.accused_address,
            data.accused_party_id,
            data.proof_type,
            data.data_hash,
            None,
            ec,
            &mut actions,
        );
        actions
    }

    /// Shared accusation creation and broadcast logic.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn initiate_accusation(
        &mut self,
        accused_address: Address,
        accused_party_id: u64,
        proof_type: ProofType,
        data_hash: [u8; 32],
        forwarded_payload: Option<SignedProofPayload>,
        ec: &EventContext<Sequenced>,
        actions: &mut Vec<VoteAction>,
    ) {
        if !self.committee.contains(&accused_address) {
            warn!(
                "Refusing accusation against {} — not on E3 {} committee",
                accused_address, self.e3_id
            );
            return;
        }

        let key = (accused_address, proof_type);

        // Dedup: don't create multiple accusations for the same (accused, proof_type)
        if !self.accused_proofs.insert(key) {
            info!(
                "Already accused {:?} for {:?} — skipping duplicate",
                accused_address, proof_type
            );
            return;
        }

        // Governance-disabled validity window means no accusation voting.
        if self.vote_validity_secs == 0 {
            warn!(
                "Refusing accusation initiation for {:?} on E3 {}: vote_validity_secs is 0",
                accused_address, self.e3_id
            );
            self.accused_proofs.remove(&key);
            return;
        }

        // Pick the on-chain validity deadline once per accusation.
        let (issued_at, deadline) = self.compute_vote_window();

        // Create the accusation
        let mut accusation = ProofFailureAccusation {
            e3_id: self.e3_id.clone(),
            accuser: self.my_address,
            accused: accused_address,
            accused_party_id,
            proof_type,
            data_hash,
            issued_at,
            deadline,
            signed_payload: forwarded_payload,
            signature: ArcBytes::default(),
        };
        match self.sign_accusation_digest(&accusation) {
            Ok(sig) => accusation.signature = ArcBytes::from_bytes(&sig),
            Err(err) => {
                error!(
                    e3_id = %self.e3_id,
                    "Failed to sign ProofFailureAccusation: {err}"
                );
                self.accused_proofs.remove(&key);
                return;
            }
        }

        let accusation_id = Self::accusation_id(&accusation);

        info!(
            "Broadcasting accusation against {} for {:?} failure",
            accused_address, proof_type
        );

        // Broadcast accusation via gossip
        actions.push(VoteAction::PublishAccusation {
            accusation: accusation.clone(),
            ec: ec.clone(),
            dedup_key: key,
        });

        // Cast our own agreement vote (we just observed the failure locally).
        let mut own_vote = AccusationVote {
            e3_id: self.e3_id.clone(),
            accusation_id,
            voter: self.my_address,
            data_hash,
            issued_at,
            deadline,
            signature: ArcBytes::default(),
        };
        match self.sign_vote_digest(&own_vote) {
            Ok(sig) => own_vote.signature = ArcBytes::from_bytes(&sig),
            Err(err) => {
                error!(
                    e3_id = %self.e3_id,
                    "Failed to sign own AccusationVote: {err}"
                );
                self.accused_proofs.remove(&key);
                return;
            }
        }

        actions.push(VoteAction::PublishVote {
            vote: own_vote.clone(),
            ec: ec.clone(),
        });

        // Start timeout
        actions.push(VoteAction::StartTimeout(accusation_id));

        // Store pending accusation with own vote
        self.pending.insert(
            accusation_id,
            PendingAccusation {
                accusation,
                votes_for: vec![own_vote],
                ec: ec.clone(),
            },
        );

        // Replay any votes that arrived before this accusation
        if let Some(buffered) = self.buffered_votes.remove(&accusation_id) {
            for vote in buffered {
                self.on_vote_received_inner(vote, ec, actions);
            }
        }

        // Check quorum immediately (defensive for a future H=1 committee).
        self.check_quorum(accusation_id, ec, actions);
    }
}
