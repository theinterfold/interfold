// SPDX-License-Identifier: LGPL-3.0-only

//! Apply commitment-consistency results and dispatch heavy ZK verification.

use super::*;

impl ShareVerificationActor {
    /// Handle consistency check response: add inconsistent parties to the
    /// dishonest set, then dispatch ZK verification for the remaining
    /// consistent parties.
    pub(in crate::actors::share_verification) fn handle_consistency_check_complete(
        &mut self,
        msg: TypedEvent<CommitmentConsistencyCheckComplete>,
    ) {
        let (data, _ec) = msg.into_components();

        let Some(pending) = self.pending_consistency.remove(&data.correlation_id) else {
            return; // Not our correlation ID
        };

        let label = label_for(&pending.kind);

        if !data.inconsistent_parties.is_empty() {
            warn!(
                "{} consistency check found {} inconsistent parties for E3 {}: {:?}",
                label,
                data.inconsistent_parties.len(),
                pending.e3_id,
                data.inconsistent_parties
            );
        }

        // Accumulate all dishonest parties discovered so far
        let mut dishonest_so_far: BTreeSet<u64> = pending.pre_dishonest.clone();
        dishonest_so_far.extend(&pending.ecdsa_dishonest);
        dishonest_so_far.extend(&data.inconsistent_parties);

        // Filter ECDSA-passed proofs to only consistent parties and dispatch ZK
        let inconsistent = &data.inconsistent_parties;
        let zk_correlation_id = CorrelationId::new();

        let (request, dispatched_party_ids) = match pending.kind {
            VerificationKind::ShareProofs
            | VerificationKind::ThresholdDecryptionProofs
            | VerificationKind::PkGenerationProofs => {
                let Some((passed, ids)) =
                    filter_consistent(pending.ecdsa_passed_share_proofs, inconsistent, |p| {
                        p.sender_party_id
                    })
                else {
                    self.publish_complete(
                        pending.e3_id,
                        pending.kind,
                        dishonest_so_far,
                        pending.ec,
                    );
                    return;
                };
                let req = ComputeRequest::zk(
                    ZkRequest::VerifyShareProofs(VerifyShareProofsRequest {
                        party_proofs: passed,
                        params_preset: pending.params_preset,
                        committee_size: pending.committee_size,
                    }),
                    zk_correlation_id,
                    pending.e3_id.clone(),
                );
                (req, ids)
            }
            VerificationKind::DecryptionProofs => {
                let Some((passed, ids)) =
                    filter_consistent(pending.ecdsa_passed_decryption_proofs, inconsistent, |p| {
                        p.sender_party_id
                    })
                else {
                    self.publish_complete(
                        pending.e3_id,
                        pending.kind,
                        dishonest_so_far,
                        pending.ec,
                    );
                    return;
                };
                let req = ComputeRequest::zk(
                    ZkRequest::VerifyShareDecryptionProofs(VerifyShareDecryptionProofsRequest {
                        party_proofs: passed,
                        params_preset: pending.params_preset,
                        committee_size: pending.committee_size,
                    }),
                    zk_correlation_id,
                    pending.e3_id.clone(),
                );
                (req, ids)
            }
        };

        // Only keep proof hashes/signals/addresses for parties going to ZK
        let party_addresses: HashMap<u64, Address> = pending
            .party_addresses
            .into_iter()
            .filter(|(pid, _)| dispatched_party_ids.contains(pid))
            .collect();
        let party_proof_hashes: HashMap<u64, Vec<(ProofType, [u8; 32])>> = pending
            .party_proof_hashes
            .into_iter()
            .filter(|(pid, _)| dispatched_party_ids.contains(pid))
            .collect();
        let party_public_signals: HashMap<u64, Vec<(ProofType, ArcBytes)>> = pending
            .party_public_signals
            .into_iter()
            .filter(|(pid, _)| dispatched_party_ids.contains(pid))
            .collect();
        let party_proof_data: HashMap<u64, Vec<(ProofType, ArcBytes)>> = pending
            .party_proof_data
            .into_iter()
            .filter(|(pid, _)| dispatched_party_ids.contains(pid))
            .collect();

        // Store pending ZK verification state.
        // All prior dishonest parties (pre_dishonest + ECDSA + consistency) are
        // folded into `pre_dishonest` so that `handle_compute_response` produces
        // the correct final dishonest set when it adds ZK failures.
        self.pending.insert(
            zk_correlation_id,
            PendingVerification {
                e3_id: pending.e3_id.clone(),
                kind: pending.kind.clone(),
                ec: pending.ec.clone(),
                ecdsa_dishonest: HashSet::new(),
                pre_dishonest: dishonest_so_far,
                dispatched_party_ids: dispatched_party_ids.clone(),
                party_addresses,
                party_proof_hashes,
                party_public_signals,
                party_proof_data,
                params_preset: pending.params_preset,
                committee_size: pending.committee_size,
            },
        );

        if let Err(err) = self.bus.publish(request, pending.ec.clone()) {
            error!(
                "Failed to dispatch {} ZK verification after consistency check: {err}",
                label
            );
            if let Some(zk_pending) = self.pending.remove(&zk_correlation_id) {
                let mut all_dishonest: BTreeSet<u64> = zk_pending.pre_dishonest;
                all_dishonest.extend(zk_pending.ecdsa_dishonest);
                all_dishonest.extend(zk_pending.dispatched_party_ids);
                self.publish_complete(
                    zk_pending.e3_id,
                    zk_pending.kind,
                    all_dishonest,
                    zk_pending.ec,
                );
            }
        }
    }
}
