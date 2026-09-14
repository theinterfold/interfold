// SPDX-License-Identifier: LGPL-3.0-only

//! Validate proof ownership/signatures and dispatch consistency checking.

use super::*;

impl ShareVerificationActor {
    /// Generic ECDSA validation + consistency check dispatch.
    ///
    /// After ECDSA validation, publishes [`CommitmentConsistencyCheckRequested`]
    /// and stores a [`PendingConsistencyCheck`]. ZK verification is deferred
    /// until the consistency check response arrives.
    #[allow(clippy::too_many_arguments)]
    pub(in crate::actors::share_verification) fn verify_proofs<P: VerifiableParty>(
        &mut self,
        e3_id: E3id,
        kind: VerificationKind,
        party_proofs: Vec<P>,
        pre_dishonest: BTreeSet<u64>,
        ec: EventContext<Sequenced>,
        params_preset: e3_fhe_params::BfvPreset,
        committee_size: e3_zk_helpers::CiphernodesCommitteeSize,
        dkg_roster: Option<Vec<u64>>,
        store_passed_proofs: impl FnOnce(&mut PendingConsistencyCheck, Vec<P>),
    ) {
        let e3_id_str = e3_id.to_string();
        let label = label_for(&kind);

        // Pure ECDSA validation + proof-commitment preparation lives in the
        // domain service; the actor only emits failures, stores pending state,
        // and publishes the consistency-check request.
        let committee = self.committees.get(&e3_id).map(Vec::as_slice);
        let outcome = ShareVerifier::validate_and_prepare(
            &party_proofs,
            &e3_id_str,
            &kind,
            label,
            committee,
            params_preset,
            committee_size,
        );

        for failure in &outcome.failures {
            self.emit_signed_proof_failed(
                &e3_id,
                &failure.signed,
                failure.recovered,
                failure.party_id,
                &ec,
            );
        }

        if outcome.ecdsa_passed_parties.is_empty() {
            // All parties failed ECDSA — publish result immediately
            let mut all_dishonest: BTreeSet<u64> = pre_dishonest;
            all_dishonest.extend(outcome.ecdsa_dishonest);
            self.publish_complete(e3_id, kind, all_dishonest, ec);
            return;
        }

        // Store pending consistency check with the original party proofs
        let correlation_id = CorrelationId::new();
        let mut pending = PendingConsistencyCheck {
            e3_id: e3_id.clone(),
            kind: kind.clone(),
            ec: ec.clone(),
            ecdsa_dishonest: outcome.ecdsa_dishonest,
            pre_dishonest,
            party_addresses: outcome.party_addresses,
            party_proof_hashes: outcome.party_proof_hashes,
            party_public_signals: outcome.party_public_signals,
            party_proof_data: outcome.party_proof_data,
            ecdsa_passed_share_proofs: Vec::new(),
            ecdsa_passed_decryption_proofs: Vec::new(),
            params_preset,
            committee_size,
        };
        store_passed_proofs(&mut pending, outcome.ecdsa_passed_parties);
        self.pending_consistency.insert(correlation_id, pending);

        // Publish consistency check request
        if let Err(err) = self.bus.publish(
            CommitmentConsistencyCheckRequested {
                e3_id: e3_id.clone(),
                kind: kind.clone(),
                correlation_id,
                party_proofs: outcome.consistency_party_data,
                dkg_roster,
            },
            ec.clone(),
        ) {
            error!(
                "Failed to dispatch {} consistency check: {err} — treating all as dishonest",
                label
            );
            if let Some(pending) = self.pending_consistency.remove(&correlation_id) {
                let mut all_dishonest: BTreeSet<u64> = pending.pre_dishonest;
                all_dishonest.extend(pending.ecdsa_dishonest);
                for p in &pending.ecdsa_passed_share_proofs {
                    all_dishonest.insert(p.sender_party_id);
                }
                for p in &pending.ecdsa_passed_decryption_proofs {
                    all_dishonest.insert(p.sender_party_id);
                }
                self.publish_complete(e3_id, kind, all_dishonest, ec);
            }
        }
    }
}
