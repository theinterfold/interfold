// SPDX-License-Identifier: LGPL-3.0-only

//! CKKS-specific proof generation: C1-CKKS (pk share; the rogue-key gate)
//! and C8-CKKS (hybrid relin round-1 digit proofs).
//!
//! Both mirror the C6 flow: the keyshare shell publishes a `*Pending`
//! event with the witness, this actor requests the proof from multithread,
//! signs it, and publishes the durable event that carries it
//! (`KeyshareCreated` / `RelinCeremonyProofSigned`) plus the local
//! `*ProofSigned` signal.

use super::*;

impl ProofRequestActor {
    /// C1-CKKS: request the pk-share proof.
    pub(in crate::actors::proof_request) fn handle_pk_generation_ckks_proof_pending(
        &mut self,
        msg: TypedEvent<PkGenerationCkksProofPending>,
    ) {
        let (msg, ec) = msg.into_components();
        let e3_id = msg.e3_id.clone();
        if self.pending_pk_generation_ckks.contains_key(&e3_id) {
            warn!("Duplicate PkGenerationCkksProofPending for E3 {e3_id} — ignoring");
            return;
        }
        self.pending_pk_generation_ckks.insert(
            e3_id.clone(),
            PendingPkGenerationCkksProof {
                party_id: msg.party_id,
                node: msg.node,
                pk_share: msg.pk_share,
                ec: ec.clone(),
            },
        );
        let correlation_id = CorrelationId::new();
        self.pk_generation_ckks_correlation
            .insert(correlation_id, e3_id.clone());
        info!("Requesting C1-CKKS pk-share proof for E3 {e3_id}");
        if let Err(err) = self.bus.publish(
            ComputeRequest::zk(
                ZkRequest::PkGenerationCkks(msg.proof_request),
                correlation_id,
                e3_id.clone(),
            ),
            ec,
        ) {
            error!("Failed to publish C1-CKKS proof request: {err}");
            self.pk_generation_ckks_correlation.remove(&correlation_id);
            self.pending_pk_generation_ckks.remove(&e3_id);
        }
    }

    /// C1-CKKS response: sign, publish `KeyshareCreated` carrying the
    /// signed proof (the aggregator verifies it before summing) and the
    /// local `PkGenerationProofSigned`.
    pub(in crate::actors::proof_request) fn handle_pk_generation_ckks_proof_response(
        &mut self,
        correlation_id: &CorrelationId,
        proof: Proof,
    ) {
        let Some(e3_id) = self.pk_generation_ckks_correlation.remove(correlation_id) else {
            return;
        };
        let Some(pending) = self.pending_pk_generation_ckks.remove(&e3_id) else {
            error!("No pending C1-CKKS proof for E3 {e3_id} — orphan correlation");
            return;
        };
        let Some(signed) = self.sign_proof(&e3_id, ProofType::C1PkGeneration, proof) else {
            error!("Failed to sign C1-CKKS proof — KeyshareCreated will not be published");
            self.fail_dkg_round(e3_id, &pending.ec, "C1-CKKS signing error");
            return;
        };
        info!(
            "C1-CKKS proof signed for E3 {e3_id} party {} (signer: {})",
            pending.party_id,
            self.signer.address()
        );
        let ec = pending.ec;
        if let Err(err) = self.bus.publish(
            KeyshareCreated {
                pubkey: pending.pk_share,
                e3_id: e3_id.clone(),
                node: pending.node,
                party_id: pending.party_id,
                signed_pk_generation_proof: Some(signed.clone()),
            },
            ec.clone(),
        ) {
            error!("Failed to publish KeyshareCreated (CKKS): {err}");
            return;
        }
        if let Err(err) = self.bus.publish(
            PkGenerationProofSigned {
                e3_id,
                party_id: pending.party_id,
                signed_proof: signed,
            },
            ec,
        ) {
            error!("Failed to publish PkGenerationProofSigned (CKKS): {err}");
        }
    }

    /// C8-CKKS: request the per-digit round-1 proofs.
    pub(in crate::actors::proof_request) fn handle_relin_round1_proof_pending(
        &mut self,
        msg: TypedEvent<RelinRound1ProofPending>,
    ) {
        let (msg, ec) = msg.into_components();
        let e3_id = msg.e3_id.clone();
        if self.pending_relin_round1.contains_key(&e3_id) {
            warn!("Duplicate RelinRound1ProofPending for E3 {e3_id} — ignoring");
            return;
        }
        self.pending_relin_round1.insert(
            e3_id.clone(),
            PendingRelinRound1Proof {
                party_id: msg.party_id,
                node: msg.node,
                level: msg.level,
                ec: ec.clone(),
            },
        );
        let correlation_id = CorrelationId::new();
        self.relin_round1_correlation
            .insert(correlation_id, e3_id.clone());
        info!("Requesting C8-CKKS relin round-1 digit proofs for E3 {e3_id}");
        if let Err(err) = self.bus.publish(
            ComputeRequest::zk(
                ZkRequest::RelinRound1Ckks(msg.proof_request),
                correlation_id,
                e3_id.clone(),
            ),
            ec,
        ) {
            error!("Failed to publish C8-CKKS proof request: {err}");
            self.relin_round1_correlation.remove(&correlation_id);
            self.pending_relin_round1.remove(&e3_id);
        }
    }

    /// C8-CKKS response: sign every digit proof and publish the durable
    /// `RelinCeremonyProofSigned` bundle next to the share chunks.
    pub(in crate::actors::proof_request) fn handle_relin_round1_proof_response(
        &mut self,
        correlation_id: &CorrelationId,
        proofs: Vec<Proof>,
    ) {
        let Some(e3_id) = self.relin_round1_correlation.remove(correlation_id) else {
            return;
        };
        let Some(pending) = self.pending_relin_round1.remove(&e3_id) else {
            error!("No pending C8-CKKS proof for E3 {e3_id} — orphan correlation");
            return;
        };
        let mut signed_proofs = Vec::with_capacity(proofs.len());
        for proof in proofs {
            let Some(signed) = self.sign_proof(&e3_id, ProofType::C8RelinRound1, proof) else {
                error!("Failed to sign C8-CKKS proof — RelinCeremonyProofSigned not published");
                self.fail_dkg_round(e3_id, &pending.ec, "C8-CKKS signing error");
                return;
            };
            signed_proofs.push(signed);
        }
        info!(
            "C8-CKKS proofs signed for E3 {e3_id} party {} ({} digits, signer: {})",
            pending.party_id,
            signed_proofs.len(),
            self.signer.address()
        );
        if let Err(err) = self.bus.publish(
            RelinCeremonyProofSigned {
                e3_id,
                party_id: pending.party_id,
                node: pending.node,
                round: 1,
                level: pending.level,
                signed_proofs,
                external: false,
            },
            pending.ec,
        ) {
            error!("Failed to publish RelinCeremonyProofSigned: {err}");
        }
    }
}
