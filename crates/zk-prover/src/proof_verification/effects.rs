// SPDX-License-Identifier: LGPL-3.0-only

//! C0 signature, commitment, and proof-dispatch boundary.

use super::*;

impl ProofVerificationActor {
    pub(in crate::actors::proof_verification) fn handle_encryption_key_received(
        &mut self,
        msg: TypedEvent<EncryptionKeyReceived>,
        ctx: &mut Context<Self>,
    ) {
        let (msg, ec) = msg.into_components();
        let pending_key = (msg.e3_id.clone(), msg.key.party_id);
        if self.pending.contains_key(&pending_key) {
            warn!(
                e3_id = %msg.e3_id,
                party_id = msg.key.party_id,
                "C0 verification is already pending for party — ignoring duplicate"
            );
            return;
        }

        let Some((preset, committee_size)) = self.presets.get(&msg.e3_id).copied() else {
            error!(
                "No BfvPreset known for e3_id={} — cannot determine circuit artifacts directory. \
                 This can happen if CiphernodeSelected was missed (e.g. after restart). Rejecting key from party {}.",
                msg.e3_id, msg.key.party_id
            );
            return;
        };
        let Some(expected_signer) = self
            .committees
            .get(&msg.e3_id)
            .and_then(|committee| {
                usize::try_from(msg.key.party_id)
                    .ok()
                    .and_then(|i| committee.get(i))
            })
            .copied()
        else {
            error!(
                e3_id = %msg.e3_id,
                party_id = msg.key.party_id,
                "No finalized committee member for C0 party slot — rejecting key"
            );
            return;
        };
        let validated = match validate_external_key(
            &msg.e3_id,
            &expected_signer,
            msg.key.party_id,
            msg.key.proof.as_ref(),
            msg.key.signed_payload.as_ref(),
        ) {
            Ok(validated) => validated,
            Err(reason) => {
                error!("{reason}");
                return;
            }
        };
        let proof = msg
            .key
            .proof
            .clone()
            .expect("proof present after validation");
        let key_commitment =
            match compute_dkg_pk_commitment_from_public_key_bytes(&msg.key.pk_bfv, preset) {
                Ok(commitment) => commitment,
                Err(err) => {
                    error!(
                        e3_id = %msg.e3_id,
                        party_id = msg.key.party_id,
                        "Could not bind C0 proof to advertised BFV key: {err} — rejecting key"
                    );
                    return;
                }
            };
        if let Err(reason) =
            validate_external_key_commitment(msg.key.party_id, &proof, &key_commitment)
        {
            error!("{reason}");
            return;
        }

        let artifacts_dir = preset.artifacts_dir_for_committee(committee_size.as_str());

        let request = TypedEvent::new(
            ZkVerificationRequest {
                proof,
                e3_id: msg.e3_id,
                key: msg.key,
                sender: ctx.address().recipient(),
                artifacts_dir,
            },
            ec,
        );

        self.pending.insert(
            pending_key.clone(),
            PendingVerification {
                signed_payload: validated.signed_payload,
                recovered_signer: validated.recovered_signer,
                request,
                retry: None,
            },
        );
        self.dispatch_verification(pending_key, ctx);
    }

    fn dispatch_verification(&mut self, pending_key: (E3id, u64), ctx: &mut Context<Self>) {
        let Some(pending) = self.pending.get(&pending_key) else {
            return;
        };
        if let Err(err) = self.verifier.try_send(pending.request.clone()) {
            error!("Could not dispatch C0 verification: {err}");
            self.retry_verification(pending_key, ctx);
        }
    }

    pub(super) fn retry_verification(&mut self, pending_key: (E3id, u64), ctx: &mut Context<Self>) {
        let Some(pending) = self.pending.get_mut(&pending_key) else {
            return;
        };
        if pending.retry.is_some() {
            return;
        }
        pending.retry = Some(ctx.run_later(VERIFICATION_RETRY_DELAY, move |actor, ctx| {
            let Some(pending) = actor.pending.get_mut(&pending_key) else {
                return;
            };
            pending.retry = None;
            actor.dispatch_verification(pending_key, ctx);
        }));
    }

    pub(in crate::actors::proof_verification) fn publish_key_created(
        &self,
        e3_id: E3id,
        key: Arc<EncryptionKey>,
        ec: EventContext<Sequenced>,
    ) {
        if let Err(err) = self.bus.publish(
            EncryptionKeyCreated {
                e3_id,
                key,
                external: true,
            },
            ec,
        ) {
            error!("Failed to publish EncryptionKeyCreated: {err}");
        }
    }
}
