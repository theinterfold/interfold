// SPDX-License-Identifier: LGPL-3.0-only

//! C0 signature, commitment, and proof-dispatch boundary.

use super::*;

impl ProofVerificationActor {
    pub(super) fn clear_e3(&mut self, e3_id: &E3id, ctx: &mut Context<Self>) {
        self.presets.remove(e3_id);
        self.committees.remove(e3_id);
        self.pending.retain(|(pending_e3, _), pending| {
            if pending_e3 != e3_id {
                return true;
            }
            if let Some(retry) = pending.retry {
                ctx.cancel_future(retry);
            }
            false
        });
    }

    pub(in crate::actors::proof_verification) fn handle_encryption_key_received(
        &mut self,
        msg: TypedEvent<EncryptionKeyReceived>,
        ctx: &mut Context<Self>,
    ) {
        let (msg, ec) = msg.into_components();
        if self.dkg_ended.contains(&msg.e3_id) {
            debug!(
                e3_id = %msg.e3_id,
                party_id = msg.key.party_id,
                "The E3's DKG ended before startup — not verifying its C0 input"
            );
            return;
        }
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
        let validated = match validate_received_key(&msg, &expected_signer, preset) {
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
                attempts: 0,
                retry_delay: VERIFICATION_RETRY_DELAY,
            },
        );
        self.dispatch_verification(pending_key, ctx);
    }

    pub(super) fn dispatch_verification(
        &mut self,
        pending_key: (E3id, u64),
        ctx: &mut Context<Self>,
    ) {
        if !self.effects_enabled {
            return;
        }
        let Some(pending) = self.pending.get_mut(&pending_key) else {
            return;
        };
        pending.attempts = pending.attempts.saturating_add(1);
        if let Err(err) = self.verifier.try_send(pending.request.clone()) {
            self.retry_verification(pending_key, err.to_string(), ctx);
        }
    }

    pub(super) fn retry_verification(
        &mut self,
        pending_key: (E3id, u64),
        error: String,
        ctx: &mut Context<Self>,
    ) {
        let Some(pending) = self.pending.get_mut(&pending_key) else {
            return;
        };
        if pending.retry.is_some() {
            return;
        }
        let delay = pending.retry_delay;
        pending.retry_delay = delay.saturating_mul(2).min(MAX_VERIFICATION_RETRY_DELAY);
        warn!(e3_id = %pending_key.0, party_id = pending_key.1, attempt = pending.attempts,
            retry_after_secs = delay.as_secs(), %error,
            "C0 verification could not complete; retaining the input for retry");
        pending.retry = Some(ctx.run_later(delay, move |actor, ctx| {
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
