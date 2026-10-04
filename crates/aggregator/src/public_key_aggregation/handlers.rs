// SPDX-License-Identifier: LGPL-3.0-only

//! Actix lifecycle and message routing for public-key aggregation.

use super::*;

impl Actor for PublicKeyAggregator {
    type Context = Context<Self>;
    fn started(&mut self, ctx: &mut Self::Context) {
        ctx.set_mailbox_capacity(MAILBOX_LIMIT);
    }
}

impl Handler<InterfoldEvent> for PublicKeyAggregator {
    type Result = ();
    fn handle(&mut self, msg: InterfoldEvent, ctx: &mut Self::Context) -> Self::Result {
        let (msg, ec) = msg.into_components();
        match msg {
            InterfoldEventData::KeyshareCreated(data) => {
                self.notify_sync(ctx, TypedEvent::new(data, ec))
            }
            InterfoldEventData::CommitmentRosterSelected(data) => {
                trap(EType::PublickeyAggregation, &self.bus.with_ec(&ec), || {
                    self.accept_dkg_roster(data, ec)
                });
            }
            InterfoldEventData::ShareVerificationComplete(data) => {
                self.notify_sync(ctx, TypedEvent::new(data, ec))
            }
            InterfoldEventData::PkAggregationProofSigned(data) => {
                self.notify_sync(ctx, TypedEvent::new(data, ec))
            }
            InterfoldEventData::DKGRecursiveAggregationComplete(data) => {
                self.notify_sync(ctx, TypedEvent::new(data, ec))
            }
            InterfoldEventData::ComputeResponse(data) => {
                self.notify_sync(ctx, TypedEvent::new(data, ec))
            }
            InterfoldEventData::ComputeRequestError(data) => {
                self.notify_sync(ctx, TypedEvent::new(data, ec))
            }
            InterfoldEventData::DkgFoldAttestationContextEstablished(data) => {
                if data.e3_id == self.e3_id {
                    self.dkg_fold_attestation_context = Some(data.context);
                }
            }
            InterfoldEventData::AggregatorChanged(data) => {
                self.notify_sync(ctx, TypedEvent::new(data, ec))
            }
            InterfoldEventData::EffectsEnabled(_) => {
                trap(EType::PublickeyAggregation, &self.bus.with_ec(&ec), || {
                    self.effects_enabled = true;
                    self.publish_inputs_ready(ec.clone())?;
                    self.resume_in_flight_work(ec)
                });
            }
            InterfoldEventData::E3RequestComplete(_) => self.notify_sync(ctx, Die),
            InterfoldEventData::CommitteePublished(data) if data.e3_id == self.e3_id => {
                self.observe_stage(&E3Stage::KeyPublished);
            }
            // The aggregation of an ended E3 does not resume, also when the context stays for
            // accusation work.
            InterfoldEventData::E3StageChanged(data)
                if data.e3_id == self.e3_id && data.new_stage.is_terminal() =>
            {
                self.notify_sync(ctx, Die)
            }
            InterfoldEventData::E3StageChanged(data) if data.e3_id == self.e3_id => {
                self.observe_stage(&data.new_stage);
            }
            ref removal @ InterfoldEventData::CommitteeMemberExpelled(CommitteeMemberExpelled {
                ref e3_id,
                node,
                party_id,
                ..
            })
            | ref removal @ InterfoldEventData::CommitteeMemberExcluded(CommitteeMemberExcluded {
                ref e3_id,
                node,
                party_id,
                ..
            }) => {
                // Sortition enriches these events with a party ID. This collector uses addresses.
                if party_id.is_some() {
                    return;
                }
                if e3_id != &self.e3_id {
                    error!("Wrong e3_id sent to PublicKeyAggregator for member removal.");
                    return;
                }
                let (removal_kind, proof_type) = match removal {
                    InterfoldEventData::CommitteeMemberExcluded(data) => {
                        ("excluded", Some(tracing::field::display(data.proof_type)))
                    }
                    _ => ("expelled", None),
                };
                let message = if self.key_published {
                    "PublicKeyAggregator ignoring DKG member removal because the key is already published"
                } else {
                    "PublicKeyAggregator processing DKG member removal"
                };
                info!(
                    removal = %removal_kind,
                    %node,
                    %e3_id,
                    proof_type,
                    "{message}"
                );
                trap(EType::PublickeyAggregation, &self.bus.with_ec(&ec), || {
                    self.handle_member_expelled(node, &ec)
                });
            }
            _ => (),
        };
    }
}

impl Handler<TypedEvent<AggregatorChanged>> for PublicKeyAggregator {
    type Result = ();

    fn handle(
        &mut self,
        msg: TypedEvent<AggregatorChanged>,
        _ctx: &mut Self::Context,
    ) -> Self::Result {
        if msg.e3_id != self.e3_id || msg.is_aggregator == self.is_aggregator {
            return;
        }
        self.is_aggregator = msg.is_aggregator;
        if self.can_run_aggregation_effects() {
            let ec = msg.get_ctx().clone();
            trap(EType::PublickeyAggregation, &self.bus.with_ec(&ec), || {
                self.resume_in_flight_work(ec)
            });
        }
    }
}

impl Handler<TypedEvent<KeyshareCreated>> for PublicKeyAggregator {
    type Result = ();

    fn handle(
        &mut self,
        event: TypedEvent<KeyshareCreated>,
        _ctx: &mut Self::Context,
    ) -> Self::Result {
        let (event, ec) = event.into_components();
        trap(EType::PublickeyAggregation, &self.bus.with_ec(&ec), || {
            let e3_id = event.e3_id.clone();
            let pubkey = event.pubkey.clone();
            let node = event.node.clone();
            let party_id = event.party_id;
            let c1_proof = event.signed_pk_generation_proof.clone();

            if e3_id != self.e3_id {
                error!("Wrong e3_id sent to aggregator. This should not happen.");
                return Ok(());
            }

            let was_ready = self.aggregation_inputs_ready();
            self.add_keyshare(pubkey, node, party_id, c1_proof, &ec)?;
            let became_ready = !was_ready && self.aggregation_inputs_ready();
            if became_ready {
                self.publish_inputs_ready(ec.clone())?;
            }

            // If we just transitioned to VerifyingC1, dispatch verification
            // using c1_proofs stored in the new state.
            if became_ready && self.can_run_aggregation_effects() {
                self.continue_c1_verification(ec)?;
            }

            Ok(())
        })
    }
}

impl Handler<TypedEvent<ShareVerificationComplete>> for PublicKeyAggregator {
    type Result = ();

    fn handle(
        &mut self,
        msg: TypedEvent<ShareVerificationComplete>,
        _ctx: &mut Self::Context,
    ) -> Self::Result {
        if !self.can_continue_aggregation_effects() {
            return;
        }
        trap(
            EType::PublickeyAggregation,
            &self.bus.with_ec(msg.get_ctx()),
            || self.handle_c1_verification_complete(msg),
        )
    }
}

impl Handler<TypedEvent<PkAggregationProofSigned>> for PublicKeyAggregator {
    type Result = ();

    fn handle(
        &mut self,
        msg: TypedEvent<PkAggregationProofSigned>,
        _ctx: &mut Self::Context,
    ) -> Self::Result {
        if !self.can_continue_aggregation_effects() {
            return;
        }
        trap(
            EType::PublickeyAggregation,
            &self.bus.with_ec(msg.get_ctx()),
            || self.handle_pk_aggregation_proof_signed(msg),
        )
    }
}

impl Handler<TypedEvent<DKGRecursiveAggregationComplete>> for PublicKeyAggregator {
    type Result = ();

    fn handle(
        &mut self,
        msg: TypedEvent<DKGRecursiveAggregationComplete>,
        _ctx: &mut Self::Context,
    ) -> Self::Result {
        // Standbys need the same durable fold inputs as the active aggregator. If the active
        // node disappears, the promoted node must not wait for proofs that were published once
        // and will not be emitted again.
        trap(
            EType::PublickeyAggregation,
            &self.bus.with_ec(msg.get_ctx()),
            || self.handle_dkg_recursive_aggregation_complete(msg),
        )
    }
}

impl Handler<TypedEvent<ComputeResponse>> for PublicKeyAggregator {
    type Result = ();

    fn handle(
        &mut self,
        msg: TypedEvent<ComputeResponse>,
        _ctx: &mut Self::Context,
    ) -> Self::Result {
        if !self.can_continue_aggregation_effects() {
            return;
        }
        trap(
            EType::PublickeyAggregation,
            &self.bus.with_ec(msg.get_ctx()),
            || self.handle_compute_response(msg),
        )
    }
}

impl Handler<TypedEvent<ComputeRequestError>> for PublicKeyAggregator {
    type Result = ();

    fn handle(
        &mut self,
        msg: TypedEvent<ComputeRequestError>,
        _ctx: &mut Self::Context,
    ) -> Self::Result {
        if !self.can_continue_aggregation_effects() {
            return;
        }
        trap(
            EType::PublickeyAggregation,
            &self.bus.with_ec(msg.get_ctx()),
            || self.handle_compute_request_error(msg),
        )
    }
}

impl Handler<Die> for PublicKeyAggregator {
    type Result = ();
    fn handle(&mut self, _: Die, ctx: &mut Self::Context) -> Self::Result {
        ctx.stop();
    }
}
