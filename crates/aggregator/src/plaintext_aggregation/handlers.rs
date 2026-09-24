// SPDX-License-Identifier: LGPL-3.0-only

//! Actix lifecycle, role ownership, and message routing.

use super::*;

impl Actor for ThresholdPlaintextAggregator {
    type Context = Context<Self>;
    fn started(&mut self, ctx: &mut Self::Context) {
        ctx.set_mailbox_capacity(MAILBOX_LIMIT);
    }
}

impl Handler<InterfoldEvent> for ThresholdPlaintextAggregator {
    type Result = ();
    fn handle(&mut self, msg: InterfoldEvent, ctx: &mut Self::Context) -> Self::Result {
        let (msg, ec) = msg.into_components();
        match msg {
            InterfoldEventData::DecryptionshareCreated(data) => {
                ctx.notify(TypedEvent::new(data, ec))
            }
            InterfoldEventData::E3RequestComplete(_) => self.notify_sync(ctx, Die),
            InterfoldEventData::ComputeResponse(data) => {
                self.notify_sync(ctx, TypedEvent::new(data, ec))
            }
            InterfoldEventData::ComputeRequestError(data) => {
                self.notify_sync(ctx, TypedEvent::new(data, ec))
            }
            InterfoldEventData::CommitteeMemberExpelled(data) => {
                self.notify_sync(ctx, TypedEvent::new(data, ec))
            }
            InterfoldEventData::CommitteeMemberExcluded(data) => {
                self.notify_sync(ctx, TypedEvent::new(data, ec))
            }
            InterfoldEventData::ShareVerificationComplete(data) => {
                self.notify_sync(ctx, TypedEvent::new(data, ec))
            }
            InterfoldEventData::PlaintextVerificationResumed(data) => {
                trap(EType::PlaintextAggregation, &self.bus.with_ec(&ec), || {
                    self.handle_c6_resume(TypedEvent::new(data, ec))
                });
            }
            InterfoldEventData::AggregationProofSigned(data) => {
                self.notify_sync(ctx, TypedEvent::new(data, ec))
            }
            InterfoldEventData::AggregatorChanged(data) => {
                self.notify_sync(ctx, TypedEvent::new(data, ec))
            }
            InterfoldEventData::EffectsEnabled(_) => {
                trap(EType::PlaintextAggregation, &self.bus.with_ec(&ec), || {
                    self.effects_enabled = true;
                    self.publish_inputs_ready(ec.clone())?;
                    self.resume_in_flight_work(ec)
                });
            }
            _ => (),
        }
    }
}

impl Handler<TypedEvent<AggregatorChanged>> for ThresholdPlaintextAggregator {
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
            trap(EType::PlaintextAggregation, &self.bus.with_ec(&ec), || {
                self.resume_in_flight_work(ec)
            });
        }
    }
}

impl Handler<TypedEvent<DecryptionshareCreated>> for ThresholdPlaintextAggregator {
    type Result = ();
    fn handle(
        &mut self,
        msg: TypedEvent<DecryptionshareCreated>,
        ctx: &mut Self::Context,
    ) -> Self::Result {
        trap(
            EType::PublickeyAggregation,
            &self.bus.with_ec(msg.get_ctx()),
            || {
                if !matches!(
                    self.state.get(),
                    Some(
                        ThresholdPlaintextAggregatorState::Collecting(_)
                            | ThresholdPlaintextAggregatorState::VerifyingC6(_)
                    )
                ) {
                    debug!(state=?self.state, "Aggregator has been closed for collecting so ignoring this event.");
                    return Ok(());
                };
                let node = msg.node.clone();
                let e3_id = msg.e3_id.clone();
                let request = E3CommitteeContainsRequest::new(e3_id, node, msg, ctx.address());
                self.sortition.try_send(request)?;
                Ok(())
            },
        )
    }
}

impl Handler<E3CommitteeContainsResponse<TypedEvent<DecryptionshareCreated>>>
    for ThresholdPlaintextAggregator
{
    type Result = ();
    fn handle(
        &mut self,
        msg: E3CommitteeContainsResponse<TypedEvent<DecryptionshareCreated>>,
        _ctx: &mut Self::Context,
    ) -> Self::Result {
        trap(
            EType::PublickeyAggregation,
            &self.bus.with_ec(msg.get_ctx()),
            || {
                let e3_id = &msg.e3_id;
                if *e3_id != self.e3_id {
                    bail!("Wrong e3_id sent to aggregator. This should not happen.")
                };

                if !msg.is_found_in_committee() {
                    trace!("Node {} not found in finalized committee", &msg.node);
                    return Ok(());
                };
                if !self.node_owns_aggregated_pk_party_slot(&msg.node, msg.party_id) {
                    trace!(
                        "Node {} does not own honest party slot {} — ignoring decryption share",
                        &msg.node,
                        msg.party_id
                    );
                    return Ok(());
                }

                // Trust the party_id from the event - it's based on CommitteeFinalized order
                // which is the authoritative source of truth for party IDs
                let (
                    DecryptionshareCreated {
                        party_id,
                        decryption_share,
                        signed_decryption_proofs,
                        ..
                    },
                    ec,
                ) = msg.into_inner().into_components();

                let was_ready = self.aggregation_inputs_ready();
                self.add_share(party_id, decryption_share, signed_decryption_proofs, &ec)?;
                let became_ready = !was_ready && self.aggregation_inputs_ready();
                if became_ready {
                    self.publish_inputs_ready(ec.clone())?;
                }

                // If we transitioned to VerifyingC6, dispatch C6 verification
                // using the proofs persisted in state
                if became_ready && self.can_run_aggregation_effects() {
                    if let Some(ThresholdPlaintextAggregatorState::VerifyingC6(ref state)) =
                        self.state.get()
                    {
                        self.dispatch_c6_verification(state.c6_proofs.clone(), ec)?;
                    }
                }

                Ok(())
            },
        )
    }
}

impl Handler<TypedEvent<ComputeResponse>> for ThresholdPlaintextAggregator {
    type Result = ();
    fn handle(
        &mut self,
        msg: TypedEvent<ComputeResponse>,
        ctx: &mut Self::Context,
    ) -> Self::Result {
        if !self.can_run_aggregation_effects() {
            return;
        }
        trap(
            EType::PlaintextAggregation,
            &self.bus.with_ec(msg.get_ctx()),
            || self.handle_compute_response(msg, ctx),
        )
    }
}

impl Handler<TypedEvent<ComputeRequestError>> for ThresholdPlaintextAggregator {
    type Result = ();

    fn handle(
        &mut self,
        msg: TypedEvent<ComputeRequestError>,
        _: &mut Self::Context,
    ) -> Self::Result {
        if !self.can_run_aggregation_effects() {
            return;
        }
        trap(
            EType::PlaintextAggregation,
            &self.bus.with_ec(msg.get_ctx()),
            || self.handle_compute_request_error(msg),
        )
    }
}

impl Handler<TypedEvent<CommitteeMemberExpelled>> for ThresholdPlaintextAggregator {
    type Result = ();

    fn handle(
        &mut self,
        msg: TypedEvent<CommitteeMemberExpelled>,
        _ctx: &mut Self::Context,
    ) -> Self::Result {
        trap(
            EType::PlaintextAggregation,
            &self.bus.with_ec(msg.get_ctx()),
            || {
                let (msg, ec) = msg.into_components();
                let Some(party_id) = msg.party_id else {
                    return Ok(());
                };

                let was_ready = self.aggregation_inputs_ready();
                self.handle_member_expelled(party_id, &ec)?;
                let became_ready = !was_ready && self.aggregation_inputs_ready();
                if became_ready {
                    self.publish_inputs_ready(ec.clone())?;
                }

                if became_ready && self.can_run_aggregation_effects() {
                    if let Some(ThresholdPlaintextAggregatorState::VerifyingC6(ref state)) =
                        self.state.get()
                    {
                        self.dispatch_c6_verification(state.c6_proofs.clone(), ec)?;
                    }
                }

                Ok(())
            },
        )
    }
}

impl Handler<TypedEvent<CommitteeMemberExcluded>> for ThresholdPlaintextAggregator {
    type Result = ();

    fn handle(
        &mut self,
        msg: TypedEvent<CommitteeMemberExcluded>,
        _ctx: &mut Self::Context,
    ) -> Self::Result {
        trap(
            EType::PlaintextAggregation,
            &self.bus.with_ec(msg.get_ctx()),
            || {
                let (msg, ec) = msg.into_components();
                let Some(party_id) = msg.party_id else {
                    return Ok(());
                };

                let was_ready = self.aggregation_inputs_ready();
                self.handle_member_expelled(party_id, &ec)?;
                let became_ready = !was_ready && self.aggregation_inputs_ready();
                if became_ready {
                    self.publish_inputs_ready(ec.clone())?;
                }
                if became_ready && self.can_run_aggregation_effects() {
                    if let Some(ThresholdPlaintextAggregatorState::VerifyingC6(ref state)) =
                        self.state.get()
                    {
                        self.dispatch_c6_verification(state.c6_proofs.clone(), ec)?;
                    }
                }
                Ok(())
            },
        )
    }
}

impl Handler<TypedEvent<ShareVerificationComplete>> for ThresholdPlaintextAggregator {
    type Result = ();
    fn handle(
        &mut self,
        msg: TypedEvent<ShareVerificationComplete>,
        _ctx: &mut Self::Context,
    ) -> Self::Result {
        trap(
            EType::PlaintextAggregation,
            &self.bus.with_ec(msg.get_ctx()),
            || self.handle_c6_verification_complete(msg),
        )
    }
}

impl Handler<TypedEvent<AggregationProofSigned>> for ThresholdPlaintextAggregator {
    type Result = ();
    fn handle(
        &mut self,
        msg: TypedEvent<AggregationProofSigned>,
        ctx: &mut Self::Context,
    ) -> Self::Result {
        if !self.can_run_aggregation_effects() {
            return;
        }
        trap(
            EType::PlaintextAggregation,
            &self.bus.with_ec(msg.get_ctx()),
            || self.handle_aggregation_proof_signed(msg, ctx),
        )
    }
}

impl Handler<Die> for ThresholdPlaintextAggregator {
    type Result = ();
    fn handle(&mut self, _: Die, ctx: &mut Self::Context) -> Self::Result {
        ctx.stop()
    }
}
