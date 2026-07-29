// SPDX-License-Identifier: LGPL-3.0-only

//! Actix lifecycle, timeout ownership, and message routing.

use super::*;

impl Actor for ThresholdPlaintextAggregator {
    type Context = Context<Self>;
    fn started(&mut self, ctx: &mut Self::Context) {
        ctx.set_mailbox_capacity(MAILBOX_LIMIT);
        // The absolute deadline and causal context are persisted with `Collecting`, so hydration
        // cannot reset the collection budget or lose the ability to publish the terminal event.
        let Some(ThresholdPlaintextAggregatorState::Collecting(collecting)) = self.state.get()
        else {
            return;
        };
        let timeout = remaining_collection_timeout(collecting.deadline_unix_ms, unix_time_millis());
        info!(
            e3_id = %self.e3_id,
            ?timeout,
            deadline_unix_ms = collecting.deadline_unix_ms,
            "ThresholdPlaintextAggregator started; scheduling remaining decryption-share collection window"
        );
        self.pending.timeout_handle = Some(ctx.notify_later(DecryptionCollectionTimeout, timeout));
    }
}

impl Handler<DecryptionCollectionTimeout> for ThresholdPlaintextAggregator {
    type Result = ();
    fn handle(&mut self, _: DecryptionCollectionTimeout, ctx: &mut Self::Context) -> Self::Result {
        self.pending.timeout_handle = None;

        if self.pending.timeout_firing {
            debug!(e3_id = %self.e3_id, "Decryption timeout publish is already in flight");
            return;
        }

        // Only fail while still collecting shares; once we have transitioned past `Collecting`
        // (VerifyingC6/Computing/…) the round is progressing and the timer is a no-op.
        let Some(ThresholdPlaintextAggregatorState::Collecting(collecting)) = self.state.get()
        else {
            debug!(
                e3_id = %self.e3_id,
                "Decryption-share collection timeout fired but round already progressed past collection; ignoring"
            );
            return;
        };

        let collected = collecting.shares.len();
        let required = self.aggregated_committee_n();
        warn!(
            e3_id = %self.e3_id,
            collected,
            required,
            "Decryption-share collection timed out with {collected}/{required} honest shares; failing E3 round (DecryptionTimeout)"
        );

        let ec = collecting.timeout_context;
        let failure = E3Failed {
            e3_id: self.e3_id.clone(),
            failed_at_stage: E3Stage::CiphertextReady,
            reason: FailureReason::DecryptionTimeout,
        };
        let bus = self.bus.clone();
        let e3_id = self.e3_id.clone();
        self.pending.timeout_firing = true;

        // Spawn, rather than wait, so acknowledged EventBus fanout can deliver the terminal event
        // through this actor's own routing path without a circular mailbox wait.
        ctx.spawn(
            async move { bus.publish_and_wait(failure, Some(ec)).await }
                .into_actor(self)
                .map(move |result, _, ctx| {
                    match result {
                        Ok(()) => info!(
                            e3_id = %e3_id,
                            "Durably published decryption timeout failure"
                        ),
                        Err(error) => warn!(
                            e3_id = %e3_id,
                            %error,
                            "Failed to durably publish decryption timeout failure"
                        ),
                    }
                    ctx.stop();
                }),
        );
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
            InterfoldEventData::ShareVerificationComplete(data) => {
                self.notify_sync(ctx, TypedEvent::new(data, ec))
            }
            InterfoldEventData::AggregationProofSigned(data) => {
                self.notify_sync(ctx, TypedEvent::new(data, ec))
            }
            _ => (),
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
                let Some(ThresholdPlaintextAggregatorState::Collecting(Collecting { .. })) =
                    self.state.get()
                else {
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

                self.add_share(party_id, decryption_share, signed_decryption_proofs, &ec)?;

                // If we transitioned to VerifyingC6, dispatch C6 verification
                // using the proofs persisted in state
                if let Some(ThresholdPlaintextAggregatorState::VerifyingC6(ref state)) =
                    self.state.get()
                {
                    self.dispatch_c6_verification(state.c6_proofs.clone(), ec)?;
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

                self.handle_member_expelled(party_id, &ec)?;

                if let Some(ThresholdPlaintextAggregatorState::VerifyingC6(ref state)) =
                    self.state.get()
                {
                    self.dispatch_c6_verification(state.c6_proofs.clone(), ec)?;
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
