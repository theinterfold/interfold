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
                    self.resume_in_flight_work(ec.clone())
                });
                // Re-arm the node-proof bound after the state is hydrated. None of the events
                // that arm it in-process are replayed on recovery, so without this a restart
                // while proofs are outstanding would wait forever for a member that is gone.
                self.rearm_node_proof_deadline(ctx, &ec);
            }
            InterfoldEventData::E3RequestComplete(_) => self.notify_sync(ctx, Die),
            InterfoldEventData::CommitteeMemberExpelled(data) => {
                // Only process raw events from chain (party_id not yet resolved).
                if data.party_id.is_some() {
                    return;
                }

                let node_addr = data.node;

                if data.e3_id != self.e3_id {
                    error!(
                        e3_id = %self.e3_id,
                        "Wrong e3_id sent to PublicKeyAggregator for expulsion. This should not happen."
                    );
                    return;
                }

                info!(
                    "PublicKeyAggregator: committee member expelled: {} for e3_id={}",
                    node_addr, data.e3_id
                );
                trap(EType::PublickeyAggregation, &self.bus.with_ec(&ec), || {
                    let was_collecting = matches!(
                        self.state.get(),
                        Some(PublicKeyAggregatorState::Collecting { .. })
                    );

                    self.handle_member_expelled(node_addr, &ec)?;

                    // If we just transitioned to VerifyingC1, dispatch C1 verification
                    // using the c1_proofs now stored in the VerifyingC1 state (already
                    // cleaned of the expelled node's entry).
                    if was_collecting && self.aggregation_inputs_ready() {
                        self.publish_inputs_ready(ec.clone())?;
                    }
                    if was_collecting && self.can_run_aggregation_effects() {
                        if let Some(PublicKeyAggregatorState::VerifyingC1 {
                            submission_order,
                            c1_proofs,
                            ..
                        }) = self.state.get()
                        {
                            self.dispatch_c1_verification(
                                &submission_order,
                                &c1_proofs,
                                ec.clone(),
                            )?;
                        }
                    }
                    Ok(())
                });
            }
            InterfoldEventData::CommitteeMemberExcluded(data) => {
                // Sortition republishes this event with a party ID. The public-key collector uses
                // the raw event because it filters by the node address before that enrichment.
                if data.party_id.is_some() {
                    return;
                }

                let node_addr = data.node;
                if data.e3_id != self.e3_id {
                    error!(
                        e3_id = %self.e3_id,
                        "Wrong e3_id sent to PublicKeyAggregator for local exclusion."
                    );
                    return;
                }

                info!(
                    node = %node_addr,
                    e3_id = %data.e3_id,
                    proof_type = %data.proof_type,
                    "PublicKeyAggregator excluding a quorum-confirmed faulty member"
                );
                trap(EType::PublickeyAggregation, &self.bus.with_ec(&ec), || {
                    let was_collecting = matches!(
                        self.state.get(),
                        Some(PublicKeyAggregatorState::Collecting { .. })
                    );
                    self.handle_member_expelled(node_addr, &ec)?;
                    if was_collecting && self.aggregation_inputs_ready() {
                        self.publish_inputs_ready(ec.clone())?;
                    }
                    if was_collecting && self.can_run_aggregation_effects() {
                        if let Some(PublicKeyAggregatorState::VerifyingC1 {
                            submission_order,
                            c1_proofs,
                            ..
                        }) = self.state.get()
                        {
                            self.dispatch_c1_verification(
                                &submission_order,
                                &c1_proofs,
                                ec.clone(),
                            )?;
                        }
                    }
                    Ok(())
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
        ctx: &mut Self::Context,
    ) -> Self::Result {
        if msg.e3_id != self.e3_id || msg.is_aggregator == self.is_aggregator {
            return;
        }
        self.is_aggregator = msg.is_aggregator;
        if self.can_run_aggregation_effects() {
            let ec = msg.get_ctx().clone();
            trap(EType::PublickeyAggregation, &self.bus.with_ec(&ec), || {
                self.resume_in_flight_work(ec.clone())
            });
            // A promoted standby inherits the same missing node proofs the demoted
            // aggregator was waiting on, so it starts its own bounded wait here rather than
            // stalling for the rest of the E3.
            if !self.missing_node_proof_parties().is_empty() {
                self.arm_node_proof_deadline(ctx, &ec);
            }
        } else {
            // Demoted: stop counting down. The newly promoted aggregator owns the bound.
            self.cancel_node_proof_deadline(ctx);
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
                error!(
                    e3_id = %self.e3_id,
                    party_id,
                    "Wrong e3_id sent to aggregator. This should not happen."
                );
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
                if let Some(PublicKeyAggregatorState::VerifyingC1 {
                    submission_order,
                    c1_proofs,
                    ..
                }) = self.state.get()
                {
                    self.dispatch_c1_verification(&submission_order, &c1_proofs, ec)?;
                }
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
        if !self.can_run_aggregation_effects() {
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
        ctx: &mut Self::Context,
    ) -> Self::Result {
        if !self.can_run_aggregation_effects() {
            return;
        }
        let ec = msg.get_ctx().clone();
        trap(
            EType::PublickeyAggregation,
            &self.bus.with_ec(msg.get_ctx()),
            || self.handle_pk_aggregation_proof_signed(msg),
        );
        // C5 is signed; from here the aggregator only waits on honest-party NodeDkgFold
        // proofs. Bound that wait — an unfinishable member used to hold the E3 open until
        // the canonical deadline.
        if !self.missing_node_proof_parties().is_empty() {
            self.arm_node_proof_deadline(ctx, &ec);
        }
    }
}

impl Handler<TypedEvent<DKGRecursiveAggregationComplete>> for PublicKeyAggregator {
    type Result = ();

    fn handle(
        &mut self,
        msg: TypedEvent<DKGRecursiveAggregationComplete>,
        ctx: &mut Self::Context,
    ) -> Self::Result {
        if !self.can_run_aggregation_effects() {
            return;
        }
        let ec = msg.get_ctx().clone();
        trap(
            EType::PublickeyAggregation,
            &self.bus.with_ec(msg.get_ctx()),
            || self.handle_dkg_recursive_aggregation_complete(msg),
        );
        // Every honest proof in: the wait is over. Otherwise keep (or start) the bound —
        // arming is idempotent, so a partial delivery never extends the original budget.
        if self.missing_node_proof_parties().is_empty() {
            self.cancel_node_proof_deadline(ctx);
        } else {
            self.arm_node_proof_deadline(ctx, &ec);
        }
    }
}

impl Handler<TypedEvent<ComputeResponse>> for PublicKeyAggregator {
    type Result = ();

    fn handle(
        &mut self,
        msg: TypedEvent<ComputeResponse>,
        _ctx: &mut Self::Context,
    ) -> Self::Result {
        if !self.can_run_aggregation_effects() {
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
        if !self.can_run_aggregation_effects() {
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
