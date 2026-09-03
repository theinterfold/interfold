// SPDX-License-Identifier: LGPL-3.0-only

//! Selector event routing and lifecycle handlers.

use super::*;

impl Handler<InterfoldEvent> for CiphernodeSelector {
    type Result = ();
    fn handle(&mut self, msg: InterfoldEvent, ctx: &mut Self::Context) -> Self::Result {
        let (msg, ec) = msg.into_components();
        match msg {
            InterfoldEventData::E3Requested(data) => {
                self.notify_sync(ctx, TypedEvent::new(data, ec))
            }
            InterfoldEventData::E3RequestComplete(data) => {
                self.notify_sync(ctx, TypedEvent::new(data, ec))
            }
            InterfoldEventData::CommitteeFinalized(data) => {
                self.notify_sync(ctx, TypedEvent::new(data, ec))
            }
            InterfoldEventData::CommitteeMemberExpelled(data) => {
                self.notify_sync(ctx, TypedEvent::new(data, ec))
            }
            InterfoldEventData::CommitteeMemberExcluded(data) => {
                self.notify_sync(ctx, TypedEvent::new(data, ec))
            }
            InterfoldEventData::CiphertextOutputPublished(data) => {
                self.notify_sync(ctx, TypedEvent::new(data, ec))
            }
            InterfoldEventData::PlaintextOutputPublished(data) => {
                self.notify_sync(ctx, TypedEvent::new(data, ec))
            }
            InterfoldEventData::E3StageChanged(data) => {
                self.notify_sync(ctx, TypedEvent::new(data, ec))
            }
            InterfoldEventData::E3Failed(data) => self.notify_sync(ctx, TypedEvent::new(data, ec)),
            InterfoldEventData::AggregationInputsReady(data) => {
                self.notify_sync(ctx, TypedEvent::new(data, ec))
            }
            InterfoldEventData::EffectsEnabled(data) => self.notify_sync(ctx, data),
            InterfoldEventData::Shutdown(data) => self.notify_sync(ctx, data),
            _ => (),
        }
    }
}

/// Handles `E3Requested` events received directly from the EventBus.
///
/// This handler populates `e3_cache` during sync replay. `Sortition` records the request but does
/// not perform selection or forward `WithSortitionTicket` until `EffectsEnabled`. Without this
/// handler the cache would be empty
/// when `CommitteeFinalized` arrives during replay, causing a missing-meta error.
///
/// During live operation both this handler AND the `WithSortitionTicket` handler fire for
/// the same E3. `or_insert` ensures the first write wins; the `WithSortitionTicket`
/// handler then overwrites with identical data via `insert`.
impl Handler<TypedEvent<E3Requested>> for CiphernodeSelector {
    type Result = ();

    fn handle(&mut self, msg: TypedEvent<E3Requested>, _: &mut Self::Context) -> Self::Result {
        trap(EType::Sortition, &self.bus.with_ec(msg.get_ctx()), || {
            self.state.try_mutate(msg.get_ctx(), |mut state| {
                state
                    .e3_cache
                    .entry(msg.e3_id.clone())
                    .or_insert_with(|| e3_meta_from(&msg));
                Ok(state)
            })
        })
    }
}

impl Handler<WithSortitionTicket<TypedEvent<E3Requested>>> for CiphernodeSelector {
    type Result = ();

    fn handle(
        &mut self,
        data: WithSortitionTicket<TypedEvent<E3Requested>>,
        _: &mut Self::Context,
    ) -> Self::Result {
        trap(EType::Sortition, &self.bus.with_ec(data.get_ctx()), || {
            self.state.try_mutate(data.get_ctx(), |mut state| {
                info!(
                    "Mutating selector state: appending data: {:?}",
                    data.e3_id.clone()
                );
                state
                    .e3_cache
                    .insert(data.e3_id.clone(), e3_meta_from(&data));
                Ok(state)
            })?;

            if !data.is_selected() {
                info!(node = &data.address(), "Ciphernode was not selected");
                return Ok(());
            }
            if let Some(tid) = data.ticket_id() {
                info!(
                    node = &data.address(),
                    ticket_id = tid,
                    "Ticket generated for score sortition"
                );
                self.bus.publish(
                    TicketGenerated {
                        e3_id: data.e3_id.clone(),
                        ticket_id: TicketId::Score(tid),
                        node: data.address().to_owned(),
                        party_index: data.party_id(),
                    },
                    data.get_ctx().to_owned(),
                )?;
            }

            Ok(())
        })
    }
}

impl Handler<TypedEvent<E3RequestComplete>> for CiphernodeSelector {
    type Result = ();
    fn handle(
        &mut self,
        msg: TypedEvent<E3RequestComplete>,
        ctx: &mut Self::Context,
    ) -> Self::Result {
        trap(
            EType::Sortition,
            &self.bus.with_ec(msg.get_ctx()),
            move || {
                self.state.try_mutate(msg.get_ctx(), |mut state| {
                    state.e3_cache.remove(&msg.e3_id);
                    state.committees.remove(&msg.e3_id);
                    state.expelled.remove(&msg.e3_id);
                    state.is_aggregator.remove(&msg.e3_id);
                    Ok(state)
                })?;
                self.observed_phases.remove(&msg.e3_id);
                self.ready_phases.remove(&msg.e3_id);
                self.failover.try_mutate(msg.get_ctx(), |mut state| {
                    state.rounds.remove(&msg.e3_id);
                    state.unresponsive.remove(&msg.e3_id);
                    Ok(state)
                })?;
                self.arm_failover_timer(&msg.e3_id, ctx);
                Ok(())
            },
        )
    }
}

impl Handler<TypedEvent<CommitteeFinalized>> for CiphernodeSelector {
    type Result = ();

    fn handle(
        &mut self,
        msg: TypedEvent<CommitteeFinalized>,
        _ctx: &mut Self::Context,
    ) -> Self::Result {
        trap(
            EType::Sortition,
            &self.bus.with_ec(msg.get_ctx()),
            move || {
                let (mut msg, ec) = msg.into_components();
                msg.sort_by_address();
                info!("CiphernodeSelector received CommitteeFinalized.");
                let bus = self.bus.clone();
                info!("Getting selector state...");
                let Some(state) = self.state.get() else {
                    bail!("Could not get selector state");
                };

                info!("Getting e3_meta...");
                let Some(e3_meta) = state.e3_cache.get(&msg.e3_id) else {
                    bail!(
                        "Could not find E3Meta on CiphernodeSelector for {}",
                        msg.e3_id
                    );
                };

                let committee = Committee::new(msg.committee.clone());
                let local_party_id = committee.party_id_for(&self.address);
                self.state.try_mutate(&ec, |mut selector_state| {
                    selector_state
                        .committees
                        .insert(msg.e3_id.clone(), committee);
                    selector_state
                        .expelled
                        .entry(msg.e3_id.clone())
                        .or_default();
                    Ok(selector_state)
                })?;

                // Check if this node is in the finalized committee
                if let Some(party_id) = local_party_id {
                    info!(
                        node = self.address,
                        party_id = party_id,
                        "Node is in finalized committee, emitting CiphernodeSelected"
                    );

                    bus.publish(
                        CiphernodeSelected {
                            party_id,
                            e3_id: msg.e3_id.clone(),
                            threshold_m: e3_meta.threshold_m,
                            threshold_n: e3_meta.threshold_n,
                            error_size: e3_meta.error_size.clone(),
                            params_preset: e3_meta.params_preset,
                            params: e3_meta.params.clone(),
                            seed: e3_meta.seed,
                            committee: msg.committee.clone(),
                            scheme: e3_meta.scheme,
                        },
                        ec.clone(),
                    )?;
                } else {
                    info!(node = self.address, "Node not in finalized committee");
                }

                self.observe_phase(
                    msg.e3_id.clone(),
                    Some(AggregatorPhase::PublicKey),
                    true,
                    &ec,
                    _ctx,
                )?;

                Ok(())
            },
        )
    }
}

impl Handler<TypedEvent<CommitteeMemberExpelled>> for CiphernodeSelector {
    type Result = ();

    fn handle(
        &mut self,
        msg: TypedEvent<CommitteeMemberExpelled>,
        ctx: &mut Self::Context,
    ) -> Self::Result {
        trap(EType::Sortition, &self.bus.with_ec(msg.get_ctx()), || {
            let (msg, ec) = msg.into_components();
            let Some(party_id) = msg.party_id else {
                return Ok(());
            };
            let active_before = self.active_aggregator_party_id(&msg.e3_id);

            self.state.try_mutate(&ec, |mut state| {
                let expelled = state.expelled.entry(msg.e3_id.clone()).or_default();
                if !expelled.contains(&party_id) {
                    expelled.push(party_id);
                    expelled.sort_unstable();
                }
                Ok(state)
            })?;

            if active_before != self.active_aggregator_party_id(&msg.e3_id) {
                self.reconcile_failover_assignment(&msg.e3_id, Some(&ec), ctx)?;
            }
            self.update_aggregator_status(&msg.e3_id, Some(&ec), false)?;
            Ok(())
        })
    }
}

impl Handler<TypedEvent<CommitteeMemberExcluded>> for CiphernodeSelector {
    type Result = ();

    fn handle(
        &mut self,
        msg: TypedEvent<CommitteeMemberExcluded>,
        ctx: &mut Self::Context,
    ) -> Self::Result {
        trap(EType::Sortition, &self.bus.with_ec(msg.get_ctx()), || {
            let (msg, ec) = msg.into_components();
            let Some(party_id) = msg.party_id else {
                return Ok(());
            };
            let active_before = self.active_aggregator_party_id(&msg.e3_id);

            self.state.try_mutate(&ec, |mut state| {
                let excluded = state.expelled.entry(msg.e3_id.clone()).or_default();
                if !excluded.contains(&party_id) {
                    excluded.push(party_id);
                    excluded.sort_unstable();
                }
                Ok(state)
            })?;

            if active_before != self.active_aggregator_party_id(&msg.e3_id) {
                self.reconcile_failover_assignment(&msg.e3_id, Some(&ec), ctx)?;
            }
            self.update_aggregator_status(&msg.e3_id, Some(&ec), false)?;
            Ok(())
        })
    }
}

impl Handler<TypedEvent<CiphertextOutputPublished>> for CiphernodeSelector {
    type Result = ();

    fn handle(
        &mut self,
        msg: TypedEvent<CiphertextOutputPublished>,
        ctx: &mut Self::Context,
    ) -> Self::Result {
        trap(EType::Sortition, &self.bus.with_ec(msg.get_ctx()), || {
            self.observe_phase(
                msg.e3_id.clone(),
                Some(AggregatorPhase::Plaintext),
                false,
                msg.get_ctx(),
                ctx,
            )
        })
    }
}

impl Handler<TypedEvent<PlaintextOutputPublished>> for CiphernodeSelector {
    type Result = ();

    fn handle(
        &mut self,
        msg: TypedEvent<PlaintextOutputPublished>,
        ctx: &mut Self::Context,
    ) -> Self::Result {
        trap(EType::Sortition, &self.bus.with_ec(msg.get_ctx()), || {
            self.observe_phase(msg.e3_id.clone(), None, false, msg.get_ctx(), ctx)
        })
    }
}

impl Handler<TypedEvent<E3StageChanged>> for CiphernodeSelector {
    type Result = ();

    fn handle(&mut self, msg: TypedEvent<E3StageChanged>, ctx: &mut Self::Context) -> Self::Result {
        trap(EType::Sortition, &self.bus.with_ec(msg.get_ctx()), || {
            if matches!(&msg.new_stage, E3Stage::None | E3Stage::Requested) {
                return Ok(());
            }
            self.observe_phase(
                msg.e3_id.clone(),
                phase_for_stage(&msg.new_stage),
                false,
                msg.get_ctx(),
                ctx,
            )
        })
    }
}

impl Handler<TypedEvent<E3Failed>> for CiphernodeSelector {
    type Result = ();

    fn handle(&mut self, msg: TypedEvent<E3Failed>, ctx: &mut Self::Context) -> Self::Result {
        trap(EType::Sortition, &self.bus.with_ec(msg.get_ctx()), || {
            self.observe_phase(msg.e3_id.clone(), None, false, msg.get_ctx(), ctx)
        })
    }
}

impl Handler<TypedEvent<AggregationInputsReady>> for CiphernodeSelector {
    type Result = ();

    fn handle(
        &mut self,
        msg: TypedEvent<AggregationInputsReady>,
        ctx: &mut Self::Context,
    ) -> Self::Result {
        trap(EType::Sortition, &self.bus.with_ec(msg.get_ctx()), || {
            let (msg, ec) = msg.into_components();
            self.observe_aggregation_inputs_ready(msg, &ec, ctx)
        })
    }
}

impl Handler<EffectsEnabled> for CiphernodeSelector {
    type Result = ();

    fn handle(&mut self, _: EffectsEnabled, ctx: &mut Self::Context) -> Self::Result {
        if self.effects_enabled {
            return;
        }
        if let Err(err) = self.reconcile_after_replay(ctx) {
            self.bus.err(EType::Sortition, err);
        }
    }
}

impl Handler<GetCiphernodeSelectorState> for CiphernodeSelector {
    type Result = Result<CiphernodeSelectorState>;

    fn handle(&mut self, _: GetCiphernodeSelectorState, _: &mut Self::Context) -> Self::Result {
        self.state.try_get()
    }
}

impl Handler<Shutdown> for CiphernodeSelector {
    type Result = ();
    fn handle(&mut self, _msg: Shutdown, ctx: &mut Self::Context) -> Self::Result {
        info!("Killing CiphernodeSelector");
        for (_, handle) in self.failover_timers.drain() {
            ctx.cancel_future(handle);
        }
        ctx.stop();
    }
}
