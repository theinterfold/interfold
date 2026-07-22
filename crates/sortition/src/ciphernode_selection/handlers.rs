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
            InterfoldEventData::AggregatorLeaseUpdated(data) => {
                self.notify_sync(ctx, TypedEvent::new(data, ec))
            }
            InterfoldEventData::CommitteePublished(data) => {
                self.notify_sync(ctx, TypedEvent::new(data, ec))
            }
            InterfoldEventData::PlaintextOutputPublished(data) => {
                self.notify_sync(ctx, TypedEvent::new(data, ec))
            }
            InterfoldEventData::E3Failed(data) => self.notify_sync(ctx, TypedEvent::new(data, ec)),
            InterfoldEventData::Shutdown(data) => self.notify_sync(ctx, data),
            _ => (),
        }
    }
}

/// Handles `E3Requested` events received directly from the EventBus.
///
/// This handler populates `e3_cache` during sync replay, when `Sortition` gates its
/// `E3Requested` subscription behind `EffectsEnabled` and therefore does NOT forward
/// `WithSortitionTicket` messages to us. Without this handler the cache would be empty
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
        _: &mut Self::Context,
    ) -> Self::Result {
        trap(
            EType::Sortition,
            &self.bus.with_ec(msg.get_ctx()),
            move || {
                self.state.try_mutate(msg.get_ctx(), |mut state| {
                    state.e3_cache.remove(&msg.e3_id);
                    state.committees.remove(&msg.e3_id);
                    state.expelled.remove(&msg.e3_id);
                    state.unresponsive.remove(&msg.e3_id);
                    state.is_aggregator.remove(&msg.e3_id);
                    Ok(state)
                })?;
                self.failover.try_mutate(msg.get_ctx(), |mut state| {
                    state.leases.remove(&msg.e3_id);
                    Ok(state)
                })
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

                self.state.try_mutate(&ec, |mut selector_state| {
                    selector_state
                        .committees
                        .insert(msg.e3_id.clone(), Committee::new(msg.committee.clone()));
                    selector_state
                        .expelled
                        .entry(msg.e3_id.clone())
                        .or_default();
                    Ok(selector_state)
                })?;

                // Check if this node is in the finalized committee
                if let Some(party_id) = msg.committee.iter().position(|addr| addr == &self.address)
                {
                    info!(
                        node = self.address,
                        party_id = party_id,
                        "Node is in finalized committee, emitting CiphernodeSelected"
                    );

                    bus.publish(
                        CiphernodeSelected {
                            party_id: party_id as u64,
                            e3_id: msg.e3_id.clone(),
                            threshold_m: e3_meta.threshold_m,
                            threshold_n: e3_meta.threshold_n,
                            error_size: e3_meta.error_size.clone(),
                            params_preset: e3_meta.params_preset,
                            params: e3_meta.params.clone(),
                            seed: e3_meta.seed,
                        },
                        ec.clone(),
                    )?;
                } else {
                    info!(node = self.address, "Node not in finalized committee");
                }

                self.update_aggregator_status(&msg.e3_id, &ec, true)?;

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
        _ctx: &mut Self::Context,
    ) -> Self::Result {
        trap(EType::Sortition, &self.bus.with_ec(msg.get_ctx()), || {
            let (msg, ec) = msg.into_components();
            let Some(party_id) = msg.party_id else {
                return Ok(());
            };

            self.state.try_mutate(&ec, |mut state| {
                let expelled = state.expelled.entry(msg.e3_id.clone()).or_default();
                if !expelled.contains(&party_id) {
                    expelled.push(party_id);
                    expelled.sort_unstable();
                }
                Ok(state)
            })?;

            self.update_aggregator_status(&msg.e3_id, &ec, false)
        })
    }
}

impl CiphernodeSelector {
    fn update_aggregator_status_without_context(
        &mut self,
        e3_id: &E3id,
        force_emit: bool,
    ) -> Result<()> {
        let Some(state) = self.state.get() else {
            bail!("Could not get selector state");
        };
        let committee = state
            .committees
            .get(e3_id)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("Missing finalized committee for {e3_id}"))?;
        let expelled = state.expelled.get(e3_id).cloned().unwrap_or_default();
        let unresponsive = state.unresponsive.get(e3_id).cloned().unwrap_or_default();
        let is_aggregator = committee.effective_aggregator(&self.address, &expelled, &unresponsive);
        let previous = state.is_aggregator.get(e3_id).copied();

        if !force_emit && previous == Some(is_aggregator) {
            return Ok(());
        }
        self.bus.publish_without_context(AggregatorChanged {
            e3_id: e3_id.clone(),
            is_aggregator,
        })?;
        self.state.try_mutate_without_context(|mut state| {
            state.is_aggregator.insert(e3_id.clone(), is_aggregator);
            Ok(state)
        })
    }

    fn eligible_for(&self, e3_id: &E3id) -> Result<EligibleAggregators> {
        let state = self
            .state
            .get()
            .ok_or_else(|| anyhow::anyhow!("Could not get selector state"))?;
        let committee = state
            .committees
            .get(e3_id)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("Missing finalized committee for {e3_id}"))?;
        let skipped: Vec<u64> = state
            .expelled
            .get(e3_id)
            .into_iter()
            .flatten()
            .chain(state.unresponsive.get(e3_id).into_iter().flatten())
            .copied()
            .collect();
        let standbys = committee.aggregator_standbys(&skipped, committee.len());
        Ok(EligibleAggregators {
            committee,
            skipped,
            standbys,
        })
    }

    pub(super) fn evaluate_failover(&mut self, _: &mut Context<Self>) {
        let now = Self::now_secs();
        let Some(failover) = self.failover.get() else {
            return;
        };

        for (e3_id, mut lease) in failover.leases {
            let Ok(eligible) = self.eligible_for(&e3_id) else {
                continue;
            };
            let active = eligible
                .committee
                .active_aggregator_party_id(&eligible.skipped);
            if active != lease.active_party_id {
                lease.active_party_id = active;
                lease.failure_requested = false;
                lease.attempt_deadline = next_attempt_deadline(
                    now,
                    lease.stage_deadline,
                    eligible.standbys.len().max(1),
                );
                if let Err(error) = self.failover.try_mutate_without_context(|mut state| {
                    state.leases.insert(e3_id.clone(), lease.clone());
                    Ok(state)
                }) {
                    self.bus.err(EType::Sortition, error);
                    continue;
                }
            }

            if let Err(error) = self.update_aggregator_status_without_context(&e3_id, false) {
                self.bus.err(EType::Sortition, error);
            }

            match decide_failover(now, &lease, &eligible.standbys) {
                FailoverDecision::Hold => {}
                FailoverDecision::Promote {
                    demote,
                    promote_to,
                    new_addr,
                } => {
                    let result: Result<()> = (|| {
                        self.state.try_mutate_without_context(|mut state| {
                            let unresponsive = state.unresponsive.entry(e3_id.clone()).or_default();
                            if !unresponsive.contains(&demote) {
                                unresponsive.push(demote);
                                unresponsive.sort_unstable();
                            }
                            Ok(state)
                        })?;
                        let remaining = self.eligible_for(&e3_id)?.standbys;
                        self.failover.try_mutate_without_context(|mut state| {
                            let lease = state.leases.get_mut(&e3_id).ok_or_else(|| {
                                anyhow::anyhow!("Missing failover lease for {e3_id}")
                            })?;
                            lease.active_party_id = Some(promote_to);
                            lease.attempt_deadline = next_attempt_deadline(
                                now,
                                lease.stage_deadline,
                                remaining.len().max(1),
                            );
                            Ok(state)
                        })?;
                        self.update_aggregator_status_without_context(&e3_id, false)?;
                        info!(%e3_id, demote, promote_to, %new_addr, "Promoted deterministic standby aggregator");
                        Ok(())
                    })();
                    if let Err(error) = result {
                        self.bus.err(EType::Sortition, error);
                    }
                }
                FailoverDecision::Exhausted { demote } => {
                    if let Some(demote) = demote {
                        let result: Result<()> = (|| {
                            self.state.try_mutate_without_context(|mut state| {
                                let unresponsive =
                                    state.unresponsive.entry(e3_id.clone()).or_default();
                                if !unresponsive.contains(&demote) {
                                    unresponsive.push(demote);
                                    unresponsive.sort_unstable();
                                }
                                Ok(state)
                            })?;
                            self.update_aggregator_status_without_context(&e3_id, false)
                        })();
                        if let Err(error) = result {
                            self.bus.err(EType::Sortition, error);
                            continue;
                        }
                    }
                    let event = AggregatorFailoverExhausted {
                        e3_id: e3_id.clone(),
                        phase: lease.phase,
                        stage_deadline: lease.stage_deadline,
                    };
                    match self.bus.publish_without_context(event) {
                        Ok(()) => {
                            if let Err(error) =
                                self.failover.try_mutate_without_context(|mut state| {
                                    if let Some(lease) = state.leases.get_mut(&e3_id) {
                                        lease.failure_requested = true;
                                    }
                                    Ok(state)
                                })
                            {
                                self.bus.err(EType::Sortition, error);
                            }
                            info!(%e3_id, ?demote, "Aggregator standbys exhausted; requested canonical on-chain failure");
                        }
                        Err(error) => self.bus.err(EType::Sortition, error),
                    }
                }
            }
        }
    }

    fn settle_failover_phase(
        &mut self,
        e3_id: &E3id,
        phase: e3_events::AggregatorPhase,
        ec: &EventContext<Sequenced>,
    ) -> Result<()> {
        self.failover.try_mutate(ec, |mut state| {
            if state
                .leases
                .get(e3_id)
                .is_some_and(|lease| lease.phase == phase)
            {
                state.leases.remove(e3_id);
            }
            Ok(state)
        })
    }
}

impl Handler<TypedEvent<AggregatorLeaseUpdated>> for CiphernodeSelector {
    type Result = ();

    fn handle(&mut self, msg: TypedEvent<AggregatorLeaseUpdated>, _: &mut Self::Context) {
        trap(EType::Sortition, &self.bus.with_ec(msg.get_ctx()), || {
            let (msg, ec) = msg.into_components();
            let state = self
                .state
                .get()
                .ok_or_else(|| anyhow::anyhow!("Could not get selector state"))?;
            let committee = state.committees.get(&msg.e3_id).cloned();
            let expelled = state.expelled.get(&msg.e3_id).cloned().unwrap_or_default();

            self.state.try_mutate(&ec, |mut state| {
                state.unresponsive.remove(&msg.e3_id);
                Ok(state)
            })?;
            let standbys = committee
                .as_ref()
                .map(|committee| committee.aggregator_standbys(&expelled, committee.len()))
                .unwrap_or_default();
            let now = Self::now_secs();
            self.failover.try_mutate(&ec, |mut state| {
                state.leases.insert(
                    msg.e3_id.clone(),
                    arm_lease(msg.phase, now, msg.stage_deadline, &standbys),
                );
                Ok(state)
            })?;
            if committee.is_some() {
                self.update_aggregator_status(&msg.e3_id, &ec, true)?;
            }
            Ok(())
        })
    }
}

impl Handler<TypedEvent<CommitteePublished>> for CiphernodeSelector {
    type Result = ();

    fn handle(&mut self, msg: TypedEvent<CommitteePublished>, _: &mut Self::Context) {
        trap(EType::Sortition, &self.bus.with_ec(msg.get_ctx()), || {
            self.settle_failover_phase(
                &msg.e3_id,
                e3_events::AggregatorPhase::AwaitingPublicKey,
                msg.get_ctx(),
            )
        })
    }
}

impl Handler<TypedEvent<PlaintextOutputPublished>> for CiphernodeSelector {
    type Result = ();

    fn handle(&mut self, msg: TypedEvent<PlaintextOutputPublished>, _: &mut Self::Context) {
        trap(EType::Sortition, &self.bus.with_ec(msg.get_ctx()), || {
            self.settle_failover_phase(
                &msg.e3_id,
                e3_events::AggregatorPhase::AwaitingPlaintext,
                msg.get_ctx(),
            )
        })
    }
}

impl Handler<TypedEvent<E3Failed>> for CiphernodeSelector {
    type Result = ();

    fn handle(&mut self, msg: TypedEvent<E3Failed>, _: &mut Self::Context) {
        trap(EType::Sortition, &self.bus.with_ec(msg.get_ctx()), || {
            self.failover.try_mutate(msg.get_ctx(), |mut state| {
                state.leases.remove(&msg.e3_id);
                Ok(state)
            })
        })
    }
}

impl Handler<EmitPersistedAggregatorState> for CiphernodeSelector {
    type Result = ();

    fn handle(
        &mut self,
        _: EmitPersistedAggregatorState,
        _ctx: &mut Self::Context,
    ) -> Self::Result {
        let Some(state) = self.state.get() else {
            return;
        };

        for (e3_id, is_aggregator) in state.is_aggregator {
            if let Err(err) = self.bus.publish_without_context(AggregatorChanged {
                e3_id,
                is_aggregator,
            }) {
                self.bus.err(EType::Sortition, err);
            }
        }
    }
}

impl Handler<Shutdown> for CiphernodeSelector {
    type Result = ();
    fn handle(&mut self, _msg: Shutdown, ctx: &mut Self::Context) -> Self::Result {
        info!("Killing CiphernodeSelector");
        ctx.stop();
    }
}

#[cfg(test)]
mod failover_actor_tests {
    use super::*;
    use actix::{Actor, Addr, Handler};
    use e3_data::{DataStore, InMemStore};
    use e3_events::{
        hlc_factory::HlcFactory, EventBus, EventBusConfig, HistoryCollector, InterfoldEvent,
        PersistEvent, Sequencer, TakeEvents,
    };

    #[derive(Default)]
    struct TestEventStore {
        next_seq: u64,
    }

    impl Actor for TestEventStore {
        type Context = Context<Self>;
    }

    impl Handler<PersistEvent> for TestEventStore {
        type Result = Result<Option<InterfoldEvent>>;

        fn handle(&mut self, msg: PersistEvent, _: &mut Self::Context) -> Self::Result {
            let seq = self.next_seq;
            self.next_seq += 1;
            Ok(Some(msg.0.into_sequenced(seq)))
        }
    }

    fn test_bus() -> (BusHandle, Addr<HistoryCollector<InterfoldEvent>>) {
        let event_bus =
            EventBus::<InterfoldEvent>::new(EventBusConfig { deduplicate: true }).start();
        let store = TestEventStore::default().start();
        let sequencer = Sequencer::new(&event_bus, store.recipient()).start();
        let bus = BusHandle::new(event_bus, sequencer, HlcFactory::new()).enable("failover-test");
        let history = bus.history();
        (bus, history)
    }

    fn test_persistable<T: e3_data::PersistableData>(value: T) -> Persistable<T> {
        let store = InMemStore::new(false).start();
        let repository = Repository::<T>::new(DataStore::from_in_mem(&store));
        repository.to_connector().send(Some(value))
    }

    #[derive(Message)]
    #[rtype(result = "()")]
    struct EvaluateNow;

    impl Handler<EvaluateNow> for CiphernodeSelector {
        type Result = ();

        fn handle(&mut self, _: EvaluateNow, ctx: &mut Self::Context) {
            self.evaluate_failover(ctx);
        }
    }

    #[derive(Message)]
    #[rtype(result = "(CiphernodeSelectorState, AggregatorFailoverState)")]
    struct GetFailoverState;

    impl Handler<GetFailoverState> for CiphernodeSelector {
        type Result = MessageResult<GetFailoverState>;

        fn handle(&mut self, _: GetFailoverState, _: &mut Self::Context) -> Self::Result {
            MessageResult((
                self.state.get().expect("selector state").clone(),
                self.failover.get().expect("failover state").clone(),
            ))
        }
    }

    #[actix::test]
    async fn runtime_promotes_all_standbys_then_demotes_and_exhausts_once() -> Result<()> {
        let (bus, history) = test_bus();
        let e3_id = E3id::new("9", 31_337);
        let committee = Committee::new(vec!["0xa".into(), "0xb".into(), "0xc".into()]);
        let mut selector_state = CiphernodeSelectorState::default();
        selector_state.committees.insert(e3_id.clone(), committee);
        selector_state.is_aggregator.insert(e3_id.clone(), false);
        let mut failover_state = AggregatorFailoverState::default();
        failover_state.leases.insert(
            e3_id.clone(),
            super::super::failover::AggregatorLease {
                phase: e3_events::AggregatorPhase::AwaitingPlaintext,
                stage_deadline: 0,
                attempt_deadline: 0,
                active_party_id: Some(0),
                failure_requested: false,
            },
        );

        let actor = CiphernodeSelector::new(
            &bus,
            test_persistable(selector_state),
            test_persistable(failover_state),
            "0xc",
        )
        .start();

        actor.send(EvaluateNow).await?;
        actor.send(EvaluateNow).await?;
        actor.send(EvaluateNow).await?;

        let received = history.send(TakeEvents::new(3)).await?;
        assert!(!received.timed_out, "timed out waiting for failover events");
        let statuses: Vec<bool> = received
            .events
            .iter()
            .filter_map(|event| match event.get_data() {
                InterfoldEventData::AggregatorChanged(event) => Some(event.is_aggregator),
                _ => None,
            })
            .collect();
        assert_eq!(statuses, vec![true, false]);
        assert_eq!(
            received
                .events
                .iter()
                .filter(|event| matches!(
                    event.get_data(),
                    InterfoldEventData::AggregatorFailoverExhausted(_)
                ))
                .count(),
            1
        );

        actor.send(EvaluateNow).await?;
        let (selector, failover) = actor.send(GetFailoverState).await?;
        assert_eq!(selector.unresponsive.get(&e3_id), Some(&vec![0, 1, 2]));
        assert_eq!(selector.is_aggregator.get(&e3_id), Some(&false));
        assert!(failover.leases[&e3_id].failure_requested);

        Ok(())
    }
}
