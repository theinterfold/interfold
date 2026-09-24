// SPDX-License-Identifier: LGPL-3.0-only

//! Apply node-registry, collateral, activation, and configuration facts.

use super::*;

impl Handler<TypedEvent<e3_events::EvmLogObserved>> for Sortition {
    type Result = ();

    fn handle(&mut self, msg: TypedEvent<e3_events::EvmLogObserved>, _: &mut Self::Context) {
        let (log, ec) = msg.into_components();
        if ec.source() != e3_events::EventSource::Evm {
            return;
        }
        trap(EType::Sortition, &self.bus.with_ec(&ec), || {
            if let Some(event) = e3_events::AdmissionUpdated::from_observed_log(&log)? {
                self.admission.try_mutate(&ec, |mut admission| {
                    admission.record(&event)?;
                    Ok(admission)
                })?;
            }
            Ok(())
        })
    }
}

impl Handler<TypedEvent<e3_events::AdmissionUpdated>> for Sortition {
    type Result = ();

    fn handle(&mut self, msg: TypedEvent<e3_events::AdmissionUpdated>, _: &mut Self::Context) {
        let (event, ec) = msg.into_components();
        trap(EType::Sortition, &self.bus.with_ec(&ec), || {
            self.admission.try_mutate(&ec, |mut admission| {
                admission.record(&event)?;
                Ok(admission)
            })
        })
    }
}

impl Handler<TypedEvent<BondOwnerSetAt>> for Sortition {
    type Result = ();

    fn handle(&mut self, msg: TypedEvent<BondOwnerSetAt>, _: &mut Self::Context) {
        let (event, ec) = msg.into_components();
        trap(EType::Sortition, &self.bus.with_ec(&ec), || {
            self.bond_owners.try_mutate(&ec, |mut owners| {
                owners.record(&event.owner, event.timepoint)?;
                Ok(owners)
            })
        })
    }
}

impl Handler<TypedEvent<CiphernodeAdded>> for Sortition {
    type Result = ();

    fn handle(&mut self, msg: TypedEvent<CiphernodeAdded>, _: &mut Self::Context) -> Self::Result {
        let (msg, ec) = msg.into_components();
        trap(EType::Sortition, &self.bus.with_ec(&ec), || {
            let chain_id = msg.chain_id;
            let addr = msg.address.clone();

            self.node_state.try_mutate(&ec, |mut state_map| {
                NodeRegistry::add_node(&mut state_map, chain_id, addr.clone());
                Ok(state_map)
            })?;
            self.backends.try_mutate(&ec, move |mut list_map| {
                let default_backend = list_map
                    .get(&u64::MAX)
                    .cloned()
                    .unwrap_or_else(SortitionBackend::score);

                list_map
                    .entry(chain_id)
                    .or_insert_with(|| default_backend)
                    .add(addr);
                Ok(list_map)
            })?;
            Ok(())
        })
    }
}

impl Handler<TypedEvent<CiphernodeRemoved>> for Sortition {
    type Result = ();

    fn handle(
        &mut self,
        msg: TypedEvent<CiphernodeRemoved>,
        _: &mut Self::Context,
    ) -> Self::Result {
        let (msg, ec) = msg.into_components();
        trap(EType::Sortition, &self.bus.with_ec(&ec), || {
            let chain_id = msg.chain_id;
            let addr = msg.address.clone();

            self.node_state.try_mutate(&ec, |mut state_map| {
                NodeRegistry::remove_node(&mut state_map, chain_id, &addr);
                Ok(state_map)
            })?;
            self.backends.try_mutate(&ec, move |mut list_map| {
                if let Some(backend) = list_map.get_mut(&chain_id) {
                    backend.remove(addr);
                }
                Ok(list_map)
            })?;
            Ok(())
        })
    }
}

impl Handler<TypedEvent<TicketBalanceUpdatedAt>> for Sortition {
    type Result = ();

    fn handle(
        &mut self,
        msg: TypedEvent<TicketBalanceUpdatedAt>,
        _: &mut Self::Context,
    ) -> Self::Result {
        let (event, ec) = msg.into_components();
        let balance = &event.balance;
        trap(EType::Sortition, &self.bus.with_ec(&ec), || {
            self.node_state.try_mutate(&ec, |mut state_map| {
                NodeRegistry::set_ticket_balance(
                    &mut state_map,
                    balance.chain_id,
                    balance.operator.clone(),
                    balance.new_balance,
                    event.position,
                );
                Ok(state_map)
            })
        })
    }
}

impl Handler<TypedEvent<OperatorActivationChangedAt>> for Sortition {
    type Result = ();

    fn handle(
        &mut self,
        msg: TypedEvent<OperatorActivationChangedAt>,
        _: &mut Self::Context,
    ) -> Self::Result {
        let (event, ec) = msg.into_components();
        let activation = &event.activation;
        trap(EType::Sortition, &self.bus.with_ec(&ec), || {
            self.node_state.try_mutate(&ec, |mut state_map| {
                NodeRegistry::set_operator_active(
                    &mut state_map,
                    activation.chain_id,
                    activation.operator.clone(),
                    activation.active,
                    event.position,
                );
                Ok(state_map)
            })
        })
    }
}

impl Handler<TypedEvent<ConfigurationUpdatedAt>> for Sortition {
    type Result = ();

    fn handle(
        &mut self,
        msg: TypedEvent<ConfigurationUpdatedAt>,
        _: &mut Self::Context,
    ) -> Self::Result {
        let (event, ec) = msg.into_components();
        if !event.configuration.affects_eligibility() {
            return;
        }
        trap(EType::Sortition, &self.bus.with_ec(&ec), || {
            self.node_state.try_mutate(&ec, |mut state_map| {
                NodeRegistry::update_configuration(&mut state_map, &event);
                Ok(state_map)
            })
        })
    }
}

impl Handler<TypedEvent<CommitteeRequested>> for Sortition {
    type Result = ();

    fn handle(
        &mut self,
        msg: TypedEvent<CommitteeRequested>,
        _: &mut Self::Context,
    ) -> Self::Result {
        let (msg, ec) = msg.into_components();
        let e3_id = msg.e3_id.clone();
        let result = self.node_state.try_mutate(&ec, |mut state_map| {
            NodeRegistry::record_sortition_snapshot(
                &mut state_map,
                &e3_id,
                msg.request_block,
                msg.ticket_price,
            );
            Ok(state_map)
        });
        if let Err(error) = result {
            self.bus.with_ec(&ec).err(EType::Sortition, error);
            return;
        }

        if let Err(error) = self.recovery.try_mutate(&ec, |mut recovery| {
            recovery.seeds.insert(e3_id.clone(), msg.seed);
            Ok(recovery)
        }) {
            self.bus.with_ec(&ec).err(EType::Sortition, error);
            return;
        }
        let pending = self
            .recovery
            .get()
            .and_then(|recovery| recovery.pending_requests.get(&e3_id).cloned());
        if self.effects_enabled {
            if let Some(request) = pending {
                self.perform_sortition(request);
            }
        }
    }
}
