// SPDX-License-Identifier: LGPL-3.0-only

//! Apply node-registry, collateral, activation, and configuration facts.

use super::*;

impl Handler<TypedEvent<BondOwnerSet>> for Sortition {
    type Result = ();

    fn handle(&mut self, msg: TypedEvent<BondOwnerSet>, _: &mut Self::Context) {
        let (event, ec) = msg.into_components();
        trap(EType::Sortition, &self.bus.with_ec(&ec), || {
            self.bond_owners.try_mutate(&ec, |mut owners| {
                owners.record(&event, Self::evm_timepoint(&ec))?;
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

impl Handler<TypedEvent<TicketBalanceUpdated>> for Sortition {
    type Result = ();

    fn handle(
        &mut self,
        msg: TypedEvent<TicketBalanceUpdated>,
        _: &mut Self::Context,
    ) -> Self::Result {
        let (msg, ec) = msg.into_components();
        let timepoint = Self::evm_timepoint(&ec);
        trap(EType::Sortition, &self.bus.with_ec(&ec), || {
            self.node_state.try_mutate(&ec, |mut state_map| {
                NodeRegistry::set_ticket_balance(
                    &mut state_map,
                    msg.chain_id,
                    msg.operator.clone(),
                    msg.new_balance,
                    timepoint,
                );
                Ok(state_map)
            })
        })
    }
}

impl Handler<TypedEvent<OperatorActivationChanged>> for Sortition {
    type Result = ();

    fn handle(
        &mut self,
        msg: TypedEvent<OperatorActivationChanged>,
        _: &mut Self::Context,
    ) -> Self::Result {
        let (msg, ec) = msg.into_components();
        let timepoint = Self::evm_timepoint(&ec);
        trap(EType::Sortition, &self.bus.with_ec(&ec), || {
            self.node_state.try_mutate(&ec, |mut state_map| {
                NodeRegistry::set_operator_active(
                    &mut state_map,
                    msg.chain_id,
                    msg.operator.clone(),
                    msg.active,
                    timepoint,
                );
                Ok(state_map)
            })
        })
    }
}

impl Handler<TypedEvent<ConfigurationUpdated>> for Sortition {
    type Result = ();

    fn handle(
        &mut self,
        msg: TypedEvent<ConfigurationUpdated>,
        _: &mut Self::Context,
    ) -> Self::Result {
        let (msg, ec) = msg.into_components();
        let timepoint = Self::evm_timepoint(&ec);
        trap(EType::Sortition, &self.bus.with_ec(&ec), || {
            let eligibility_parameter = matches!(
                msg.parameter.as_str(),
                "ticketPrice"
                    | "requiredCiphernodeBond"
                    | "ciphernodeBondActiveBps"
                    | "minTicketBalance"
            );

            if !eligibility_parameter {
                return Ok(());
            }

            self.node_state.try_mutate(&ec, |mut state_map| {
                if msg.parameter == "ticketPrice" {
                    NodeRegistry::set_ticket_price(&mut state_map, msg.chain_id, msg.new_value);
                }
                NodeRegistry::invalidate_operator_activity(&mut state_map, msg.chain_id, timepoint);
                Ok(state_map)
            })?;
            Ok(())
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
