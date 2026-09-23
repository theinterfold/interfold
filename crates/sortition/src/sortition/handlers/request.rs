// SPDX-License-Identifier: LGPL-3.0-only

//! E3 ticket sortition and selector dispatch.

use super::*;

impl Handler<TypedEvent<E3Requested>> for Sortition {
    type Result = ();
    fn handle(&mut self, msg: TypedEvent<E3Requested>, _: &mut Self::Context) -> Self::Result {
        let e3_id = msg.e3_id.clone();
        if let Err(error) = self.recovery.try_mutate(msg.get_ctx(), |mut recovery| {
            recovery.pending_requests.insert(e3_id.clone(), msg.clone());
            Ok(recovery)
        }) {
            self.bus.with_ec(msg.get_ctx()).err(EType::Sortition, error);
            return;
        }
        let seed_ready = self
            .recovery
            .get()
            .is_some_and(|recovery| recovery.seeds.contains_key(&e3_id));
        if !seed_ready {
            info!(e3_id = %e3_id, "Waiting for the delayed sortition seed");
            return;
        }
        if self.effects_enabled {
            self.perform_sortition(msg);
        }
    }
}

impl Handler<EffectsEnabled> for Sortition {
    type Result = ();

    fn handle(&mut self, _: EffectsEnabled, _: &mut Self::Context) -> Self::Result {
        self.effects_enabled = true;
        let recovery = self.recovery.get().unwrap_or_default();
        let mut requests = recovery
            .pending_requests
            .iter()
            .filter(|(e3_id, _)| recovery.seeds.contains_key(e3_id))
            .map(|(_, request)| request.clone())
            .collect::<Vec<_>>();
        requests.sort_by_key(EventContextAccessors::ts);
        let membership_e3s = recovery
            .pending_expulsions
            .keys()
            .chain(recovery.pending_exclusions.keys())
            .cloned()
            .collect::<HashSet<_>>();

        for request in requests {
            self.perform_sortition(request);
        }
        for e3_id in membership_e3s {
            self.redrive_membership_changes(&e3_id);
        }
    }
}

impl Sortition {
    pub(super) fn perform_sortition(&mut self, msg: TypedEvent<E3Requested>) {
        let e3_id = msg.e3_id.clone();
        if self.processed_requests.contains(&e3_id) {
            return;
        }
        let chain_id = msg.e3_id.chain_id();
        let Some(seed) = self
            .recovery
            .get()
            .and_then(|recovery| recovery.seeds.get(&e3_id).copied())
        else {
            self.bus.err(
                EType::Sortition,
                anyhow!("E3 {e3_id} has no recovered sortition seed"),
            );
            return;
        };
        let snapshot = self.node_state.get().and_then(|state| {
            state
                .get(&chain_id)
                .and_then(|state| state.sortition_snapshot(&e3_id))
        });

        info!(
            e3_id = %e3_id,
            threshold_m = msg.threshold_m,
            threshold_n = msg.threshold_n,
            "Ranking eligible ticket submissions; the contract selects distinct bond owners"
        );

        let node_index = match snapshot {
            Some(snapshot)
                if snapshot.request_block == msg.request_block
                    && !snapshot.ticket_price.is_zero() =>
            {
                self.get_node_index(e3_id.clone(), seed, chain_id, snapshot)
            }
            Some(snapshot) if snapshot.request_block != msg.request_block => {
                self.bus.err(
                    EType::Sortition,
                    anyhow!(
                        "E3 {} has inconsistent sortition context: request block {} != {}",
                        e3_id,
                        msg.request_block,
                        snapshot.request_block
                    ),
                );
                None
            }
            Some(_) => {
                self.bus.err(
                    EType::Sortition,
                    anyhow!("E3 {} has a zero request-time ticket price", e3_id),
                );
                None
            }
            None => {
                self.bus.err(
                    EType::Sortition,
                    anyhow!("E3 {} has no request-time sortition snapshot", e3_id),
                );
                None
            }
        };

        match &node_index {
            Some((index, ticket_id)) => {
                info!(
                    e3_id = %e3_id,
                    node = %self.address,
                    index = index,
                    ticket_id = ?ticket_id,
                    "This node was SELECTED for sortition"
                );
            }
            None => {
                info!(
                    e3_id = %e3_id,
                    node = %self.address,
                    "This node was NOT selected for sortition"
                );
            }
        }

        if node_index.is_some() {
            let reservation = self.node_state.try_mutate(msg.get_ctx(), |mut state_map| {
                ensure!(
                    NodeRegistry::reserve_committee_job(&mut state_map, &e3_id, &self.address,),
                    "E3 {e3_id} already has a different capacity reservation"
                );
                Ok(state_map)
            });
            if let Err(error) = reservation {
                self.bus.with_ec(msg.get_ctx()).err(EType::Sortition, error);
                return;
            }
        }

        match self.ciphernode_selector.try_send(WithSortitionTicket::new(
            msg,
            node_index,
            &self.address,
        )) {
            Ok(()) => {
                self.processed_requests.insert(e3_id);
            }
            Err(error) => {
                self.bus.err(
                    EType::Sortition,
                    anyhow!("Could not dispatch sortition result for E3 {e3_id}: {error}"),
                );
            }
        }
    }
}
