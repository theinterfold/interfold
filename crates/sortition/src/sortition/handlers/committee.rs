// SPDX-License-Identifier: LGPL-4.0-only

//! Persist finalized committees and enrich expulsion facts.

use super::*;

impl Handler<TypedEvent<CommitteeFinalized>> for Sortition {
    type Result = ();

    fn handle(
        &mut self,
        msg: TypedEvent<CommitteeFinalized>,
        _ctx: &mut Self::Context,
    ) -> Self::Result {
        let (mut msg, ec) = msg.into_components();
        msg.sort_by_address();
        trap(EType::Sortition, &self.bus.with_ec(&ec), || {
            info!(
                e3_id = %msg.e3_id,
                committee_size = msg.committee.len(),
                "Storing finalized committee"
            );

            self.node_state.try_mutate(&ec, |mut state_map| {
                NodeRegistry::reconcile_committee_jobs(
                    &mut state_map,
                    &msg.e3_id,
                    &msg.committee,
                    "CommitteeFinalized",
                );
                Ok(state_map)
            })?;
            self.finalized_committees
                .try_mutate(&ec, |mut committees| {
                    committees.insert(msg.e3_id.clone(), Committee::new(msg.committee.clone()));
                    Ok(committees)
                })?;
            if self.effects_enabled {
                self.redrive_membership_changes(&msg.e3_id);
            }

            self.recovery.try_mutate(&ec, |mut recovery| {
                recovery.complete_sortition(&msg.e3_id);
                Ok(recovery)
            })?;
            self.processed_requests.remove(&msg.e3_id);

            Ok(())
        })
    }
}

impl Handler<TypedEvent<CommitteeMemberExcluded>> for Sortition {
    type Result = ();

    fn handle(
        &mut self,
        msg: TypedEvent<CommitteeMemberExcluded>,
        _ctx: &mut Self::Context,
    ) -> Self::Result {
        let (data, ec) = msg.into_components();
        if data.party_id.is_some() {
            if let Err(error) = self.recovery.try_mutate(&ec, |mut recovery| {
                recovery.acknowledge_exclusion(&data);
                Ok(recovery)
            }) {
                self.bus.with_ec(&ec).err(EType::Sortition, error);
            }
            return;
        }

        trap(EType::Sortition, &self.bus.with_ec(&ec), || {
            self.recovery.try_mutate(&ec, |mut recovery| {
                recovery.buffer_exclusion(data.clone(), ec.clone());
                Ok(recovery)
            })?;
            if self.effects_enabled
                && !self.try_resolve_and_publish_exclusion(data.clone(), ec.clone())?
            {
                warn!(
                    node = %data.node,
                    e3_id = %data.e3_id,
                    "Local exclusion is waiting for committee finalization"
                );
            }
            Ok(())
        })
    }
}

impl Handler<TypedEvent<CommitteeMemberExpelled>> for Sortition {
    type Result = ();

    fn handle(
        &mut self,
        msg: TypedEvent<CommitteeMemberExpelled>,
        _ctx: &mut Self::Context,
    ) -> Self::Result {
        let (data, ec) = msg.into_components();

        // Only process raw events from chain (party_id not yet resolved).
        // Events we re-publish with party_id set will also arrive here; ignore them.
        if data.party_id.is_some() {
            if let Err(error) = self.recovery.try_mutate(&ec, |mut recovery| {
                recovery.acknowledge_expulsion(&data);
                Ok(recovery)
            }) {
                self.bus.with_ec(&ec).err(EType::Sortition, error);
            }
            return;
        }

        trap(EType::Sortition, &self.bus.with_ec(&ec), || {
            self.recovery.try_mutate(&ec, |mut recovery| {
                recovery.buffer_expulsion(data.clone(), ec.clone());
                Ok(recovery)
            })?;
            if self.effects_enabled
                && !self.try_resolve_and_publish_expulsion(data.clone(), ec.clone())?
            {
                warn!(
                    node = %data.node,
                    e3_id = %data.e3_id,
                    "Committee expulsion is waiting for committee finalization"
                );
            }
            Ok(())
        })
    }
}
