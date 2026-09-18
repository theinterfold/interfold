// SPDX-License-Identifier: LGPL-4.0-only

//! Committee queries, job release, and terminal cleanup.

use super::*;

impl Handler<GetCommitteeMembersRequest> for Sortition {
    type Result = ();

    fn handle(&mut self, msg: GetCommitteeMembersRequest, _: &mut Self::Context) -> Self::Result {
        trap(EType::Sortition, &self.bus.clone(), || {
            let members = self.get_committee(&msg.e3_id).map(|c| c.members().to_vec());
            let reply = msg.reply;
            // `try_send` can drop the reply when the aggregator mailbox is busy (e.g. mid
            // `AggregationProofSigned`), leaving decryption stuck after C7 with no ZK job.
            actix::spawn(async move {
                if reply
                    .send(CommitteeMembersResponse { members })
                    .await
                    .is_err()
                {
                    tracing::error!("committee members reply failed: aggregator recipient closed");
                }
            });
            Ok(())
        })
    }
}

impl<T> Handler<E3CommitteeContainsRequest<T>> for Sortition
where
    T: Clone + Send + Sync + 'static,
{
    type Result = ();
    fn handle(
        &mut self,
        msg: E3CommitteeContainsRequest<T>,
        _: &mut Self::Context,
    ) -> Self::Result {
        trap(EType::Sortition, &self.bus.clone(), || {
            let response = E3CommitteeContainsResponse::new(
                msg.inner,
                self.committee_contains(msg.e3_id, msg.node),
            );
            msg.sender.try_send(response)?;
            Ok(())
        })
    }
}

impl Handler<TypedEvent<PlaintextOutputPublished>> for Sortition {
    type Result = ();

    fn handle(
        &mut self,
        msg: TypedEvent<PlaintextOutputPublished>,
        _ctx: &mut Self::Context,
    ) -> Self::Result {
        let (msg, ec) = msg.into_components();
        trap(EType::Sortition, &self.bus.with_ec(&ec), || {
            self.decrement_jobs_for_e3(&msg.e3_id, "PlaintextOutputPublished", ec)
        })
    }
}

impl Handler<TypedEvent<E3Failed>> for Sortition {
    type Result = ();

    fn handle(&mut self, msg: TypedEvent<E3Failed>, _ctx: &mut Self::Context) -> Self::Result {
        let (msg, ec) = msg.into_components();
        trap(EType::Sortition, &self.bus.with_ec(&ec), || {
            let reason = format!("E3Failed: {:?}", msg.reason);
            self.decrement_jobs_for_e3(&msg.e3_id, &reason, ec.clone())?;
            self.recovery.try_mutate(&ec, |mut recovery| {
                recovery.remove(&msg.e3_id);
                Ok(recovery)
            })?;
            self.processed_requests.remove(&msg.e3_id);
            Ok(())
        })
    }
}

impl Handler<TypedEvent<E3StageChanged>> for Sortition {
    type Result = ();

    fn handle(
        &mut self,
        msg: TypedEvent<E3StageChanged>,
        _ctx: &mut Self::Context,
    ) -> Self::Result {
        let (msg, ec) = msg.into_components();
        trap(EType::Sortition, &self.bus.with_ec(&ec), || {
            match msg.new_stage {
                E3Stage::Complete | E3Stage::Failed => {
                    let reason = format!("E3StageChanged to {:?}", msg.new_stage);
                    self.decrement_jobs_for_e3(&msg.e3_id, &reason, ec.clone())?;
                    self.recovery.try_mutate(&ec, |mut recovery| {
                        recovery.remove(&msg.e3_id);
                        Ok(recovery)
                    })?;
                    self.processed_requests.remove(&msg.e3_id);
                }
                _ => {
                    // Non-terminal stages, no action needed
                }
            }
            Ok(())
        })
    }
}

impl Handler<TypedEvent<E3RequestComplete>> for Sortition {
    type Result = ();

    fn handle(
        &mut self,
        msg: TypedEvent<E3RequestComplete>,
        _ctx: &mut Self::Context,
    ) -> Self::Result {
        trap(EType::Sortition, &self.bus.with_ec(msg.get_ctx()), || {
            self.decrement_jobs_for_e3(&msg.e3_id, "E3RequestComplete", msg.get_ctx().clone())?;
            self.finalized_committees
                .try_mutate(msg.get_ctx(), |mut committees| {
                    FinalizedCommitteeRetention::remove(&mut committees, &msg.e3_id);
                    Ok(committees)
                })?;
            self.recovery.try_mutate(msg.get_ctx(), |mut recovery| {
                recovery.remove(&msg.e3_id);
                Ok(recovery)
            })?;
            self.processed_requests.remove(&msg.e3_id);
            Ok(())
        })
    }
}
