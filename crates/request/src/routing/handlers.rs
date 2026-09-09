// SPDX-License-Identifier: LGPL-3.0-only

//! Mailbox entry points and lifecycle hooks.

use super::effects::advance_request_router_cursor;
use super::*;
use actix::AsyncContext;
use anyhow::Context as _;
use e3_events::{EventContext, InterfoldEventData, RequestRouterCheckpoint, Sequenced, SyncEffect};
use tracing::{error, info};

impl E3Router {
    fn checkpoint_with_context(&mut self, context: &EventContext<Sequenced>) -> Result<()> {
        advance_request_router_cursor(
            &mut self.replay_cursors,
            context.aggregate_id(),
            context.seq(),
        );
        let snapshot = self.snapshot()?;
        self.recovery_store.write_with_context(
            &RequestRouterCheckpoint {
                contexts: snapshot.contexts,
                completed: snapshot.completed,
                replay_cursors: self.replay_cursors.clone(),
                teardown_deadlines: self.teardown_deadlines.clone(),
            },
            context,
        )?;
        Ok(())
    }

    fn unix_now_secs() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or_default()
    }

    /// Record when a slashably-failed E3 may be torn down and arm the timer for it.
    fn schedule_teardown(
        &mut self,
        e3_id: E3id,
        caused_by: EventContext<Sequenced>,
        ctx: &mut Context<Self>,
    ) {
        let deadline = Self::unix_now_secs().saturating_add(self.teardown_grace.as_secs());
        self.teardown_deadlines.insert(e3_id.clone(), deadline);
        self.arm_teardown(e3_id, deadline, Some(caused_by), ctx);
    }

    /// Fire `E3RequestComplete` for `e3_id` once `deadline` (unix seconds) has passed.
    ///
    /// Idempotent against the persisted map: a timer whose entry was already removed (the E3
    /// completed some other way, or a second timer was armed after a restart) does nothing.
    /// `caused_by` is the `E3Failed` context when armed in-process; after a restart it is
    /// gone and the completion is published as a root event.
    fn arm_teardown(
        &mut self,
        e3_id: E3id,
        deadline: u64,
        caused_by: Option<EventContext<Sequenced>>,
        ctx: &mut Context<Self>,
    ) {
        let delay = std::time::Duration::from_secs(deadline.saturating_sub(Self::unix_now_secs()));
        ctx.run_later(delay, move |act, _| {
            if act.teardown_deadlines.remove(&e3_id).is_none() {
                return;
            }
            if act.completed.contains(&e3_id) || !act.contexts.contains_key(&e3_id) {
                return;
            }
            info!(
                %e3_id,
                "Slashing window closed for the failed E3; tearing down its request context"
            );
            let complete = E3RequestComplete {
                e3_id: e3_id.clone(),
            };
            let published = match caused_by {
                Some(ec) => act.bus.publish(complete, ec),
                None => act.bus.publish_without_context(complete),
            };
            if let Err(err) = published {
                error!(%e3_id, %err, "Failed to publish E3RequestComplete for the failed E3");
            }
        });
    }

    /// Re-arm every persisted teardown deadline after a restart. Deadlines already in the
    /// past fire on the next tick.
    fn rearm_teardowns(&mut self, ctx: &mut Context<Self>) {
        let pending: Vec<(E3id, u64)> = self
            .teardown_deadlines
            .iter()
            .map(|(id, deadline)| (id.clone(), *deadline))
            .collect();
        for (e3_id, deadline) in pending {
            self.arm_teardown(e3_id, deadline, None, ctx);
        }
    }

    fn reconcile_recovered_selections(&mut self) -> Result<()> {
        for selection in std::mem::take(&mut self.recovered_selections) {
            if self.completed.contains(&selection.e3_id) {
                continue;
            }

            let e3_id = selection.e3_id.clone();
            let event = self.bus.event_from(selection, None)?;
            let sequence = self
                .replay_cursors
                .get(&event.aggregate_id())
                .copied()
                .unwrap_or_default();
            let event = event.into_sequenced(sequence);
            let context = self.contexts.get_mut(&e3_id).with_context(|| {
                format!(
                    "cannot restore local selection for E3 {e3_id}: request-router context is missing"
                )
            })?;

            for extension in self.extensions.iter() {
                extension.on_event(context, &event);
            }
            context.forward_message(&event, &mut self.buffer);
            context.repository.write(&context.snapshot()?);
        }
        Ok(())
    }
}

impl Actor for E3Router {
    type Context = Context<Self>;

    fn started(&mut self, ctx: &mut Self::Context) {
        ctx.set_mailbox_capacity(MAILBOX_LIMIT);
        self.rearm_teardowns(ctx);
    }
}

impl Handler<InterfoldEvent> for E3Router {
    type Result = ();

    fn handle(&mut self, msg: InterfoldEvent, ctx: &mut Self::Context) -> Self::Result {
        trap(EType::Event, &self.bus.with_ec(msg.get_ctx()), || {
            if matches!(msg.get_data(), InterfoldEventData::SyncEffect(SyncEffect)) {
                let event_context = msg.get_ctx().clone();
                let result = self.reconcile_recovered_selections();
                let checkpoint_result = self.checkpoint_with_context(&event_context);
                return result.and(checkpoint_result);
            }
            let event_context = msg.get_ctx().clone();
            let result = match RequestRouter::route_with_context(
                &msg,
                &self.completed,
                msg.get_e3_id()
                    .is_some_and(|e3_id| self.contexts.contains_key(&e3_id)),
            ) {
                RoutingDecision::Broadcast => {
                    for context in self.contexts.values() {
                        context.forward_message_now(&msg)
                    }
                    Ok(())
                }
                RoutingDecision::Ignore => Ok(()),
                RoutingDecision::AlreadyCompleted(e3_id) => Err(anyhow!(
                    "unexpected {} for completed E3 {} (event={}, origin={}, source={:?}, block={:?})",
                    msg.event_type(),
                    e3_id,
                    msg.id(),
                    msg.origin_id(),
                    msg.source(),
                    msg.block(),
                )),
                RoutingDecision::UnadmittedNetworkEvent(e3_id) => Err(anyhow!(
                    "rejected {} for unknown E3 {} from the peer network (event={}, origin={})",
                    msg.event_type(),
                    e3_id,
                    msg.id(),
                    msg.origin_id(),
                )),
                RoutingDecision::Process {
                    e3_id,
                    post_forward,
                } => {
                    let repositories = self.store.repositories();
                    let context = self.contexts.entry(e3_id.clone()).or_insert_with(|| {
                        E3Context::from_params(E3ContextParams {
                            e3_id: e3_id.clone(),
                            repository: repositories.context(&e3_id),
                            extensions: self.extensions.clone(),
                        })
                    });

                    for extension in self.extensions.iter() {
                        extension.on_event(context, &msg);
                    }

                    context.forward_message(&msg, &mut self.buffer);
                    if post_forward != PostForward::Teardown {
                        context
                            .repository
                            .write_with_context(&context.snapshot()?, &event_context)?;
                    }

                    let (_, ctx_ec) = msg.into_components();
                    match post_forward {
                        PostForward::PublishComplete => {
                            self.bus.publish(
                                E3RequestComplete {
                                    e3_id: e3_id.clone(),
                                },
                                ctx_ec,
                            )?;
                        }
                        PostForward::ScheduleTeardown => {
                            self.schedule_teardown(e3_id, ctx_ec, ctx);
                        }
                        PostForward::Teardown => {
                            self.contexts.remove(&e3_id);
                            self.buffer.remove_e3(&e3_id);
                            self.teardown_deadlines.remove(&e3_id);
                            self.completed.insert(e3_id);
                            prune_completed(&mut self.completed);
                        }
                        PostForward::None => (),
                    }

                    Ok(())
                }
            };

            let checkpoint_result = self.checkpoint_with_context(&event_context);
            result.and(checkpoint_result)
        });
    }
}
