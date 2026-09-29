// SPDX-License-Identifier: LGPL-3.0-only

//! Mailbox entry points and lifecycle hooks.

use super::effects::advance_request_router_cursor;
use super::*;
use actix::AsyncContext;
use anyhow::Context as _;
use e3_events::{EventContext, InterfoldEventData, RequestRouterCheckpoint, Sequenced, SyncEffect};
use tracing::info;

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
            },
            context,
        )?;
        Ok(())
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
        ctx.set_mailbox_capacity(MAILBOX_LIMIT)
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
                    if matches!(msg.get_data(), InterfoldEventData::EffectsEnabled(_)) {
                        // Startup pruned the finalized committee of a Failed E3, so no accusation
                        // work resumes for its restored context.
                        for e3_id in std::mem::take(&mut self.failed_on_restart) {
                            if self.contexts.contains_key(&e3_id) {
                                info!(
                                    %e3_id,
                                    "Completing a restored E3 whose lifecycle stage is Failed"
                                );
                                self.bus
                                    .publish(E3RequestComplete { e3_id }, msg.get_ctx().clone())?;
                            }
                        }
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

                    let (_, ec) = msg.into_components();
                    match post_forward {
                        PostForward::PublishComplete => {
                            self.bus.publish(
                                E3RequestComplete {
                                    e3_id: e3_id.clone(),
                                },
                                ec,
                            )?;
                        }
                        PostForward::ScheduleTeardown => {
                            // Skip when the E3 completed another way during the grace.
                            ctx.run_later(self.teardown_grace, move |act, _| {
                                if act.contexts.contains_key(&e3_id) {
                                    trap(EType::Event, &act.bus.with_ec(&ec), || {
                                        act.bus.publish(E3RequestComplete { e3_id }, ec)
                                    });
                                }
                            });
                        }
                        PostForward::Teardown => {
                            self.contexts.remove(&e3_id);
                            self.buffer.remove_e3(&e3_id);
                            self.completed.insert(e3_id);
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
