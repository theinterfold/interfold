// SPDX-License-Identifier: LGPL-3.0-only

//! Mailbox entry points and lifecycle hooks.

use super::*;

#[derive(Message)]
#[rtype(result = "()")]
struct IncomingNetEvent(NetEvent);

#[derive(Message)]
#[rtype(result = "()")]
struct NetInputLagged(u64);

impl Actor for NetEventBuffer {
    type Context = actix::Context<Self>;

    fn started(&mut self, ctx: &mut Self::Context) {
        ctx.set_mailbox_capacity(MAILBOX_LIMIT);
        let addr = ctx.address();
        let mut input_rx = self.input_rx.take().expect("input_rx should be present");

        actix::spawn(async move {
            loop {
                match input_rx.recv().await {
                    Ok(event) => {
                        if addr.send(IncomingNetEvent(event)).await.is_err() {
                            break;
                        }
                    }
                    Err(RecvError::Lagged(skipped)) => {
                        if addr.send(NetInputLagged(skipped)).await.is_err() {
                            break;
                        }
                    }
                    Err(RecvError::Closed) => break,
                }
            }
        });
    }

    fn stopped(&mut self, _: &mut Self::Context) {
        self.signal_startup(Err(
            "network event buffer stopped before startup synchronization completed".to_owned(),
        ));
    }
}

impl Handler<IncomingNetEvent> for NetEventBuffer {
    type Result = ();

    fn handle(&mut self, msg: IncomingNetEvent, ctx: &mut Self::Context) {
        let event = match msg.0 {
            NetEvent::AuthenticatedGossip {
                author,
                propagation_source,
                message_id,
                data: GossipData::ProtocolEvent(envelope),
            } => {
                let admission = crate::unix_time_secs()
                    .map_err(|error| crate::AdmissionRejection {
                        reason: error.to_string(),
                        quarantine: false,
                    })
                    .and_then(|now| self.protocol_admission.authorize(author, envelope, now));
                match admission {
                    Ok(authorized) => {
                        self.submit_net_commands(
                            vec![NetCommand::GossipValidation {
                                propagation_source,
                                message_id,
                                acceptance: GossipAcceptance::Accept,
                            }],
                            Some(NetEvent::AuthorizedGossip(Box::new(authorized.event))),
                            ctx,
                        );
                        return;
                    }
                    Err(rejection) => {
                        let mut commands = vec![NetCommand::GossipValidation {
                            propagation_source,
                            message_id,
                            acceptance: GossipAcceptance::Reject,
                        }];
                        if rejection.quarantine {
                            commands.push(NetCommand::QuarantinePeer { peer_id: author });
                            warn!(%author, reason=%rejection.reason, "Quarantining unauthorized protocol-gossip author");
                        } else {
                            tracing::trace!(%author, reason=%rejection.reason, "Rejecting protocol gossip before startup buffering");
                        }
                        self.submit_net_commands(commands, None, ctx);
                        return;
                    }
                }
            }
            NetEvent::AuthenticatedGossip {
                propagation_source,
                message_id,
                ..
            } => {
                self.submit_net_commands(
                    vec![NetCommand::GossipValidation {
                        propagation_source,
                        message_id,
                        acceptance: GossipAcceptance::Reject,
                    }],
                    None,
                    ctx,
                );
                return;
            }
            event => event,
        };
        self.process_net_event(event, ctx);
    }
}

impl NetEventBuffer {
    fn submit_net_commands(
        &mut self,
        commands: Vec<NetCommand>,
        admitted: Option<NetEvent>,
        ctx: &mut actix::Context<Self>,
    ) {
        let tx = self.net_commands.clone();
        ctx.wait(
            async move {
                for command in commands {
                    tx.send(command).await?;
                }
                Ok::<_, mpsc::error::SendError<NetCommand>>(())
            }
            .into_actor(self)
            .map(move |result, actor, ctx| match result {
                Ok(()) => {
                    if let Some(event) = admitted {
                        actor.process_net_event(event, ctx);
                    }
                }
                Err(error) => actor.fail_closed(
                    anyhow!("network command channel closed during gossip admission: {error}"),
                    ctx,
                ),
            }),
        );
    }

    fn process_net_event(&mut self, event: NetEvent, ctx: &mut actix::Context<Self>) {
        let event_bytes = if self.state.is_running() {
            0
        } else {
            event.buffered_size_bytes()
        };
        let result = self
            .state
            .observe(event, event_bytes, self.max_events, self.max_bytes)
            .and_then(|decision| match decision {
                BufferDecision::Buffered => Ok(()),
                BufferDecision::Forward(event) => self.forward_event(*event),
            });
        if let Err(error) = result {
            self.fail_closed(error, ctx);
        }
    }
}

impl Handler<NetInputLagged> for NetEventBuffer {
    type Result = ();

    fn handle(&mut self, msg: NetInputLagged, ctx: &mut Self::Context) {
        if self.state.is_running() {
            warn!(
                skipped_events = msg.0,
                "Network event buffer input lagged after startup; continuing from the oldest retained event"
            );
            return;
        }
        self.fail_closed(
            anyhow!(
                "network event input skipped {} events because its bounded broadcast receiver lagged",
                msg.0
            ),
            ctx,
        );
    }
}

impl Handler<InterfoldEvent> for NetEventBuffer {
    type Result = ();

    fn handle(&mut self, msg: InterfoldEvent, ctx: &mut Self::Context) -> Self::Result {
        if let Err(error) = self.handle_interfold_event(msg) {
            self.fail_closed(error, ctx);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::GossipData;
    use e3_ciphernode_builder::EventSystem;
    use std::time::Duration;

    #[actix::test]
    async fn lag_after_startup_keeps_the_buffer_actor_live() -> Result<()> {
        let system = EventSystem::new().with_fresh_bus();
        let bus = system.handle()?.enable("post-startup-lag");
        let (_input_tx, input_rx) = broadcast::channel(1);
        let (output_tx, mut output_rx) = broadcast::channel(8);
        let (readiness, _readiness_rx) = oneshot::channel();
        let mut state = NetEventBufferState::syncing();
        state.run()?;
        let actor = NetEventBuffer {
            state,
            input_rx: Some(input_rx),
            output_tx,
            bus,
            max_events: 8,
            max_bytes: 1_024,
            readiness: Some(readiness),
            net_commands: mpsc::channel(1).0,
            protocol_admission: ProtocolAdmission::default(),
        }
        .start();

        actor.send(NetInputLagged(4)).await?;
        actor
            .send(IncomingNetEvent(NetEvent::GossipData(
                GossipData::GossipBytes(vec![7]),
            )))
            .await?;

        let forwarded = tokio::time::timeout(Duration::from_secs(1), output_rx.recv()).await??;
        assert!(matches!(
            forwarded,
            NetEvent::GossipData(GossipData::GossipBytes(bytes)) if bytes == vec![7]
        ));
        assert!(actor.connected());
        Ok(())
    }
}
