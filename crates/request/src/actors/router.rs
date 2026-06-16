// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::ContextRepositoryFactory;
use crate::E3Context;
use crate::E3ContextParams;
use crate::E3MetaExtension;
use crate::EventBuffer;
use crate::PostForward;
use crate::RequestRouter;
use crate::RouterRepositoryFactory;
use crate::RoutingDecision;
use actix::{Actor, Addr, Context, Handler};
use anyhow::*;
use async_trait::async_trait;
use e3_data::Checkpoint;
use e3_data::DataStore;
use e3_data::FromSnapshotWithParams;
use e3_data::RepositoriesFactory;
use e3_data::Repository;
use e3_data::Snapshot;
use e3_events::prelude::*;
use e3_events::trap;
use e3_events::BusHandle;
use e3_events::E3RequestComplete;
use e3_events::EType;
use e3_events::EventType;
use e3_events::{E3id, InterfoldEvent};
use e3_utils::MAILBOX_LIMIT;
use serde::Deserialize;
use serde::Serialize;
use std::collections::HashSet;
use std::{collections::HashMap, sync::Arc};

/// An Extension interface for the E3Router system that listens and responds to InterfoldEvents.
///
/// # Responsibilities
/// - Listens for broadcast InterfoldEvents
/// - Instantiates appropriate actors based on received events
/// - Manages actor state persistence and reconstruction
/// - Handles event streaming to registered recipients
///
/// # Usage
/// Extensions implement the `on_event` handler to define which events they respond to.
/// When an event is received, the extension typically:
/// 1. Uses the request's context to construct required actors
/// 2. Saves actor addresses to the context using `set_event_recipient`
/// 3. Manages event streaming from buffers to registered recipients
///
/// Extensions can also reconstruct actors from persisted state using context
/// snapshots and repositories. They can check for dependencies in the context
/// before constructing new extensions.
#[async_trait]
pub trait E3Extension: Send + Sync + 'static {
    /// This function is triggered when an InterfoldEvent is sent to the router. Use this to
    /// initialize the receiver using `ctx.set_event_receiver(my_address.into())`. Typically this
    /// means filtering for specific e3_id enabled events that give rise to actors that have to
    /// handle certain behaviour.
    fn on_event(&self, ctx: &mut E3Context, evt: &InterfoldEvent);

    /// This function it triggered when the request context is being hydrated from snapshot.
    async fn hydrate(&self, ctx: &mut E3Context, snapshot: &crate::E3ContextSnapshot)
        -> Result<()>;
}

/// Routes E3_id-specific contexts to registered extensions and manages message forwarding.
///
/// # Core Functions
/// - Maintains contexts for each E3 request
/// - Lazily registers extension instances with appropriate dependencies per E3_id
/// - Forwards incoming messages to registered instances
/// - Manages request lifecycle and completion
///
/// Extensions receive an E3_id-specific context and can handle specific
/// message types. The router ensures proper message delivery and context management
/// throughout the request lifecycle.
///
/// This actor is a thin message-passing shell: all routing decisions are computed by the
/// pure [`RequestRouter`] service; the actor only performs the resulting actix I/O.
// TODO: setup so that we have to place extensions within correct order of dependencies
pub struct E3Router {
    /// The context for every E3 request
    contexts: HashMap<E3id, E3Context>,
    /// A list of completed requests
    completed: HashSet<E3id>,
    /// The extensions this instance of the router is configured to listen for
    extensions: Arc<Vec<Box<dyn E3Extension>>>,
    /// A buffer for events to send to the
    buffer: EventBuffer,
    /// The EventBus
    bus: BusHandle,
    /// A repository for storing snapshots
    store: Repository<E3RouterSnapshot>,
}

pub struct E3RouterParams {
    extensions: Arc<Vec<Box<dyn E3Extension>>>,
    bus: BusHandle,
    store: Repository<E3RouterSnapshot>,
}

impl E3Router {
    pub fn builder(bus: &BusHandle, store: DataStore) -> E3RouterBuilder {
        let repositories = store.repositories();
        let builder = E3RouterBuilder {
            bus: bus.clone(),
            extensions: vec![],
            store: repositories.router(),
        };

        // Everything needs the committe meta factory so adding it here by default
        builder.with(E3MetaExtension::create())
    }

    pub fn from_params(params: E3RouterParams) -> Self {
        Self {
            extensions: params.extensions,
            bus: params.bus.clone(),
            store: params.store.clone(),
            completed: HashSet::new(),
            contexts: HashMap::new(),
            buffer: EventBuffer::default(),
        }
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
    fn handle(&mut self, msg: InterfoldEvent, _: &mut Self::Context) -> Self::Result {
        trap(EType::Event, &self.bus.with_ec(msg.get_ctx()), || {
            match RequestRouter::route(&msg, &self.completed) {
                RoutingDecision::Broadcast => {
                    // If we are shutting down then bail on anything else
                    for (_, ctx) in self.contexts.iter() {
                        ctx.forward_message_now(&msg)
                    }
                    Ok(())
                }
                RoutingDecision::Ignore => Ok(()),
                RoutingDecision::AlreadyCompleted(e3_id) => Err(anyhow!(
                    "Received the following event to E3Id({}) despite already being completed:\n\n{:?}\n\n",
                    e3_id,
                    msg
                )),
                RoutingDecision::Process {
                    e3_id,
                    post_forward,
                } => {
                    let repositories = self.repository().repositories();
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

                    let (_, ctx) = msg.into_components();
                    match post_forward {
                        PostForward::PublishComplete => {
                            let event = E3RequestComplete {
                                e3_id: e3_id.clone(),
                            };

                            // Send to bus so all other actors can react to a request being complete.
                            self.bus.publish(event, ctx)?;
                        }
                        PostForward::Teardown => {
                            // The original event is forwarded above so children can kill themselves.
                            self.contexts.remove(&e3_id);
                            self.completed.insert(e3_id);
                        }
                        PostForward::None => (),
                    }

                    self.checkpoint();
                    Ok(())
                }
            }
        });
    }
}

#[derive(Serialize, Deserialize)]
pub struct E3RouterSnapshot {
    contexts: Vec<E3id>,
    completed: HashSet<E3id>,
}

impl Snapshot for E3Router {
    type Snapshot = E3RouterSnapshot;
    fn snapshot(&self) -> Result<Self::Snapshot> {
        let contexts = self.contexts.keys().cloned().collect();
        let completed = self.completed.clone();

        Ok(Self::Snapshot {
            completed,
            contexts,
        })
    }
}

impl Checkpoint for E3Router {
    fn repository(&self) -> &Repository<E3RouterSnapshot> {
        &self.store
    }
}

#[async_trait]
impl FromSnapshotWithParams for E3Router {
    type Params = E3RouterParams;

    async fn from_snapshot(params: Self::Params, snapshot: Self::Snapshot) -> Result<Self> {
        let mut contexts = HashMap::new();

        let repositories = params.store.repositories();
        for e3_id in snapshot.contexts {
            let Some(ctx_snapshot) = repositories.context(&e3_id).read().await? else {
                continue;
            };

            contexts.insert(
                e3_id.clone(),
                E3Context::from_snapshot(
                    E3ContextParams {
                        repository: repositories.context(&e3_id),
                        e3_id: e3_id.clone(),
                        extensions: params.extensions.clone(),
                    },
                    ctx_snapshot,
                )
                .await?,
            );
        }

        Ok(E3Router {
            contexts,
            completed: snapshot.completed,
            extensions: params.extensions,
            buffer: EventBuffer::default(),
            bus: params.bus,
            store: params.store,
        })
    }
}

/// Builder for E3Router
pub struct E3RouterBuilder {
    pub bus: BusHandle,
    pub extensions: Vec<Box<dyn E3Extension>>,
    pub store: Repository<E3RouterSnapshot>,
}

impl E3RouterBuilder {
    pub fn with(mut self, listener: Box<dyn E3Extension>) -> Self {
        self.extensions.push(listener);
        self
    }

    pub async fn build(self) -> Result<Addr<E3Router>> {
        let snapshot: Option<E3RouterSnapshot> = self.store.read().await?;
        let params = E3RouterParams {
            extensions: self.extensions.into(),
            bus: self.bus.clone(),
            store: self.store.clone(),
        };

        let e3r = match snapshot {
            Some(snapshot) => E3Router::from_snapshot(params, snapshot).await?,
            None => E3Router::from_params(params),
        };

        let addr = e3r.start();
        self.bus.subscribe(EventType::All, addr.clone().recipient());
        Ok(addr)
    }
}
