// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::traits::{ErrorEvent, Event};
use crate::EventType;
use actix::prelude::*;
use bloom::{BloomFilter, ASMS};
use e3_utils::{colorize, Color, MAILBOX_LIMIT, MAILBOX_LIMIT_LARGE};
use std::collections::HashMap;
use std::fmt;
use std::marker::PhantomData;
use std::time::Duration;
use tokio::sync::mpsc;

//////////////////////////////////////////////////////////////////////////////
// Configuration
//////////////////////////////////////////////////////////////////////////////

/// Configuration for EventBus behavior
pub struct EventBusConfig {
    pub deduplicate: bool,
}

impl Default for EventBusConfig {
    fn default() -> Self {
        Self { deduplicate: true }
    }
}

fn default_bloomfilter() -> BloomFilter {
    let num_items = 10000000;
    let fp_rate = 0.001;
    BloomFilter::with_rate(fp_rate, num_items)
}

//////////////////////////////////////////////////////////////////////////////
// EventBus Implementation
//////////////////////////////////////////////////////////////////////////////
/// Central EventBus for each node. Actors publish events to this bus by sending it InterfoldEvents.
/// All events sent to this bus are assumed to be published over the network via pubsub.
/// Other actors such as the NetEventTranslator and Evm actor connect to outside services and control which events
/// actually get published as well as ensure that local events are not rebroadcast locally after
/// being published.
pub struct EventBus<E: Event> {
    config: EventBusConfig,
    ids: BloomFilter,
    listeners: HashMap<String, Vec<Recipient<E>>>,
}

impl<E: Event> Actor for EventBus<E> {
    type Context = Context<Self>;
    fn started(&mut self, ctx: &mut Self::Context) {
        ctx.set_mailbox_capacity(MAILBOX_LIMIT_LARGE)
    }
}

impl<E: Event> EventBus<E> {
    pub fn new(config: EventBusConfig) -> Self {
        EventBus {
            config,
            listeners: HashMap::new(),
            ids: default_bloomfilter(),
        }
    }

    pub fn set_config(&mut self, config: EventBusConfig) {
        self.config = config;
    }

    pub fn history(source: &Addr<EventBus<E>>) -> Addr<HistoryCollector<E>> {
        let addr = HistoryCollector::<E>::new().start();
        source.do_send(Subscribe::new(EventType::All, addr.clone().recipient()));
        addr
    }

    pub fn error<EE: Event>(source: &Addr<EventBus<EE>>) -> Addr<HistoryCollector<EE>> {
        let addr = HistoryCollector::<EE>::new().start();
        source.do_send(Subscribe::new(
            EventType::InterfoldError,
            addr.clone().recipient(),
        ));
        addr
    }

    pub fn pipe(source: &Addr<EventBus<E>>, dest: &Addr<EventBus<E>>) {
        source.do_send(Subscribe::new(EventType::All, dest.clone().recipient()))
    }

    pub fn pipe_filter<F>(source: &Addr<EventBus<E>>, predicate: F, dest: &Addr<EventBus<E>>)
    where
        F: Fn(&E) -> bool + 'static,
    {
        let filter = EventFilter::new(dest.clone().recipient(), predicate).start();

        source.do_send(Subscribe::new(EventType::All, filter.recipient()));
    }

    fn track(&mut self, event: E) {
        self.ids.insert(&event.event_id());
    }

    fn is_duplicate(&self, event: &E) -> bool {
        self.ids.contains(&event.event_id())
    }
}

impl<E: Event> Default for EventBus<E> {
    fn default() -> Self {
        Self {
            config: EventBusConfig::default(),
            listeners: HashMap::new(),
            ids: default_bloomfilter(),
        }
    }
}

impl<E: Event> Handler<E> for EventBus<E> {
    type Result = ();

    fn handle(&mut self, event: E, _: &mut Context<Self>) {
        if self.is_duplicate(&event) {
            return;
        }
        if let Some(listeners) = self.listeners.get("*") {
            for listener in listeners {
                listener.do_send(event.clone());
            }
        }

        if let Some(listeners) = self.listeners.get(&event.event_type()) {
            for listener in listeners {
                listener.do_send(event.clone());
            }
        }

        // TODO: workshop to work out best display format
        tracing::info!("{} {}", colorize(">>>", Color::Yellow), event);
        self.track(event);
    }
}

//////////////////////////////////////////////////////////////////////////////
// Subscribe Message
//////////////////////////////////////////////////////////////////////////////

#[derive(Message)]
#[rtype(result = "()")]
pub struct Subscribe<E: Event> {
    pub event_type: String,
    pub listener: Recipient<E>,
}

#[derive(Message)]
#[rtype(result = "()")]
pub struct Unsubscribe<E: Event> {
    pub event_type: String,
    pub listener: Recipient<E>,
}

impl<E: Event> Subscribe<E> {
    pub fn new(event_type: impl Into<String>, listener: Recipient<E>) -> Self {
        Self {
            event_type: event_type.into(),
            listener,
        }
    }
}

impl<E: Event> Unsubscribe<E> {
    pub fn new(event_type: impl Into<String>, listener: Recipient<E>) -> Self {
        Self {
            event_type: event_type.into(),
            listener,
        }
    }
}

impl<E: Event> Handler<Subscribe<E>> for EventBus<E> {
    type Result = ();

    fn handle(&mut self, msg: Subscribe<E>, _: &mut Context<Self>) {
        self.listeners
            .entry(msg.event_type)
            .or_default()
            .push(msg.listener);
    }
}

impl<E: Event> Handler<Unsubscribe<E>> for EventBus<E> {
    type Result = ();

    fn handle(&mut self, msg: Unsubscribe<E>, _: &mut Context<Self>) {
        if let Some(listeners) = self.listeners.get_mut(&msg.event_type) {
            listeners.retain(|listener| listener != &msg.listener);
        }
    }
}

//////////////////////////////////////////////////////////////////////////////
// Event Filter
//////////////////////////////////////////////////////////////////////////////

pub type Predicate<E> = Box<dyn Fn(&E) -> bool>;

pub struct EventFilter<E: Event> {
    dest: Recipient<E>,
    predicate: Predicate<E>,
}

impl<E: Event> EventFilter<E> {
    pub fn new<F>(dest: Recipient<E>, predicate: F) -> Self
    where
        F: Fn(&E) -> bool + 'static,
    {
        Self {
            dest,
            predicate: Box::new(predicate),
        }
    }
}

impl<E: Event> Actor for EventFilter<E> {
    type Context = actix::Context<Self>;
    fn started(&mut self, ctx: &mut Self::Context) {
        ctx.set_mailbox_capacity(MAILBOX_LIMIT_LARGE)
    }
}

impl<E: Event> Handler<E> for EventFilter<E> {
    type Result = ();
    fn handle(&mut self, msg: E, _: &mut Self::Context) -> Self::Result {
        if (self.predicate)(&msg) {
            self.dest.do_send(msg);
        }
    }
}

//////////////////////////////////////////////////////////////////////////////
// History Management
//////////////////////////////////////////////////////////////////////////////

#[derive(Message)]
#[rtype(result = "Vec<E>")]
pub struct GetEvents<E: Event>(PhantomData<E>);

impl<E: Event> Default for GetEvents<E> {
    fn default() -> Self {
        Self::new()
    }
}

impl<E: Event> GetEvents<E> {
    pub fn new() -> Self {
        Self(PhantomData)
    }
}

#[derive(Message)]
#[rtype(result = "TakeEventsResult<E>")]
pub struct TakeEvents<E: Event> {
    amount: usize,
    timeout: Duration,
    _d: PhantomData<E>,
}

#[derive(Debug)]
pub struct TakeEventsResult<E: Event> {
    pub events: Vec<E>,
    pub timed_out: bool,
}

impl<E: Event> TakeEvents<E> {
    pub fn new(amount: usize) -> Self {
        Self {
            amount,
            timeout: Duration::from_secs(1),
            _d: PhantomData,
        }
    }

    pub fn with_per_evt_timeout(amount: usize, timeout: Duration) -> Self {
        Self {
            amount,
            timeout,
            _d: PhantomData,
        }
    }
}

#[derive(Message)]
#[rtype(result = "()")]
pub struct ResetHistory;

#[derive(Message)]
#[rtype(result = "Vec<E::Data>")]
pub struct GetErrors<E: ErrorEvent>(PhantomData<E>);

impl<E: ErrorEvent> Default for GetErrors<E> {
    fn default() -> Self {
        Self::new()
    }
}

impl<E: ErrorEvent> GetErrors<E> {
    pub fn new() -> Self {
        Self(PhantomData)
    }
}

//////////////////////////////////////////////////////////////////////////////
// History Collector
//////////////////////////////////////////////////////////////////////////////

struct HistoryCollectorWaiter<E: Event> {
    rx: Option<mpsc::UnboundedReceiver<E>>,
}

impl<E: Event> Actor for HistoryCollectorWaiter<E> {
    type Context = Context<Self>;
}

impl<E: Event + fmt::Debug> Handler<TakeEvents<E>> for HistoryCollectorWaiter<E> {
    type Result = ResponseActFuture<Self, TakeEventsResult<E>>;
    fn handle(&mut self, msg: TakeEvents<E>, _: &mut Context<Self>) -> Self::Result {
        let count = msg.amount;
        let timeout = msg.timeout;
        let mut rx = self.rx.take().unwrap();
        Box::pin(
            async move {
                let mut events = Vec::with_capacity(count);
                let mut timed_out = false;
                for _ in 0..count {
                    match tokio::time::timeout(timeout, rx.recv()).await {
                        Ok(Some(e)) => events.push(e),
                        Ok(None) => break,
                        Err(_) => {
                            timed_out = true;
                            break;
                        }
                    }
                }
                (TakeEventsResult { events, timed_out }, rx)
            }
            .into_actor(self)
            .map(|(result, rx), actor, _| {
                actor.rx = Some(rx);
                result
            }),
        )
    }
}

impl<E: Event> Handler<ResetHistory> for HistoryCollectorWaiter<E> {
    type Result = ();
    fn handle(&mut self, _: ResetHistory, _: &mut Context<Self>) {
        if let Some(ref mut rx) = self.rx {
            while rx.try_recv().is_ok() {}
        }
    }
}

pub struct HistoryCollector<E: Event> {
    history: Vec<E>,
    tx: mpsc::UnboundedSender<E>,
    waiter: Addr<HistoryCollectorWaiter<E>>,
}

impl<E: Event> Default for HistoryCollector<E> {
    fn default() -> Self {
        Self::new()
    }
}

impl<E: Event> HistoryCollector<E> {
    pub fn new() -> Self {
        let (tx, rx) = mpsc::unbounded_channel();
        let waiter = HistoryCollectorWaiter { rx: Some(rx) }.start();
        Self {
            history: Vec::new(),
            tx,
            waiter,
        }
    }
}

impl<E: Event> Actor for HistoryCollector<E> {
    type Context = Context<Self>;
    fn started(&mut self, ctx: &mut Self::Context) {
        ctx.set_mailbox_capacity(MAILBOX_LIMIT);
    }
}

impl<E: Event> Handler<E> for HistoryCollector<E> {
    type Result = E::Result;
    fn handle(&mut self, msg: E, _ctx: &mut Self::Context) -> Self::Result {
        self.history.push(msg.clone());
        let _ = self.tx.send(msg);
    }
}

impl<E: Event> Handler<ResetHistory> for HistoryCollector<E> {
    type Result = ();
    fn handle(&mut self, _: ResetHistory, _: &mut Context<Self>) {
        self.history.clear();
        self.waiter.do_send(ResetHistory);
    }
}

impl<E: Event + fmt::Debug> Handler<TakeEvents<E>> for HistoryCollector<E> {
    type Result = ResponseActFuture<Self, TakeEventsResult<E>>;
    fn handle(&mut self, msg: TakeEvents<E>, _: &mut Context<Self>) -> Self::Result {
        let fut = self.waiter.send(msg);
        Box::pin(async move { fut.await.unwrap() }.into_actor(self))
    }
}

impl<E: Event> Handler<GetEvents<E>> for HistoryCollector<E> {
    type Result = Vec<E>;
    fn handle(&mut self, _: GetEvents<E>, _: &mut Context<Self>) -> Vec<E> {
        self.history.clone()
    }
}
