// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use actix::{Actor, Addr, Handler, Recipient};
use anyhow::{Context, Result};
use derivative::Derivative;
use e3_utils::{actix::channel::oneshot, MAILBOX_LIMIT};
use std::{
    future::Future,
    marker::PhantomData,
    pin::Pin,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc,
    },
};
use tokio::sync::Notify;
use tracing::{error, warn};

use crate::{
    event_context::EventContext,
    hlc::{Hlc, HlcMethods, HlcTimestamp},
    hlc_factory::HlcFactory,
    sequencer::Sequencer,
    traits::{
        ErrorDispatcher, ErrorFactory, EventConstructorWithTimestamp, EventContextAccessors,
        EventFactory, EventPublisher, EventSubscriber,
    },
    EType, ErrorEvent, EventBus, EventBusBarrier, EventContextManager, EventSource, EventType,
    FlushEventStores, HistoryCollector, InterfoldEvent, InterfoldEventData, PublishEvent,
    Sequenced, SequencerBarrier, Shutdown, Subscribe, Unsequenced, Unsubscribe,
};

/// Typestate marker indicating the BusHandle has not yet been enabled with an HLC clock.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Disabled;

/// Typestate marker indicating the BusHandle has been enabled and is ready for use.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Enabled;

#[derive(Debug)]
struct EventAdmission {
    accepting: AtomicBool,
    in_flight: AtomicUsize,
    drained: Notify,
}

impl EventAdmission {
    fn new() -> Self {
        Self {
            accepting: AtomicBool::new(true),
            in_flight: AtomicUsize::new(0),
            drained: Notify::new(),
        }
    }

    fn enter(self: &Arc<Self>) -> Result<EventAdmissionGuard> {
        if !self.accepting.load(Ordering::Acquire) {
            anyhow::bail!("event admission is closed because node shutdown has started");
        }

        self.in_flight.fetch_add(1, Ordering::AcqRel);
        let guard = EventAdmissionGuard(Arc::clone(self));
        if !self.accepting.load(Ordering::Acquire) {
            drop(guard);
            anyhow::bail!("event admission is closed because node shutdown has started");
        }
        Ok(guard)
    }

    async fn close_and_wait(&self) {
        self.accepting.store(false, Ordering::Release);
        loop {
            let drained = self.drained.notified();
            if self.in_flight.load(Ordering::Acquire) == 0 {
                return;
            }
            drained.await;
        }
    }
}

struct EventAdmissionGuard(Arc<EventAdmission>);

impl Drop for EventAdmissionGuard {
    fn drop(&mut self) {
        if self.0.in_flight.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.0.drained.notify_one();
        }
    }
}

#[derive(Derivative)]
#[derivative(
    Clone(bound = ""),
    Debug(bound = ""),
    PartialEq(bound = ""),
    Eq(bound = "")
)]
pub struct BusHandle<S = Enabled> {
    /// EventBus that actors can consume sequenced events from
    event_bus: Addr<EventBus<InterfoldEvent<Sequenced>>>,
    /// Sequencer that new events should be produced from
    sequencer: Addr<Sequencer>,
    /// Hlc clock used to time all events created on this BusHandle
    #[derivative(Debug = "ignore", PartialEq = "ignore")]
    hlc: HlcFactory,
    /// Temporary context for events the bus publishes
    ctx: Option<EventContext<Sequenced>>,
    /// Shared admission fence closed before the shutdown event is enqueued.
    #[derivative(Debug = "ignore", PartialEq = "ignore")]
    admission: Arc<EventAdmission>,
    #[derivative(Debug = "ignore", PartialEq = "ignore")]
    _state: PhantomData<S>,
}

impl BusHandle<Disabled> {
    /// Create a new disabled BusHandle. Call `enable()` or `enable_with_hlc()` to activate it.
    pub fn new(
        event_bus: Addr<EventBus<InterfoldEvent<Sequenced>>>,
        sequencer: Addr<Sequencer>,
        hlc: HlcFactory,
    ) -> Self {
        Self {
            event_bus,
            sequencer,
            hlc,
            ctx: None,
            admission: Arc::new(EventAdmission::new()),
            _state: PhantomData,
        }
    }

    /// Enable the BusHandle by providing a node ID string used to create the HLC clock.
    pub fn enable(self, node_id: &str) -> BusHandle<Enabled> {
        let hlc = Hlc::from_str(node_id);
        self.hlc.enable(hlc);
        BusHandle {
            event_bus: self.event_bus,
            sequencer: self.sequencer,
            hlc: self.hlc,
            ctx: None,
            admission: self.admission,
            _state: PhantomData,
        }
    }

    /// Enable the BusHandle by providing a pre-configured HLC clock.
    pub fn enable_with_hlc(self, hlc: Hlc) -> BusHandle<Enabled> {
        self.hlc.enable(hlc);
        BusHandle {
            event_bus: self.event_bus,
            sequencer: self.sequencer,
            hlc: self.hlc,
            ctx: None,
            admission: self.admission,
            _state: PhantomData,
        }
    }
}

impl BusHandle<Enabled> {
    /// Return a HistoryCollector for examining events that have passed through on the events bus
    pub fn history(&self) -> Addr<HistoryCollector<InterfoldEvent<Sequenced>>> {
        EventBus::<InterfoldEvent<Sequenced>>::history(&self.event_bus)
    }

    /// Return a HistoryCollector that is subscribed only to InterfoldError events.
    pub fn errors(&self) -> Addr<HistoryCollector<InterfoldEvent<Sequenced>>> {
        EventBus::<InterfoldEvent<Sequenced>>::error(&self.event_bus)
    }

    /// Access the sequencer to internally dispatch an event to
    pub fn sequencer(&self) -> &Addr<Sequencer> {
        &self.sequencer
    }

    /// Access the event_bus to internally subscribe to events
    pub fn event_bus(&self) -> &Addr<EventBus<InterfoldEvent<Sequenced>>> {
        &self.event_bus
    }

    /// Get a new timestamp. Note this ticks over the internal Hlc.
    pub fn ts(&self) -> Result<u128> {
        let ts = self.hlc.tick()?;
        Ok(ts.into())
    }

    /// Restore the HLC ordering floor from the greatest persisted packed timestamp.
    pub fn seed_clock(&self, packed_ts: u128) -> Result<()> {
        self.hlc.seed_from_history(HlcTimestamp::from(packed_ts))?;
        Ok(())
    }

    /// Pipe events from this handle to the other handle only when the predicate returns true
    pub fn pipe_to<F>(&self, other: &BusHandle<Enabled>, predicate: F)
    where
        F: Fn(&InterfoldEvent<Sequenced>) -> bool + Unpin + 'static,
    {
        let pipe = BusHandlePipe::new(other.to_owned(), predicate).start();
        self.subscribe(EventType::All, pipe.into());
    }

    pub fn with_ec(&self, ec: &EventContext<Sequenced>) -> Self {
        let mut bus = self.clone();
        bus.set_ctx(ec.clone());
        bus
    }
}

impl EventPublisher<InterfoldEvent<Unsequenced>> for BusHandle<Enabled> {
    fn publish(
        &self,
        data: impl Into<InterfoldEventData>,
        caused_by: impl Into<EventContext<Sequenced>>,
    ) -> Result<()> {
        self.publish_local(data, Some(caused_by.into()))
    }

    fn publish_without_context(&self, data: impl Into<InterfoldEventData>) -> Result<()> {
        self.publish_local(data, None)
    }

    fn publish_from_remote(
        &self,
        data: impl Into<InterfoldEventData>,
        remote_ts: u128,
        block: Option<u64>,
        source: EventSource,
    ) -> Result<()> {
        self.publish_from_remote_impl(data, remote_ts, None, block, source)
    }

    fn publish_from_remote_as_response(
        &self,
        data: impl Into<InterfoldEventData>,
        remote_ts: u128,
        caused_by: impl Into<EventContext<Sequenced>>,
        block: Option<u64>,
        source: EventSource,
    ) -> Result<()> {
        self.publish_from_remote_impl(data, remote_ts, Some(caused_by.into()), block, source)
    }

    fn naked_dispatch(&self, event: InterfoldEvent<Unsequenced>) {
        let Ok(_admission) = self.admission.enter() else {
            warn!("Dropping an internal event because node shutdown has closed admission");
            return;
        };
        if let Err(error) = self.sequencer.try_send(event) {
            error!(%error, "Internal event was not admitted by the sequencer");
        }
    }
}

impl BusHandle<Enabled> {
    pub async fn naked_dispatch_async(&self, event: InterfoldEvent<Unsequenced>) -> Result<()> {
        let _admission = self.admission.enter()?;
        self.sequencer.send(PublishEvent(event)).await??;
        Ok(())
    }

    /// Publish locally after durable persistence and bounded admission by every live subscriber.
    pub async fn publish_and_wait(
        &self,
        data: impl Into<InterfoldEventData>,
        caused_by: Option<EventContext<Sequenced>>,
    ) -> Result<()> {
        let _admission = self.admission.enter()?;
        let event = self.event_from(data, caused_by)?;
        self.sequencer.send(PublishEvent(event)).await??;
        Ok(())
    }

    /// Publish remotely after durable persistence and bounded admission by every live subscriber.
    pub async fn publish_from_remote_and_wait(
        &self,
        data: impl Into<InterfoldEventData>,
        remote_ts: u128,
        caused_by: Option<EventContext<Sequenced>>,
        block: Option<u64>,
        source: EventSource,
    ) -> Result<()> {
        let _admission = self.admission.enter()?;
        let event = self.event_from_remote_source(data, caused_by, remote_ts, block, source)?;
        self.sequencer.send(PublishEvent(event)).await??;
        Ok(())
    }

    /// Persist and broadcast `Shutdown`, waiting until every live EventBus
    /// subscriber has completed its shutdown handler.
    pub async fn publish_shutdown_and_wait(&self) -> Result<InterfoldEvent<Sequenced>> {
        let (recipient, response) = oneshot::<InterfoldEvent<Sequenced>>();
        self.event_bus
            .send(Subscribe::new(EventType::Shutdown, recipient.clone()))
            .await?;

        // Refuse new work and wait until every publisher that entered before
        // the fence has enqueued its event. Shutdown is therefore ordered after
        // all admitted work and before every rejected late arrival.
        self.admission.close_and_wait().await;
        let event = self.event_from(Shutdown, None)?;
        self.sequencer.send(PublishEvent(event)).await??;

        let shutdown = response.await?;
        // Awaiting this mailbox operation also proves the EventBus has
        // completed its paused, acknowledged Shutdown fanout.
        self.event_bus
            .send(Unsubscribe::new(EventType::Shutdown, recipient))
            .await?;
        Ok(shutdown)
    }

    /// Drain and flush the event pipeline after producers have observed
    /// `Shutdown`: sequencer -> event-store router -> logs -> sequencer
    /// responses -> EventBus fanout.
    pub async fn flush_event_pipeline(&self) -> Result<()> {
        self.sequencer.send(FlushEventStores).await??;
        self.sequencer.send(SequencerBarrier).await?;
        self.event_bus.send(EventBusBarrier).await?;
        Ok(())
    }

    fn publish_from_remote_impl(
        &self,
        data: impl Into<InterfoldEventData>,
        remote_ts: u128,
        caused_by: Option<EventContext<Sequenced>>,
        block: Option<u64>,
        source: EventSource,
    ) -> Result<()> {
        let _admission = self.admission.enter()?;
        let evt = self.event_from_remote_source(data, caused_by, remote_ts, block, source)?;
        self.sequencer
            .try_send(evt)
            .context("sequencer rejected remote event admission")?;
        Ok(())
    }
    fn publish_local(
        &self,
        data: impl Into<InterfoldEventData>,
        caused_by: Option<EventContext<Sequenced>>,
    ) -> Result<()> {
        let _admission = self.admission.enter()?;
        let evt = self.event_from(data, caused_by)?;
        self.sequencer
            .try_send(evt)
            .context("sequencer rejected local event admission")?;
        Ok(())
    }
}

impl<S> ErrorDispatcher<InterfoldEvent<Unsequenced>> for BusHandle<S> {
    fn err(&self, err_type: EType, error: anyhow::Error) {
        let Ok(_admission) = self.admission.enter() else {
            error!(%error, "Error event not admitted because node shutdown has started");
            return;
        };
        match self.event_from_error(err_type, error, self.get_ctx()) {
            Ok(evt) => {
                if let Err(error) = self.sequencer.try_send(evt) {
                    error!(%error, "Error event was not admitted by the sequencer");
                }
            }
            Err(e) => error!("{e}"),
        }
    }
}

impl EventFactory<InterfoldEvent<Unsequenced>> for BusHandle<Enabled> {
    fn event_from(
        &self,
        data: impl Into<InterfoldEventData>,
        caused_by: Option<EventContext<Sequenced>>,
    ) -> Result<InterfoldEvent<Unsequenced>> {
        let ts = self.hlc.tick()?;
        Ok(InterfoldEvent::<Unsequenced>::new_with_timestamp(
            data.into(),
            caused_by,
            ts.into(),
            None,
            EventSource::Local,
        ))
    }

    fn event_from_remote_source(
        &self,
        data: impl Into<InterfoldEventData>,
        caused_by: Option<EventContext<Sequenced>>,
        ts: u128,
        block: Option<u64>,
        source: EventSource,
    ) -> Result<InterfoldEvent<Unsequenced>> {
        let ts = self.hlc.receive(&ts.into())?;
        Ok(InterfoldEvent::<Unsequenced>::new_with_timestamp(
            data.into(),
            caused_by,
            ts.into(),
            block,
            source,
        ))
    }
}

impl<S> ErrorFactory<InterfoldEvent<Unsequenced>> for BusHandle<S> {
    fn event_from_error(
        &self,
        err_type: EType,
        error: impl Into<anyhow::Error>,
        caused_by: Option<EventContext<Sequenced>>,
    ) -> Result<InterfoldEvent<Unsequenced>> {
        let ts = self.hlc.tick()?;
        InterfoldEvent::<Unsequenced>::from_error(err_type, error, ts.into(), caused_by)
    }
}

impl<S> EventSubscriber<InterfoldEvent<Sequenced>> for BusHandle<S> {
    fn subscribe(&self, event_type: EventType, recipient: Recipient<InterfoldEvent<Sequenced>>) {
        self.event_bus
            .do_send(Subscribe::new(event_type, recipient))
    }

    fn subscribe_all(
        &self,
        event_types: &[EventType],
        recipient: Recipient<InterfoldEvent<Sequenced>>,
    ) {
        for event_type in event_types.iter() {
            self.event_bus
                .do_send(Subscribe::new(*event_type, recipient.clone()));
        }
    }

    fn unsubscribe(&self, event_type: &str, recipient: Recipient<InterfoldEvent<Sequenced>>) {
        self.event_bus
            .do_send(Unsubscribe::new(event_type, recipient));
    }

    fn wait_for(
        &self,
        event_type: EventType,
    ) -> Pin<Box<dyn Future<Output = Result<InterfoldEvent<Sequenced>>> + Send>> {
        let (addr, rx) = oneshot::<InterfoldEvent<Sequenced>>();
        self.subscribe(event_type, addr.clone());
        let bus = self.event_bus.clone();
        Box::pin(async move {
            let r = rx.await?;
            bus.do_send(Unsubscribe::new(event_type, addr));
            Ok(r)
        })
    }
}

impl<S> EventContextManager for BusHandle<S> {
    fn set_ctx<C>(&mut self, value: C)
    where
        C: Into<EventContext<Sequenced>>,
    {
        self.ctx = Some(value.into().clone());
    }
    fn get_ctx(&self) -> Option<EventContext<Sequenced>> {
        self.ctx.clone()
    }
}

/// Actor for piping between BusHandles.
pub struct BusHandlePipe<F>
where
    F: Fn(&InterfoldEvent<Sequenced>) -> bool + Unpin + 'static,
{
    handle: BusHandle<Enabled>,
    predicate: F,
}

impl<F> BusHandlePipe<F>
where
    F: Fn(&InterfoldEvent<Sequenced>) -> bool + Unpin + 'static,
{
    /// Create a new BusHandlePipe only forwarding events to the wrapped handle when the predicate
    /// function returns true
    pub fn new(handle: BusHandle<Enabled>, predicate: F) -> Self {
        Self { handle, predicate }
    }
}

impl<F> Actor for BusHandlePipe<F>
where
    F: Fn(&InterfoldEvent<Sequenced>) -> bool + Unpin + 'static,
{
    type Context = actix::Context<Self>;
    fn started(&mut self, ctx: &mut Self::Context) {
        ctx.set_mailbox_capacity(MAILBOX_LIMIT)
    }
}

impl<F> Handler<InterfoldEvent<Sequenced>> for BusHandlePipe<F>
where
    F: Fn(&InterfoldEvent<Sequenced>) -> bool + Unpin + 'static,
{
    type Result = ();
    fn handle(&mut self, msg: InterfoldEvent<Sequenced>, _: &mut Self::Context) -> Self::Result {
        if (self.predicate)(&msg) {
            let source = msg.source();
            let block = msg.block();
            let (data, ts) = msg.split();
            if let Err(e) = self.handle.publish_from_remote(data, ts, block, source) {
                error!("{e}");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use actix::{Actor, Handler, Message};
    use e3_ciphernode_builder::EventSystem;
    // NOTE: We cannot pull from crate as the features will be missing as they are not default.
    use e3_events::{
        hlc::{Hlc, HlcTimestamp},
        prelude::*,
        BusHandle, EventPublisher, EventType, InterfoldEvent, InterfoldEventData, TestEvent,
    };
    use std::time::{Duration, SystemTime, UNIX_EPOCH};
    use tokio::time::sleep;

    fn now_micros() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_micros() as u64
    }

    #[actix::test]
    async fn restart_seed_keeps_next_event_after_durable_logical_time() -> anyhow::Result<()> {
        let bus = EventSystem::new()
            .with_fresh_bus()
            .handle()?
            .enable_with_hlc(Hlc::new(7).with_clock(|| 1_000));
        let persisted = HlcTimestamp::new(5_000, 17, 99);

        bus.seed_clock(persisted.to_u128())?;
        let next = HlcTimestamp::from(bus.ts()?);

        assert_eq!(next, HlcTimestamp::new(5_000, 18, 7));
        assert!(next > persisted);
        Ok(())
    }

    #[actix::test]
    async fn test_hlc_events() -> anyhow::Result<()> {
        #[derive(Message)]
        #[rtype("Vec<InterfoldEvent>")]
        struct GetEventsOrdered;

        // Setup forwarder
        struct Forwarder {
            dest: BusHandle,
        }
        impl Actor for Forwarder {
            type Context = actix::Context<Self>;
        }

        impl Handler<InterfoldEvent> for Forwarder {
            type Result = ();
            fn handle(&mut self, msg: InterfoldEvent, _: &mut Self::Context) -> Self::Result {
                let ts = msg.ts();
                let block = msg.block();
                let source = msg.source();
                self.dest
                    .publish_from_remote(msg.into_data(), ts, block, source)
                    .unwrap()
            }
        }

        // Setup saver
        struct Saver {
            events: Vec<InterfoldEvent>,
        }

        impl Actor for Saver {
            type Context = actix::Context<Self>;
        }

        impl Handler<InterfoldEvent> for Saver {
            type Result = ();
            fn handle(&mut self, msg: InterfoldEvent, _: &mut Self::Context) -> Self::Result {
                self.events.push(msg);
            }
        }

        impl Handler<GetEventsOrdered> for Saver {
            type Result = Vec<InterfoldEvent>;
            fn handle(&mut self, _: GetEventsOrdered, _: &mut Self::Context) -> Self::Result {
                self.events.clone()
            }
        }

        // 1. setup up two separate busses with out of sync clocks A and B. B should be 30 seconds
        //    faster than A.
        let bus_a = EventSystem::new()
            .with_fresh_bus()
            .handle()?
            .enable_with_hlc(
                Hlc::new(1).with_clock(move || now_micros().saturating_sub(30_000_000)),
            ); // Late
        let bus_b = EventSystem::new()
            .with_fresh_bus()
            .handle()?
            .enable_with_hlc(Hlc::new(2));
        let bus_c = EventSystem::new()
            .with_fresh_bus()
            .handle()?
            .enable_with_hlc(Hlc::new(3));

        let forwarder = Forwarder {
            dest: bus_c.clone(),
        }
        .start();

        // pipe all bus_a and bus_b events to bus_c
        bus_a.subscribe(EventType::All, forwarder.clone().into());
        bus_b.subscribe(EventType::All, forwarder.into());

        // Create and subscribe the Saver to bus_c
        let saver = Saver { events: vec![] }.start();
        bus_c.subscribe(EventType::All, saver.clone().into());

        // Publish events in causal order across buses
        bus_a.publish_without_context(TestEvent::new("one", 1))?;
        sleep(Duration::from_millis(5)).await; // next tick
        bus_b.publish_without_context(TestEvent::new("two", 2))?;
        sleep(Duration::from_millis(5)).await; // next tick
        bus_a.publish_without_context(TestEvent::new("three", 3))?;
        sleep(Duration::from_millis(5)).await; // next tick
        bus_b.publish_without_context(TestEvent::new("four", 4))?;
        sleep(Duration::from_millis(50)).await; // next tick

        // Get events
        let events = saver.send(GetEventsOrdered).await?;

        // Sort by HLC timestamp
        let mut sorted_events = events.clone();
        sorted_events.sort_by_key(|e| e.ts());

        // Extract the payloads/names in HLC-sorted order
        let ordered_names: Vec<_> = sorted_events
            .iter()
            .filter_map(|e| match e.get_data() {
                InterfoldEventData::TestEvent(e) => Some(e.msg.clone()),
                _ => None,
            })
            .collect();

        // ASSERTION 1: Causal order is preserved despite clock drift
        assert_eq!(
            ordered_names,
            vec!["one", "two", "three", "four"],
            "HLC should preserve causal ordering despite 30s clock drift on bus_a"
        );

        // ASSERTION 2: All timestamps are unique (HLC guarantee)
        let timestamps: Vec<_> = sorted_events.iter().map(|e| e.ts()).collect();
        let unique_timestamps: std::collections::HashSet<_> = timestamps.iter().collect();
        assert_eq!(
            timestamps.len(),
            unique_timestamps.len(),
            "All HLC timestamps should be unique"
        );

        // ASSERTION 3: Timestamps are strictly monotonically increasing when sorted
        for window in timestamps.windows(2) {
            assert!(
                window[0] < window[1],
                "HLC timestamps should be strictly increasing: {:?} should be < {:?}",
                window[0],
                window[1]
            );
        }

        Ok(())
    }
}
