// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Admission of live events into the Sequencer -> EventStore -> EventBus pipeline.
//!
//! An admitted event holds capacity in a shared window until its EventBus fanout ends, so a
//! stalled store, bus or subscriber fills the window and publishers get an error instead of
//! growing mailboxes. An admitted event that leaves the pipeline before its fanout ends is lost:
//! its receipt closes admission and reports the loss on the event-pipeline failure signal, which
//! stops the node.

use std::{
    fmt,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc, Mutex, MutexGuard, OnceLock, PoisonError,
    },
};

use anyhow::{bail, Result};
use e3_utils::MAILBOX_LIMIT_LARGE;
use tokio::sync::{futures::Notified, watch, Notify};
use tracing::{debug, error};

use crate::{InterfoldEvent, Unsequenced, MAX_ENCODED_EVENT_BYTES};

const WINDOW: Usage = Usage {
    events: MAILBOX_LIMIT_LARGE,
    bytes: 512 * 1024 * 1024,
};

/// Publishers that wait for capacity use at most this fraction of the window. The rest stays free
/// for publishers that cannot wait, such as actors reacting to the events being waited in.
const WAITING_SHARE: usize = 4;

/// No event charges more than the window less this fraction of it, so even an event larger than
/// the window leaves room for the events its handlers publish during its fanout.
const FOLLOW_UP_SHARE: usize = 4;

/// The event was not admitted because node shutdown has closed admission.
#[derive(Debug, thiserror::Error)]
#[error("event admission is closed because node shutdown has started")]
pub struct AdmissionClosed;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Usage {
    events: usize,
    bytes: usize,
}

pub(crate) struct EventAdmission {
    /// Shutdown fence: closed before the shutdown event is enqueued.
    accepting: AtomicBool,
    in_flight: AtomicUsize,
    drained: Notify,
    limit: Usage,
    window: Mutex<Usage>,
    released: Notify,
    failure_signal: OnceLock<watch::Sender<Option<String>>>,
    /// The first loss, which closes admission even without a failure signal.
    loss: OnceLock<String>,
}

impl EventAdmission {
    pub(crate) fn new() -> Self {
        Self::with_limit(WINDOW)
    }

    fn with_limit(limit: Usage) -> Self {
        Self {
            accepting: AtomicBool::new(true),
            in_flight: AtomicUsize::new(0),
            drained: Notify::new(),
            limit,
            window: Mutex::new(Usage::default()),
            released: Notify::new(),
            failure_signal: OnceLock::new(),
            loss: OnceLock::new(),
        }
    }

    /// The first signal set is kept.
    pub(crate) fn set_failure_signal(&self, signal: watch::Sender<Option<String>>) {
        let _ = self.failure_signal.set(signal);
    }

    pub(crate) fn enter(self: &Arc<Self>) -> Result<EventAdmissionGuard> {
        if !self.accepting.load(Ordering::Acquire) {
            bail!(AdmissionClosed);
        }

        self.in_flight.fetch_add(1, Ordering::AcqRel);
        let guard = EventAdmissionGuard(Arc::clone(self));
        if !self.accepting.load(Ordering::Acquire) {
            drop(guard);
            bail!(AdmissionClosed);
        }
        Ok(guard)
    }

    pub(crate) async fn close_and_wait(&self) {
        self.accepting.store(false, Ordering::Release);
        // Waiting publishers must observe the closed fence instead of waiting for capacity.
        self.released.notify_waiters();
        loop {
            let drained = self.drained.notified();
            if self.in_flight.load(Ordering::Acquire) == 0 {
                return;
            }
            drained.await;
        }
    }

    /// Reserves window capacity for `event`, failing when the window is full.
    pub(crate) fn reserve(
        self: &Arc<Self>,
        event: &InterfoldEvent<Unsequenced>,
    ) -> Result<EventReceipt> {
        if let Some(receipt) = self.reserve_within(event, self.limit)? {
            return Ok(receipt);
        }
        let usage = *self.window();
        bail!(
            "event admission is saturated: {} admitted events ({} bytes) have not finished \
             EventBus fanout",
            usage.events,
            usage.bytes
        )
    }

    /// Reserves capacity within the share of waiting publishers, or returns `None` when it is
    /// full. Enable a [`Self::released`] future before calling this so no release is missed.
    pub(crate) fn reserve_waiting(
        self: &Arc<Self>,
        event: &InterfoldEvent<Unsequenced>,
    ) -> Result<Option<EventReceipt>> {
        let share = Usage {
            events: self.limit.events / WAITING_SHARE,
            bytes: self.limit.bytes / WAITING_SHARE,
        };
        self.reserve_within(event, share)
    }

    /// Completes when capacity is released or the fence closes.
    pub(crate) fn released(&self) -> Notified<'_> {
        self.released.notified()
    }

    /// The first event fits an empty window whatever its size, so no event is refused forever.
    fn reserve_within(
        self: &Arc<Self>,
        event: &InterfoldEvent<Unsequenced>,
        limit: Usage,
    ) -> Result<Option<EventReceipt>> {
        if let Some(reason) = self.failure() {
            bail!("event admission is closed because the event pipeline failed: {reason}");
        }
        // The cap keeps the sums in range. Two capped events never fit together.
        let max_charge = self.limit.bytes - self.limit.bytes / FOLLOW_UP_SHARE;
        let bytes = bincode::serialized_size(event)
            .unwrap_or(MAX_ENCODED_EVENT_BYTES)
            .min(max_charge as u64) as usize;
        let mut window = self.window();
        if window.events > 0
            && (window.events >= limit.events || window.bytes + bytes > limit.bytes)
        {
            return Ok(None);
        }
        window.events += 1;
        window.bytes += bytes;
        Ok(Some(EventReceipt(Some(Reservation {
            admission: Arc::clone(self),
            bytes,
            event_type: event.event_type_enum().as_str(),
        }))))
    }

    fn window(&self) -> MutexGuard<'_, Usage> {
        self.window.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn failure(&self) -> Option<String> {
        let signalled = self
            .failure_signal
            .get()
            .and_then(|signal| signal.borrow().clone());
        signalled.or_else(|| self.loss.get().cloned())
    }

    fn release(&self, bytes: usize) {
        let mut window = self.window();
        window.events -= 1;
        window.bytes -= bytes;
        drop(window);
        self.released.notify_waiters();
    }

    fn report_loss(&self, event_type: &str) {
        let reason =
            format!("an admitted {event_type} event was lost before its EventBus fanout ended");
        if self.loss.set(reason.clone()).is_err() {
            debug!(%reason, "Event pipeline lost another admitted event");
            return;
        }
        error!(%reason, "Event pipeline lost an admitted event");
        if let Some(signal) = self.failure_signal.get() {
            // Keeps an earlier reason, such as the storage failure that caused this loss.
            record_failure(signal, reason);
        }
    }
}

/// Records `reason` on the event-pipeline failure signal unless it already holds one, so health
/// reports the failure that came first rather than its consequences.
pub(crate) fn record_failure(signal: &watch::Sender<Option<String>>, reason: String) {
    signal.send_if_modified(|current| {
        if current.is_some() {
            return false;
        }
        *current = Some(reason);
        true
    });
}

/// Holds the shutdown fence open while a publisher admits and enqueues one event.
pub(crate) struct EventAdmissionGuard(Arc<EventAdmission>);

impl Drop for EventAdmissionGuard {
    fn drop(&mut self) {
        if self.0.in_flight.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.0.drained.notify_one();
        }
    }
}

/// Window capacity held by one admitted event. The EventBus settles it when the event's fanout
/// ends; dropping it unsettled reports the event as lost.
pub(crate) struct EventReceipt(Option<Reservation>);

struct Reservation {
    admission: Arc<EventAdmission>,
    bytes: usize,
    event_type: &'static str,
}

impl EventReceipt {
    /// For events that are not admitted: replayed, stored directly, or the shutdown event.
    pub(crate) fn untracked() -> Self {
        Self(None)
    }

    pub(crate) fn settle(mut self) {
        if let Some(reservation) = self.0.take() {
            reservation.admission.release(reservation.bytes);
        }
    }
}

impl Drop for EventReceipt {
    fn drop(&mut self) {
        if let Some(reservation) = self.0.take() {
            // Report before releasing, so a woken publisher already sees the failure.
            reservation.admission.report_loss(reservation.event_type);
            reservation.admission.release(reservation.bytes);
        }
    }
}

impl fmt::Debug for EventReceipt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("EventReceipt")
            .field(&self.0.as_ref().map(|reservation| reservation.event_type))
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        eventbus::Dispatch, EventBus, EventBusBarrier, EventConstructorWithTimestamp, EventSource,
        EventType, Subscribe, TestEvent,
    };
    use actix::{Actor, ActorContext, Handler, ResponseActFuture, WrapFuture};

    fn event(msg: &str) -> InterfoldEvent<Unsequenced> {
        InterfoldEvent::<Unsequenced>::new_with_timestamp(
            TestEvent::new(msg, 0).into(),
            None,
            1,
            None,
            EventSource::Local,
        )
    }

    fn size(event: &InterfoldEvent<Unsequenced>) -> usize {
        bincode::serialized_size(event).unwrap() as usize
    }

    fn admission(events: usize, bytes: usize) -> Arc<EventAdmission> {
        Arc::new(EventAdmission::with_limit(Usage { events, bytes }))
    }

    #[test]
    fn window_bounds_admitted_events_and_bytes_until_settled() {
        let small = event("a");
        let by_count = admission(2, usize::MAX / 2);
        let first = by_count.reserve(&small).unwrap();
        let _second = by_count.reserve(&small).unwrap();
        let error = by_count.reserve(&small).unwrap_err();
        assert!(error.to_string().contains("saturated"), "{error:#}");
        first.settle();
        by_count.reserve(&small).unwrap().settle();
        assert!(by_count.failure().is_none());

        let by_bytes = admission(100, 2 * size(&small));
        let _first = by_bytes.reserve(&small).unwrap();
        let _second = by_bytes.reserve(&small).unwrap();
        assert!(by_bytes.reserve(&small).is_err());
    }

    #[test]
    fn waiting_publishers_use_a_share_of_the_window() {
        let small = event("a");
        let admission = admission(2 * WAITING_SHARE, usize::MAX / 2);
        let _first = admission.reserve_waiting(&small).unwrap().unwrap();
        let _second = admission.reserve_waiting(&small).unwrap().unwrap();
        assert!(admission.reserve_waiting(&small).unwrap().is_none());
        admission.reserve(&small).unwrap();
    }

    #[test]
    fn oversized_event_leaves_room_for_follow_ups() {
        let small = event("a");
        let large = event(&"x".repeat(1_000));
        let admission = admission(10, FOLLOW_UP_SHARE * size(&small));
        assert!(size(&large) > admission.limit.bytes);

        let receipt = admission.reserve(&large).unwrap();
        admission.reserve(&small).unwrap().settle();
        assert!(admission.reserve(&large).is_err());
        receipt.settle();
        assert_eq!(*admission.window(), Usage::default());
    }

    /// Stops while it handles an event, so the EventBus fanout of that event fails.
    struct StoppingSubscriber;

    impl Actor for StoppingSubscriber {
        type Context = actix::Context<Self>;
    }

    impl Handler<InterfoldEvent> for StoppingSubscriber {
        type Result = ResponseActFuture<Self, ()>;

        fn handle(&mut self, _: InterfoldEvent, ctx: &mut Self::Context) -> Self::Result {
            ctx.stop();
            Box::pin(std::future::pending().into_actor(self))
        }
    }

    #[actix::test]
    async fn failed_fanout_settles_the_receipt() -> Result<()> {
        let (signal, health) = watch::channel(None);
        let admission = admission(1, usize::MAX / 2);
        admission.set_failure_signal(signal);
        let bus = EventBus::<InterfoldEvent>::default().start();
        bus.send(Subscribe::new(
            EventType::TestEvent,
            StoppingSubscriber.start().recipient(),
        ))
        .await?;

        let event = event("a");
        let receipt = admission.reserve(&event)?;
        bus.send(Dispatch {
            event: event.into_sequenced(1),
            receipt,
        })
        .await?;
        bus.send(EventBusBarrier).await?;

        assert_eq!(*admission.window(), Usage::default());
        assert!(health.borrow().is_none());
        Ok(())
    }

    #[test]
    fn unsettled_receipt_reports_the_first_loss_and_keeps_an_earlier_reason() {
        let (signal, health) = watch::channel(None);
        let admission = admission(10, usize::MAX / 2);
        admission.set_failure_signal(signal.clone());

        drop(admission.reserve(&event("a")).unwrap());
        let reason = health.borrow().clone().expect("the loss is reported");
        assert!(reason.contains("TestEvent event was lost"), "{reason}");
        assert_eq!(*admission.window(), Usage::default());
        let error = admission.reserve(&event("b")).unwrap_err();
        assert!(error.to_string().contains(&reason), "{error:#}");

        let admission = Arc::new(EventAdmission::new());
        admission.set_failure_signal(signal.clone());
        signal.send_replace(None);
        let receipt = admission.reserve(&event("a")).unwrap();
        signal.send_replace(Some("storage failed".to_owned()));
        drop(receipt);
        assert_eq!(health.borrow().as_deref(), Some("storage failed"));
    }

    #[test]
    fn unsettled_receipt_closes_admission_without_a_failure_signal() {
        let admission = admission(10, usize::MAX / 2);
        drop(admission.reserve(&event("a")).unwrap());
        let error = admission.reserve(&event("b")).unwrap_err();
        assert!(
            error.to_string().contains("TestEvent event was lost"),
            "{error:#}"
        );
    }
}
