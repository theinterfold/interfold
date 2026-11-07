// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::{EffectsEnabled, Event, HistoricalEvmSyncStart, InterfoldEvent, InterfoldEventData};
use actix::{Actor, Addr, Handler, Message, Recipient};
use e3_utils::MAILBOX_LIMIT;
use std::marker::PhantomData;
use tracing::error;

/// Trait for events that can be extracted from InterfoldEventData
pub trait ExtractableEvent: Message<Result = ()> + Send + 'static {
    fn extract_from(data: InterfoldEventData) -> Option<Self>
    where
        Self: Sized;
}

/// Generic event extractor that can handle any ExtractableEvent
pub struct EventExtractor<T: ExtractableEvent> {
    dest: Recipient<T>,
}

impl<T: ExtractableEvent> EventExtractor<T> {
    pub fn new(dest: impl Into<Recipient<T>>) -> Self {
        Self { dest: dest.into() }
    }

    pub fn setup(dest: impl Into<Recipient<T>>) -> Addr<Self> {
        Self::new(dest).start()
    }
}

impl<T: ExtractableEvent> Actor for EventExtractor<T> {
    type Context = actix::Context<Self>;

    fn started(&mut self, ctx: &mut Self::Context) {
        ctx.set_mailbox_capacity(MAILBOX_LIMIT)
    }
}

impl<T: ExtractableEvent> Handler<InterfoldEvent> for EventExtractor<T> {
    type Result = ();

    fn handle(&mut self, msg: InterfoldEvent, _: &mut Self::Context) -> Self::Result {
        if let Some(evt) = T::extract_from(msg.into_data()) {
            self.dest.do_send(evt)
        }
    }
}

impl ExtractableEvent for EffectsEnabled {
    fn extract_from(data: InterfoldEventData) -> Option<Self> {
        if let InterfoldEventData::EffectsEnabled(evt) = data {
            Some(evt)
        } else {
            None
        }
    }
}

impl ExtractableEvent for HistoricalEvmSyncStart {
    fn extract_from(data: InterfoldEventData) -> Option<Self> {
        if let InterfoldEventData::HistoricalEvmSyncStart(evt) = data {
            Some(evt)
        } else {
            None
        }
    }
}

/// Helper function to set up a one-shot event extractor
pub fn run_once<T: ExtractableEvent + Unpin>(
    f: impl FnOnce(T) -> anyhow::Result<()> + Unpin + Send + 'static,
) -> Addr<EventExtractor<T>> {
    // EventExtractor filters the given event and sends to the receiver
    EventExtractor::<T>::setup(
        // OneShotRunner runs the closure once when it first receives the event
        OneShotRunner::setup(f),
    )
}

/// Runs its closure on the first message it receives and logs any error. Later messages are
/// ignored.
struct OneShotRunner<F, M>
where
    F: FnOnce(M) -> anyhow::Result<()> + 'static,
    M: Message<Result = ()> + 'static,
{
    task: Option<F>,
    _marker: PhantomData<M>,
}

impl<F, M> OneShotRunner<F, M>
where
    F: FnOnce(M) -> anyhow::Result<()> + 'static + Unpin,
    M: Message<Result = ()> + 'static + Unpin,
{
    fn new(task: F) -> Self {
        Self {
            task: Some(task),
            _marker: PhantomData,
        }
    }

    fn setup(task: F) -> Addr<Self> {
        Self::new(task).start()
    }
}

impl<F, M> Actor for OneShotRunner<F, M>
where
    F: FnOnce(M) -> anyhow::Result<()> + 'static + Unpin,
    M: Message<Result = ()> + 'static + Unpin,
{
    type Context = actix::Context<Self>;

    fn started(&mut self, ctx: &mut Self::Context) {
        ctx.set_mailbox_capacity(MAILBOX_LIMIT)
    }
}

impl<F, M> Handler<M> for OneShotRunner<F, M>
where
    F: FnOnce(M) -> anyhow::Result<()> + 'static + Unpin,
    M: Message<Result = ()> + 'static + Unpin,
{
    type Result = ();

    fn handle(&mut self, msg: M, _ctx: &mut Self::Context) -> Self::Result {
        if let Some(task) = self.task.take() {
            match task(msg) {
                Ok(_) => (),
                Err(e) => error!("{e}"),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    #[derive(Message)]
    #[rtype(result = "()")]
    struct TestMessage(usize);

    #[actix::test]
    async fn test_one_shot_runner() {
        let call_count = Arc::new(AtomicUsize::new(0));
        let received_value = Arc::new(AtomicUsize::new(0));
        let call_count_clone = call_count.clone();
        let received_value_clone = received_value.clone();

        let runner = OneShotRunner::new(move |msg: TestMessage| {
            call_count_clone.fetch_add(1, Ordering::SeqCst);
            received_value_clone.store(msg.0, Ordering::SeqCst);
            Ok(())
        });

        let addr = runner.start();
        addr.send(TestMessage(42)).await.unwrap();
        addr.send(TestMessage(99)).await.unwrap();

        assert_eq!(received_value.load(Ordering::SeqCst), 42);
        assert_eq!(call_count.load(Ordering::SeqCst), 1);
    }
}
