// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::{EffectsEnabled, Event, HistoricalEvmSyncStart, InterfoldEvent, InterfoldEventData};
use actix::{Actor, Addr, Handler, Message, Recipient};
use e3_utils::{actix::oneshot_runner::OneShotRunner, MAILBOX_LIMIT};

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
