// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use actix::{Message, Recipient};
use anyhow::Result;
use std::hash::Hash;
use std::pin::Pin;
use std::{fmt::Display, future::Future};

use crate::{
    event_context::{AggregateId, EventContext},
    EventId, EventSource, EventType, InterfoldEvent, Sequenced, Unsequenced,
};

/// Trait that must be implemented by events used with EventBus
pub trait Event:
    Message<Result = ()> + Clone + Display + Send + Sync + Unpin + Sized + 'static
{
    type Id: Hash + Eq + Clone + Unpin + Send + Sync + Display;

    /// Payload for the Event
    type Data: WithAggregateId;
    fn event_id(&self) -> Self::Id;
    fn event_type(&self) -> String;
    fn get_data(&self) -> &Self::Data;
    fn into_data(self) -> Self::Data;
}

/// Trait for events that contain an error
pub trait ErrorEvent: Event {
    /// Error type associated with this event
    type ErrType;
    type FromError;

    fn from_error(
        err_type: Self::ErrType,
        error: impl Into<Self::FromError>,
        ts: u128,
        caused_by: Option<EventContext<Sequenced>>,
    ) -> Result<Self>;
}

/// An EventFactory creates events
pub trait EventFactory<E: Event> {
    /// Create a new event from the given event data, apply a local HLC timestamp.
    ///
    /// This method should be used for events that have originated locally.
    fn event_from(
        &self,
        data: impl Into<E::Data>,
        caused_by: Option<EventContext<Sequenced>>,
    ) -> Result<E>;
    /// Create a new event from the given event data, apply the given remote HLC time to ensure correct
    /// event ordering.
    ///
    /// This method should be used for events that originated from remote sources.
    ///
    /// The Option `caused_by` is for correlation when we send a remote request and receive a response.
    /// Block should be provided when the event is from the blockchain
    fn event_from_remote_source(
        &self,
        data: impl Into<E::Data>,
        caused_by: Option<EventContext<Sequenced>>,
        ts: u128,
        block: Option<u64>,
        source: EventSource,
    ) -> Result<E>;
}

/// An ErrorFactory creates errors.
pub trait ErrorFactory<E: ErrorEvent> {
    /// Create an error event from the given error.
    fn event_from_error(
        &self,
        err_type: E::ErrType,
        error: impl Into<E::FromError>,
        caused_by: Option<EventContext<Sequenced>>,
    ) -> Result<E>;
}

/// An EventPublisher publishes events on it's internal EventBus
pub trait EventPublisher<E: Event> {
    /// Create a new event from the given event data, apply a local HLC timestamp and publish it
    /// to the event bus.
    ///
    /// This method should be used for events that have originated locally.
    ///
    /// The ctx parameter is to pass on the current context to the local event.
    fn publish(
        &self,
        data: impl Into<E::Data>,
        caused_by: impl Into<EventContext<Sequenced>>,
    ) -> Result<()>;
    /// This creates a context based on the given data. This should only be used when an event is
    /// the origin event and does not originate remotely. This is also useful in tests.
    fn publish_without_context(&self, data: impl Into<E::Data>) -> Result<()>;
    /// Create a new event from the given event data, apply the given remote HLC time to ensure correct
    /// event ordering and publish it.
    ///
    /// This method should be used for events that originated from remote sources.
    fn publish_from_remote(
        &self,
        data: impl Into<E::Data>,
        remote_ts: u128,
        block: Option<u64>,
        source: EventSource,
    ) -> Result<()>;
    /// Create a new event from the given event data, apply the given remote HLC time to ensure correct
    /// event ordering and publish it.
    ///
    /// This method should be used for events that originated from remote sources as a response to
    /// a request we have sent
    ///
    /// The `caused_by` parameter is for correlation when we send a remote request and receive a response.
    fn publish_from_remote_as_response(
        &self,
        data: impl Into<E::Data>,
        remote_ts: u128,
        caused_by: impl Into<EventContext<Sequenced>>,
        block: Option<u64>,
        source: EventSource,
    ) -> Result<()>;
    /// Dispatch the given event without applying any HLC transformation.
    fn naked_dispatch(&self, event: E);
}

/// Trait for dispatching errors to an inner event bus.
///
/// Uses a concrete [`anyhow::Error`] so the trait is object-safe (`Box<dyn ErrorDispatcher<_>>`).
pub trait ErrorDispatcher<E: ErrorEvent> {
    /// Dispatch the error to the event bus.
    fn err(&self, err_type: E::ErrType, error: anyhow::Error);
}

/// Trait to subscribe to events
pub trait EventSubscriber<E: Event> {
    /// Subscribe the recipient to events matching the given event type
    fn subscribe(&self, event_type: EventType, recipient: Recipient<E>);
    /// Subscribe the recipient to events matching any of the given event types
    fn subscribe_all(&self, event_types: &[EventType], recipient: Recipient<E>);
    /// Subscribe the recipient to events matching the given event type
    fn unsubscribe(&self, event_type: &str, recipient: Recipient<E>);
    /// Return a future that waits for a specific event
    fn wait_for(&self, event_type: EventType) -> Pin<Box<dyn Future<Output = Result<E>> + Send>>;
}

/// Trait to create an event with a timestamp from its associated type data
pub trait EventConstructorWithTimestamp: Event + Sized {
    /// Create an event passing attaching a specific timestamp.
    fn new_with_timestamp(
        data: Self::Data,
        caused_by: Option<EventContext<Sequenced>>,
        ts: u128,
        block: Option<u64>,
        source: EventSource,
    ) -> Self;
}

pub trait CompositeEvent: EventConstructorWithTimestamp {}

impl<E> CompositeEvent for E where E: Sized + Event + EventConstructorWithTimestamp {}

/// SequenceIndex is the index for each sequence which we can lookup based on HLC timestamp
pub trait SequenceIndex: Unpin + 'static {
    /// Insert a sequence offset at the given timestamp
    fn insert(&mut self, key: u128, value: u64) -> Result<()>;
    /// Get the sequence offset for the given timestamp
    fn get(&self, key: u128) -> Result<Option<u64>>;
    /// Get the first sequence offset at or after the given timestamp
    fn seek(&self, key: u128) -> Result<Option<u64>>;
}

/// Store and retrieve events from a write ahead log
pub trait EventLog: Unpin + 'static {
    /// Append an event to the log, returning its sequence number
    fn append(&mut self, event: &InterfoldEvent<Unsequenced>) -> Result<u64>;
    /// Read all events starting from the given sequence number (inclusive)
    fn read_from(&self, from: u64) -> Box<dyn Iterator<Item = (u64, InterfoldEvent<Unsequenced>)>>;
    /// The 1-indexed sequence number of the last appended event, or `0` if the log is empty.
    fn head(&self) -> u64;
}

/// EventContext allows consumers to extract infrastructure metadata from event objects
pub trait EventContextAccessors {
    /// The unique id for this event
    fn id(&self) -> EventId;
    /// The event that caused this event to occur
    fn causation_id(&self) -> EventId;
    /// The root event that caused this event to occur
    fn origin_id(&self) -> EventId;
    /// The timestamp when the event occurred timestamp is encoded HlcTimestamp format
    fn ts(&self) -> u128;
    /// The aggregate id for this event
    fn aggregate_id(&self) -> AggregateId;
    /// The highest block watermark we have seen
    fn block(&self) -> Option<u64>;
    /// The event source
    fn source(&self) -> EventSource;
    /// Apply a new source fluently
    fn with_source(self, source: EventSource) -> Self;
}

pub trait EventContextSeq {
    /// The sequence number of the event
    fn seq(&self) -> u64;
}

pub trait WithAggregateId {
    /// Extract the aggregate id from the object
    fn get_aggregate_id(&self) -> AggregateId;
}

/// An EventContextManager hold the current event context for use in event publishing and
/// persistence management
pub trait EventContextManager {
    fn set_ctx<C>(&mut self, value: C)
    where
        C: Into<EventContext<Sequenced>>;
    fn get_ctx(&self) -> Option<EventContext<Sequenced>>;
}
