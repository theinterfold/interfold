// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use super::*;
use crate::{
    event_context::{AggregateId, EventContext},
    traits::{ErrorEvent, Event, EventConstructorWithTimestamp, EventContextAccessors},
    E3id, EventContextSeq, EventId, EventSource, WithAggregateId,
};
use actix::Message;
use e3_utils::{colorize, colorize_event_ids, Color};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::{
    fmt::{self},
    hash::Hash,
};

/// Maximum size for an inline event record or a network-decoded event.
/// Larger local events use the private blob path in `e3-data`.
pub const MAX_ENCODED_EVENT_BYTES: u64 = 32 * 1024 * 1024;

pub trait SeqState: Clone + std::fmt::Debug + 'static {
    type Seq: Unpin
        + Sync
        + Send
        + Serialize
        + DeserializeOwned
        + Clone
        + PartialEq
        + Eq
        + Hash
        + std::fmt::Debug;
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Unsequenced;

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Sequenced;

impl SeqState for Unsequenced {
    type Seq = ();
}

impl SeqState for Sequenced {
    type Seq = u64;
}

#[derive(Message, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[rtype(result = "()")]
#[serde(bound(
    serialize = "S: SeqState, S::Seq: Serialize",
    deserialize = "S: SeqState, S::Seq: DeserializeOwned"
))]
pub struct InterfoldEvent<S: SeqState = Sequenced> {
    pub(super) payload: InterfoldEventData,
    pub(super) ctx: EventContext<S>,
}

impl<S> InterfoldEvent<S>
where
    S: SeqState,
{
    pub fn to_bytes(&self) -> Result<Vec<u8>, bincode::Error> {
        bincode::serialize(self)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, bincode::Error> {
        e3_utils::deserialize_bounded(bytes, MAX_ENCODED_EVENT_BYTES)
    }

    pub fn split(self) -> (InterfoldEventData, u128) {
        (self.payload, self.ctx.ts())
    }

    pub fn into_components(self) -> (InterfoldEventData, EventContext<S>) {
        (self.payload, self.ctx)
    }

    pub fn get_ctx(&self) -> &EventContext<S> {
        &self.ctx
    }

    /// Give deferred copies compact storage for collections inside shared payloads.
    pub fn compact_shared_collections(&mut self) {
        match &mut self.payload {
            InterfoldEventData::EncryptionKeyCreated(data) => {
                data.key = std::sync::Arc::new(data.key.as_ref().clone());
            }
            InterfoldEventData::EncryptionKeyReceived(data) => {
                data.key = std::sync::Arc::new(data.key.as_ref().clone());
            }
            InterfoldEventData::EncryptionKeyPending(data) => {
                data.key = std::sync::Arc::new(data.key.as_ref().clone());
            }
            InterfoldEventData::ThresholdShareCreated(data) => {
                data.share = std::sync::Arc::new(data.share.as_ref().clone());
            }
            InterfoldEventData::ThresholdSharePending(data) => {
                data.full_share = std::sync::Arc::new(data.full_share.as_ref().clone());
            }
            _ => (),
        }
    }

    pub fn get_e3_id(&self) -> Option<E3id> {
        self.payload.get_e3_id()
    }

    /// Get the EventType enum for this event
    pub fn event_type_enum(&self) -> EventType {
        (&self.payload).into()
    }
}

impl<S: SeqState> EventContextAccessors for InterfoldEvent<S> {
    fn causation_id(&self) -> EventId {
        self.ctx.causation_id()
    }
    fn origin_id(&self) -> EventId {
        self.ctx.origin_id()
    }
    fn ts(&self) -> u128 {
        self.ctx.ts()
    }
    fn id(&self) -> EventId {
        self.ctx.id()
    }
    fn aggregate_id(&self) -> AggregateId {
        self.ctx.aggregate_id()
    }
    fn block(&self) -> Option<u64> {
        self.ctx.block()
    }
    fn source(&self) -> EventSource {
        self.ctx.source()
    }
    fn with_source(mut self, source: EventSource) -> Self {
        self.ctx = self.ctx.with_source(source);
        self
    }
}

impl EventContextSeq for InterfoldEvent<Sequenced> {
    fn seq(&self) -> u64 {
        self.ctx.seq()
    }
}

impl InterfoldEvent<Sequenced> {
    pub fn clone_unsequenced(&self) -> InterfoldEvent<Unsequenced> {
        let ts = self.ts();
        let block = self.block();
        let data = self.clone().into_data();
        InterfoldEvent::new_with_timestamp(data, Some(self.ctx.clone()), ts, block, self.source())
    }

    pub fn to_typed_event<T>(&self, data: T) -> TypedEvent<T> {
        let ctx: EventContext<Sequenced> = self.get_ctx().clone();
        TypedEvent::new(data, ctx)
    }
}

impl InterfoldEvent<Unsequenced> {
    pub fn into_sequenced(self, seq: u64) -> InterfoldEvent<Sequenced> {
        InterfoldEvent::<Sequenced> {
            payload: self.payload,
            ctx: self.ctx.sequence(seq),
        }
    }
}

impl TryFrom<Vec<u8>> for InterfoldEvent<Unsequenced> {
    type Error = bincode::Error;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        InterfoldEvent::from_bytes(&value)
    }
}

#[cfg(feature = "test-helpers")]
impl InterfoldEvent<Sequenced> {
    /// test-helpers only utility function to create a new sequenced event
    pub fn new_stored_event(data: InterfoldEventData, time: u128, seq: u64) -> Self {
        InterfoldEvent::<Unsequenced>::new_with_timestamp(
            data,
            None,
            time,
            None,
            EventSource::Local,
        )
        .into_sequenced(seq)
    }

    /// test-helpers only utility function to create a new sequenced event
    pub fn from_data_ec(data: InterfoldEventData, ec: EventContext<Sequenced>) -> Self {
        InterfoldEvent::<Unsequenced>::new_with_timestamp(
            data,
            Some(ec.clone()),
            ec.ts(),
            ec.block(),
            EventSource::Local,
        )
        .into_sequenced(ec.seq())
    }

    /// test-helpers only utility function to remove time information from an event
    pub fn strip_ts(&self) -> InterfoldEvent {
        InterfoldEvent::new_stored_event(self.get_data().clone(), 0, self.seq())
    }
}

impl<S: SeqState> Event for InterfoldEvent<S> {
    type Id = EventId;
    type Data = InterfoldEventData;

    fn event_id(&self) -> Self::Id {
        self.ctx.id()
    }

    fn delivery_id(&self) -> Self::Id {
        match self.source() {
            // Existing persisted EVM events use a payload-derived EventId. Include the chain,
            // block, and deterministic log timestamp (which carries the log index) in local
            // delivery identity. Equal facts from distinct chain-log occurrences are both
            // applied, while replay of the same occurrence at the snapshot boundary stays
            // idempotent.
            EventSource::Evm => EventId::hash((
                self.ctx.id(),
                self.ctx.aggregate_id(),
                self.ctx.block(),
                self.ctx.ts(),
            )),
            // Equal C2/C3 or C6 verdicts can belong to different batches: a share batch grows,
            // and C6 batches are replaced. An error's ID is its payload, so the same failure of two
            // different events has one ID. The cause tells such occurrences apart without changing
            // persisted or network event payloads; a repeat of one occurrence stays one delivery.
            EventSource::Local
                if matches!(
                    self.payload,
                    InterfoldEventData::ShareVerificationComplete(ShareVerificationComplete {
                        kind: VerificationKind::ShareProofs
                            | VerificationKind::ThresholdDecryptionProofs,
                        ..
                    }) | InterfoldEventData::InterfoldError(_)
                ) =>
            {
                EventId::hash((self.ctx.id(), self.ctx.causation_id()))
            }
            EventSource::Local | EventSource::Net => self.ctx.id(),
        }
    }

    fn event_type(&self) -> String {
        self.payload.event_type()
    }

    fn get_data(&self) -> &InterfoldEventData {
        &self.payload
    }

    fn into_data(self) -> InterfoldEventData {
        self.payload
    }
}

impl ErrorEvent for InterfoldEvent<Unsequenced> {
    type ErrType = EType;
    type FromError = anyhow::Error;

    fn from_error(
        err_type: Self::ErrType,
        msg: impl Into<Self::FromError>,
        ts: u128,
        caused_by: Option<EventContext<Sequenced>>,
    ) -> anyhow::Result<Self> {
        let payload = InterfoldError::new(err_type, msg);
        let id = EventId::hash(&payload);
        let aggregate_id = AggregateId::new(0); // Error events use default aggregate_id

        let ctx = caused_by
            .map(|cause| {
                EventContext::from_cause(id, cause, ts, aggregate_id, None, EventSource::Local)
            })
            .unwrap_or_else(|| {
                EventContext::new_origin(id, ts, aggregate_id, None, EventSource::Local)
            });

        Ok(InterfoldEvent {
            payload: payload.into(),
            ctx,
        })
    }
}

impl<S: SeqState> From<InterfoldEvent<S>> for EventId {
    fn from(value: InterfoldEvent<S>) -> Self {
        value.ctx.id()
    }
}

impl<S: SeqState> From<&InterfoldEvent<S>> for EventId {
    fn from(value: &InterfoldEvent<S>) -> Self {
        value.ctx.id()
    }
}

impl<S: SeqState> WithAggregateId for InterfoldEvent<S> {
    fn get_aggregate_id(&self) -> AggregateId {
        self.payload.get_aggregate_id()
    }
}

impl TryFrom<&InterfoldEvent<Sequenced>> for InterfoldError {
    type Error = anyhow::Error;
    fn try_from(value: &InterfoldEvent) -> Result<Self, Self::Error> {
        value.clone().try_into()
    }
}

impl TryFrom<InterfoldEvent<Sequenced>> for InterfoldError {
    type Error = anyhow::Error;
    fn try_from(value: InterfoldEvent<Sequenced>) -> Result<Self, Self::Error> {
        if let InterfoldEventData::InterfoldError(data) = value.payload.clone() {
            Ok(data)
        } else {
            Err(anyhow::anyhow!("Not an interfold error {:?}", value))
        }
    }
}

impl From<InterfoldEvent<Sequenced>> for EventContext<Sequenced> {
    fn from(value: InterfoldEvent) -> Self {
        (&value).into()
    }
}

impl From<&InterfoldEvent<Sequenced>> for EventContext<Sequenced> {
    fn from(value: &InterfoldEvent) -> Self {
        value.ctx.clone()
    }
}

impl<S: SeqState> fmt::Display for InterfoldEvent<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let t = self.event_type();
        let colorized_debug = colorize_event_ids(self);

        let s = match t.as_str() {
            "InterfoldError" => format!("{} {}", colorize(t, Color::Red), colorized_debug),
            _ => format!("{} {}", colorize(t, Color::Cyan), colorized_debug),
        };
        f.write_str(&s)
    }
}

impl EventConstructorWithTimestamp for InterfoldEvent<Unsequenced> {
    fn new_with_timestamp(
        data: Self::Data,
        caused_by: Option<EventContext<Sequenced>>,
        ts: u128,
        block: Option<u64>,
        source: EventSource,
    ) -> Self {
        let payload: InterfoldEventData = data;
        let id = EventId::hash(&payload);
        let aggregate_id = payload.get_aggregate_id();
        InterfoldEvent {
            payload,
            ctx: caused_by
                .map(|cause| EventContext::from_cause(id, cause, ts, aggregate_id, block, source))
                .unwrap_or_else(|| EventContext::new_origin(id, ts, aggregate_id, block, source)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_decode_rejects_trailing_bytes() {
        let event = InterfoldEvent::<Unsequenced>::new_with_timestamp(
            TestEvent::new("bounded", 1).into(),
            None,
            1,
            None,
            EventSource::Local,
        );
        let mut bytes = event.to_bytes().unwrap();
        bytes.push(0);

        assert!(InterfoldEvent::<Unsequenced>::from_bytes(&bytes).is_err());
    }

    #[test]
    fn evm_delivery_identity_distinguishes_equal_facts_by_log_occurrence() {
        let data: InterfoldEventData = TestEvent::new("same fact", 1).into();
        let first = InterfoldEvent::<Unsequenced>::new_with_timestamp(
            data.clone(),
            None,
            1,
            Some(100),
            EventSource::Evm,
        );
        let second = InterfoldEvent::<Unsequenced>::new_with_timestamp(
            data.clone(),
            None,
            2,
            Some(100),
            EventSource::Evm,
        );
        let replay = InterfoldEvent::<Unsequenced>::new_with_timestamp(
            data,
            None,
            1,
            Some(100),
            EventSource::Evm,
        );
        let other_chain = InterfoldEvent {
            payload: first.payload.clone(),
            ctx: first.ctx.clone().with_aggregate(AggregateId::new(2)),
        };

        assert_eq!(first.event_id(), second.event_id());
        assert_ne!(first.delivery_id(), second.delivery_id());
        assert_eq!(first.delivery_id(), replay.delivery_id());
        assert_ne!(first.delivery_id(), other_chain.delivery_id());
    }

    #[test]
    fn local_errors_distinguish_causes_but_deduplicate_repeats() -> anyhow::Result<()> {
        let make_error = |cause: &str, ts| {
            let cause = EventContext::<Unsequenced>::from(InterfoldEventData::from(
                TestEvent::new(cause, 1),
            ))
            .sequence(0);
            InterfoldEvent::<Unsequenced>::from_error(
                EType::KeyGeneration,
                anyhow::anyhow!("persistable store mailbox rejected snapshot write"),
                ts,
                Some(cause),
            )
        };
        let first = make_error("event of E3 A", 1)?;
        let other = make_error("event of E3 B", 2)?;
        let repeat = make_error("event of E3 A", 3)?;
        assert_eq!(first.event_id(), other.event_id());
        assert_ne!(first.delivery_id(), other.delivery_id());
        assert_eq!(first.delivery_id(), repeat.delivery_id());
        Ok(())
    }

    #[test]
    fn local_batch_verdicts_distinguish_batches_but_deduplicate_retries() {
        for kind in [
            VerificationKind::ShareProofs,
            VerificationKind::ThresholdDecryptionProofs,
        ] {
            let outcome: InterfoldEventData = ShareVerificationComplete {
                e3_id: E3id::new("1", 1),
                kind: kind.clone(),
                dishonest_parties: Default::default(),
            }
            .into();
            let make_result = |batch: &str, ts| {
                let cause = EventContext::<Unsequenced>::from(InterfoldEventData::from(
                    TestEvent::new(batch, 1),
                ))
                .sequence(0);
                InterfoldEvent::<Unsequenced>::new_with_timestamp(
                    outcome.clone(),
                    Some(cause),
                    ts,
                    None,
                    EventSource::Local,
                )
            };
            let first = make_result("first", 1);
            let replacement = make_result("replacement", 2);
            let replay = make_result("first", 3);
            assert_eq!(first.event_id(), replacement.event_id(), "{kind:?}");
            assert_ne!(first.delivery_id(), replacement.delivery_id(), "{kind:?}");
            assert_eq!(first.delivery_id(), replay.delivery_id(), "{kind:?}");
        }
    }
}
