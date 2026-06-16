// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

mod accusation_quorum_reached;
mod accusation_vote;
mod aggregation_proof_pending;
mod aggregation_proof_signed;
mod aggregator_changed;
mod ciphernode_added;
mod ciphernode_removed;
mod ciphernode_selected;
mod ciphertext_output_published;
mod commitment_consistency;
mod committee_finalize_requested;
mod committee_finalized;
mod committee_published;
mod committee_requested;
mod compute_request;
mod configuration_updated;
mod decryption_key_shared;
mod decryption_share_proof_signed;
mod decryption_share_proofs;
mod decryptionshare_created;
mod die;
mod dkg_fold_attestation;
mod dkg_inner_proof_ready;
mod dkg_recursive_aggregation_complete;
mod e3_failed;
mod e3_request_complete;
mod e3_requested;
mod e3_stage_changed;
mod enable_effects;
mod encryption_key_collection_failed;
mod encryption_key_created;
mod encryption_key_pending;
mod encryption_key_received;
mod interfold_error;
mod keyshare_created;
mod net_ready;
mod operator_activation_changed;
mod outgoing_sync_requested;
mod pk_aggregation_proof_pending;
mod pk_aggregation_proof_signed;
mod pk_generation_proof_signed;
mod plaintext_aggregated;
mod plaintext_output_published;
mod proof;
mod proof_failure_accusation;
mod proof_verification_failed;
mod proof_verification_passed;
mod publickey_aggregated;
mod publish_document;
mod share_computation_proof_signed;
mod share_decryption_proof_pending;
mod share_verification;
mod shutdown;
mod signed_proof;
mod slash_executed;
mod sync_effect;
mod sync_end;
mod sync_start;
mod test_event;
mod threshold_share_collection_failed;
mod threshold_share_created;
mod threshold_share_pending;
mod ticket_balance_updated;
mod ticket_generated;
mod ticket_submitted;
mod typed_event;

pub use accusation_quorum_reached::*;
pub use accusation_vote::*;
pub use aggregation_proof_pending::*;
pub use aggregation_proof_signed::*;
pub use aggregator_changed::*;
pub use ciphernode_added::*;
pub use ciphernode_removed::*;
pub use ciphernode_selected::*;
pub use ciphertext_output_published::*;
pub use commitment_consistency::*;
pub use committee_finalize_requested::*;
pub use committee_finalized::*;
pub use committee_published::*;
pub use committee_requested::*;
pub use compute_request::*;
pub use configuration_updated::*;
pub use decryption_key_shared::*;
pub use decryption_share_proof_signed::*;
pub use decryption_share_proofs::*;
pub use decryptionshare_created::*;
pub use die::*;
pub use dkg_fold_attestation::*;
pub use dkg_inner_proof_ready::*;
pub use dkg_recursive_aggregation_complete::*;
pub use e3_failed::*;
pub use e3_request_complete::*;
pub use e3_requested::*;
pub use e3_stage_changed::*;
use e3_utils::{colorize, colorize_event_ids, Color};
pub use enable_effects::*;
pub use encryption_key_collection_failed::*;
pub use encryption_key_created::*;
pub use encryption_key_pending::*;
pub use encryption_key_received::*;
pub use interfold_error::*;
pub use keyshare_created::*;
pub use net_ready::*;
pub use operator_activation_changed::*;
pub use outgoing_sync_requested::*;
pub use pk_aggregation_proof_pending::*;
pub use pk_aggregation_proof_signed::*;
pub use pk_generation_proof_signed::*;
pub use plaintext_aggregated::*;
pub use plaintext_output_published::*;
pub use proof::*;
pub use proof_failure_accusation::*;
pub use proof_verification_failed::*;
pub use proof_verification_passed::*;
pub use publickey_aggregated::*;
pub use publish_document::*;
pub use share_computation_proof_signed::*;
pub use share_decryption_proof_pending::*;
pub use share_verification::*;
pub use shutdown::*;
pub use signed_proof::*;
pub use slash_executed::*;
use strum::IntoStaticStr;
pub use sync_effect::*;
pub use sync_end::*;
pub use sync_start::*;
pub use test_event::*;
pub use threshold_share_collection_failed::*;
pub use threshold_share_created::*;
pub use threshold_share_pending::*;
pub use ticket_balance_updated::*;
pub use ticket_generated::*;
pub use ticket_submitted::*;
pub use typed_event::*;

use crate::{
    event_context::{AggregateId, EventContext},
    traits::{ErrorEvent, Event, EventConstructorWithTimestamp, EventContextAccessors},
    E3id, EventContextSeq, EventId, EventSource, WithAggregateId,
};
use actix::Message;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::{
    fmt::{self},
    hash::Hash,
};

// In crates/events/src/interfold_event/mod.rs

/// Macro to generate EventType enum and implement From traits
macro_rules! impl_event_types {
    ($($variant:ident),* $(,)?) => {
        // Generate the EventType enum
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
        pub enum EventType {
            /// Wildcard - matches all events
            All,
            $($variant,)*
        }

        impl EventType {
            /// Get the string representation of this event type
            pub fn as_str(&self) -> &'static str {
                match self {
                    EventType::All => "*",
                    $(EventType::$variant => stringify!($variant),)*
                }
            }

            /// Parse an EventType from a string
            #[allow(clippy::should_implement_trait)]
            pub fn from_str(s: &str) -> Option<Self> {
                match s {
                    "*" => Some(EventType::All),
                    $(stringify!($variant) => Some(EventType::$variant),)*
                    _ => None,
                }
            }

            /// Get all event types (excluding All wildcard)
            pub fn all_types() -> Vec<EventType> {
                vec![
                    $(EventType::$variant,)*
                ]
            }
        }

        impl fmt::Display for EventType {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}", self.as_str())
            }
        }

        impl From<EventType> for String {
            fn from(event_type: EventType) -> Self {
                event_type.as_str().to_string()
            }
        }

        impl From<&EventType> for String {
            fn from(event_type: &EventType) -> Self {
                event_type.as_str().to_string()
            }
        }

        // Implement From<InterfoldEventData> for EventType
        impl From<&InterfoldEventData> for EventType {
            fn from(data: &InterfoldEventData) -> Self {
                match data {
                    $(InterfoldEventData::$variant(_) => EventType::$variant,)*
                }
            }
        }

        impl From<InterfoldEventData> for EventType {
            fn from(data: InterfoldEventData) -> Self {
                (&data).into()
            }
        }

        $(
            impl From<$variant> for InterfoldEventData {
                fn from(data: $variant) -> Self {
                    InterfoldEventData::$variant(data)
                }
            }
        )*
    };
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, IntoStaticStr, Serialize, Deserialize)]
pub enum InterfoldEventData {
    AccusationQuorumReached(AccusationQuorumReached),
    AccusationVote(AccusationVote),
    AggregatorChanged(AggregatorChanged),
    ProofFailureAccusation(ProofFailureAccusation),
    ProofVerificationFailed(ProofVerificationFailed),
    ProofVerificationPassed(ProofVerificationPassed),
    KeyshareCreated(KeyshareCreated),
    E3Requested(E3Requested),
    PublicKeyAggregated(PublicKeyAggregated),
    CiphertextOutputPublished(CiphertextOutputPublished),
    DecryptionKeyShared(DecryptionKeyShared),
    DecryptionshareCreated(DecryptionshareCreated),
    PlaintextAggregated(PlaintextAggregated),
    PublishDocumentRequested(PublishDocumentRequested),
    CiphernodeSelected(CiphernodeSelected),
    CiphernodeAdded(CiphernodeAdded),
    CiphernodeRemoved(CiphernodeRemoved),
    TicketBalanceUpdated(TicketBalanceUpdated),
    ConfigurationUpdated(ConfigurationUpdated),
    OperatorActivationChanged(OperatorActivationChanged),
    CommitteePublished(CommitteePublished),
    CommitteeRequested(CommitteeRequested),
    CommitteeFinalizeRequested(CommitteeFinalizeRequested),
    CommitteeFinalized(CommitteeFinalized),
    TicketGenerated(TicketGenerated),
    TicketSubmitted(TicketSubmitted),
    PlaintextOutputPublished(PlaintextOutputPublished),
    PkGenerationProofSigned(PkGenerationProofSigned),
    DkgProofSigned(DkgProofSigned),
    InterfoldError(InterfoldError),
    E3RequestComplete(E3RequestComplete),
    E3Failed(E3Failed),
    E3StageChanged(E3StageChanged),
    Shutdown(Shutdown),
    DocumentReceived(DocumentReceived),
    ThresholdShareCreated(ThresholdShareCreated),
    ThresholdSharePending(ThresholdSharePending),
    EncryptionKeyPending(EncryptionKeyPending),
    EncryptionKeyReceived(EncryptionKeyReceived),
    EncryptionKeyCreated(EncryptionKeyCreated),
    EncryptionKeyCollectionFailed(EncryptionKeyCollectionFailed),
    ThresholdShareCollectionFailed(ThresholdShareCollectionFailed),
    ComputeRequest(ComputeRequest),           // ComputeRequested
    ComputeResponse(ComputeResponse),         // ComputeResponseReceived
    ComputeRequestError(ComputeRequestError), // ComputeRequestFailed
    SignedProofFailed(SignedProofFailed),
    DecryptionShareProofsPending(DecryptionShareProofsPending),
    ShareVerificationDispatched(ShareVerificationDispatched),
    ShareVerificationComplete(ShareVerificationComplete),
    SlashExecuted(SlashExecuted),
    CommitteeMemberExpelled(CommitteeMemberExpelled),
    OutgoingSyncRequested(OutgoingSyncRequested),
    HistoricalEvmSyncStart(HistoricalEvmSyncStart),
    HistoricalNetSyncStart(HistoricalNetSyncStart),
    HistoricalNetSyncEventsReceived(HistoricalNetSyncEventsReceived),
    SyncEffect(SyncEffect),
    SyncEnded(SyncEnded),
    EffectsEnabled(EffectsEnabled),
    NetReady(NetReady),
    DecryptionShareProofSigned(DecryptionShareProofSigned),
    ShareDecryptionProofPending(ShareDecryptionProofPending),
    PkAggregationProofPending(PkAggregationProofPending),
    PkAggregationProofSigned(PkAggregationProofSigned),
    AggregationProofPending(AggregationProofPending),
    AggregationProofSigned(AggregationProofSigned),
    DKGInnerProofReady(DKGInnerProofReady),
    DKGRecursiveAggregationComplete(DKGRecursiveAggregationComplete),
    CommitmentConsistencyCheckRequested(CommitmentConsistencyCheckRequested),
    CommitmentConsistencyCheckComplete(CommitmentConsistencyCheckComplete),
    CommitmentConsistencyViolation(CommitmentConsistencyViolation),
    /// This is a test event to use in testing
    TestEvent(TestEvent),
}

impl InterfoldEventData {
    pub fn event_type(&self) -> String {
        let name: &'static str = self.into();
        name.to_string()
    }
}

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
    payload: InterfoldEventData,
    ctx: EventContext<S>,
}

impl<S> InterfoldEvent<S>
where
    S: SeqState,
{
    pub fn to_bytes(&self) -> Result<Vec<u8>, bincode::Error> {
        bincode::serialize(self)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, bincode::Error> {
        bincode::deserialize(bytes)
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

impl InterfoldEventData {
    pub fn get_e3_id(&self) -> Option<E3id> {
        match self {
            InterfoldEventData::AccusationQuorumReached(ref data) => Some(data.e3_id.clone()),
            InterfoldEventData::AccusationVote(ref data) => Some(data.e3_id.clone()),
            InterfoldEventData::AggregatorChanged(ref data) => Some(data.e3_id.clone()),
            InterfoldEventData::ProofFailureAccusation(ref data) => Some(data.e3_id.clone()),
            InterfoldEventData::ProofVerificationFailed(ref data) => Some(data.e3_id.clone()),
            InterfoldEventData::ProofVerificationPassed(ref data) => Some(data.e3_id.clone()),
            InterfoldEventData::KeyshareCreated(ref data) => Some(data.e3_id.clone()),
            InterfoldEventData::E3Requested(ref data) => Some(data.e3_id.clone()),
            InterfoldEventData::E3RequestComplete(ref data) => Some(data.e3_id.clone()),
            InterfoldEventData::PublicKeyAggregated(ref data) => Some(data.e3_id.clone()),
            InterfoldEventData::CiphertextOutputPublished(ref data) => Some(data.e3_id.clone()),
            InterfoldEventData::DecryptionKeyShared(ref data) => Some(data.e3_id.clone()),
            InterfoldEventData::DecryptionshareCreated(ref data) => Some(data.e3_id.clone()),
            InterfoldEventData::PlaintextAggregated(ref data) => Some(data.e3_id.clone()),
            InterfoldEventData::PkGenerationProofSigned(ref data) => Some(data.e3_id.clone()),
            InterfoldEventData::DkgProofSigned(ref data) => Some(data.e3_id.clone()),
            InterfoldEventData::CiphernodeSelected(ref data) => Some(data.e3_id.clone()),
            InterfoldEventData::ThresholdShareCreated(ref data) => Some(data.e3_id.clone()),
            InterfoldEventData::ThresholdSharePending(ref data) => Some(data.e3_id.clone()),
            InterfoldEventData::EncryptionKeyPending(ref data) => Some(data.e3_id.clone()),
            InterfoldEventData::EncryptionKeyReceived(ref data) => Some(data.e3_id.clone()),
            InterfoldEventData::CommitteePublished(ref data) => Some(data.e3_id.clone()),
            InterfoldEventData::CommitteeRequested(ref data) => Some(data.e3_id.clone()),
            InterfoldEventData::CommitteeFinalizeRequested(ref data) => Some(data.e3_id.clone()),
            InterfoldEventData::PlaintextOutputPublished(ref data) => Some(data.e3_id.clone()),
            InterfoldEventData::CommitteeFinalized(ref data) => Some(data.e3_id.clone()),
            InterfoldEventData::TicketGenerated(ref data) => Some(data.e3_id.clone()),
            InterfoldEventData::TicketSubmitted(ref data) => Some(data.e3_id.clone()),
            InterfoldEventData::EncryptionKeyCreated(ref data) => Some(data.e3_id.clone()),
            InterfoldEventData::ComputeResponse(ref data) => Some(data.e3_id.clone()),
            InterfoldEventData::TestEvent(ref data) => data.e3_id.clone(),
            InterfoldEventData::SignedProofFailed(ref data) => Some(data.e3_id.clone()),
            InterfoldEventData::DecryptionShareProofsPending(ref data) => Some(data.e3_id.clone()),
            InterfoldEventData::ShareVerificationDispatched(ref data) => Some(data.e3_id.clone()),
            InterfoldEventData::ShareVerificationComplete(ref data) => Some(data.e3_id.clone()),
            InterfoldEventData::SlashExecuted(ref data) => Some(data.e3_id.clone()),
            InterfoldEventData::CommitteeMemberExpelled(ref data) => Some(data.e3_id.clone()),
            InterfoldEventData::E3Failed(ref data) => Some(data.e3_id.clone()),
            InterfoldEventData::E3StageChanged(ref data) => Some(data.e3_id.clone()),
            InterfoldEventData::DecryptionShareProofSigned(ref data) => Some(data.e3_id.clone()),
            InterfoldEventData::ShareDecryptionProofPending(ref data) => Some(data.e3_id.clone()),
            InterfoldEventData::PkAggregationProofPending(ref data) => Some(data.e3_id.clone()),
            InterfoldEventData::PkAggregationProofSigned(ref data) => Some(data.e3_id.clone()),
            InterfoldEventData::AggregationProofPending(ref data) => Some(data.e3_id.clone()),
            InterfoldEventData::AggregationProofSigned(ref data) => Some(data.e3_id.clone()),
            InterfoldEventData::DKGRecursiveAggregationComplete(ref data) => {
                Some(data.e3_id.clone())
            }
            InterfoldEventData::DKGInnerProofReady(ref data) => Some(data.e3_id.clone()),
            InterfoldEventData::CommitmentConsistencyCheckRequested(ref data) => {
                Some(data.e3_id.clone())
            }
            InterfoldEventData::CommitmentConsistencyCheckComplete(ref data) => {
                Some(data.e3_id.clone())
            }
            InterfoldEventData::CommitmentConsistencyViolation(ref data) => {
                Some(data.e3_id.clone())
            }
            _ => None,
        }
    }
}

impl WithAggregateId for InterfoldEventData {
    fn get_aggregate_id(&self) -> AggregateId {
        let chain_id = self.get_e3_id().map(|e3_id| e3_id.chain_id());
        AggregateId::from_chain_id(chain_id)
    }
}

impl<S: SeqState> InterfoldEvent<S> {
    pub fn get_e3_id(&self) -> Option<E3id> {
        self.payload.get_e3_id()
    }
}

impl<S: SeqState> WithAggregateId for InterfoldEvent<S> {
    fn get_aggregate_id(&self) -> AggregateId {
        self.payload.get_aggregate_id()
    }
}

impl_event_types!(
    AccusationQuorumReached,
    AccusationVote,
    AggregatorChanged,
    ProofFailureAccusation,
    ProofVerificationFailed,
    ProofVerificationPassed,
    KeyshareCreated,
    E3Requested,
    PublicKeyAggregated,
    CiphertextOutputPublished,
    DecryptionKeyShared,
    DecryptionshareCreated,
    PlaintextAggregated,
    PublishDocumentRequested,
    PkGenerationProofSigned,
    DkgProofSigned,
    E3RequestComplete,
    E3Failed,
    E3StageChanged,
    CiphernodeSelected,
    CiphernodeAdded,
    CiphernodeRemoved,
    TicketBalanceUpdated,
    ConfigurationUpdated,
    OperatorActivationChanged,
    CommitteePublished,
    CommitteeRequested,
    CommitteeFinalizeRequested,
    CommitteeFinalized,
    TicketGenerated,
    TicketSubmitted,
    PlaintextOutputPublished,
    InterfoldError,
    Shutdown,
    TestEvent,
    DocumentReceived,
    ThresholdShareCreated,
    ThresholdSharePending,
    EncryptionKeyPending,
    EncryptionKeyReceived,
    EncryptionKeyCreated,
    EncryptionKeyCollectionFailed,
    ThresholdShareCollectionFailed,
    ComputeRequest,
    ComputeResponse,
    ComputeRequestError,
    SignedProofFailed,
    DecryptionShareProofsPending,
    ShareVerificationDispatched,
    ShareVerificationComplete,
    SlashExecuted,
    CommitteeMemberExpelled,
    OutgoingSyncRequested,
    HistoricalEvmSyncStart,
    HistoricalNetSyncStart,
    HistoricalNetSyncEventsReceived,
    SyncEffect,
    SyncEnded,
    EffectsEnabled,
    NetReady,
    DecryptionShareProofSigned,
    ShareDecryptionProofPending,
    PkAggregationProofPending,
    PkAggregationProofSigned,
    AggregationProofPending,
    AggregationProofSigned,
    DKGInnerProofReady,
    DKGRecursiveAggregationComplete,
    CommitmentConsistencyCheckRequested,
    CommitmentConsistencyCheckComplete,
    CommitmentConsistencyViolation
);

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

// Add convenience method to InterfoldEvent
impl<S: SeqState> InterfoldEvent<S> {
    /// Get the EventType enum for this event
    pub fn event_type_enum(&self) -> EventType {
        (&self.payload).into()
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

#[cfg(feature = "test-helpers")]
impl<S: SeqState> InterfoldEvent<S> {
    /// Create a test event using the TestEventBuilder struct
    pub fn test_event(label: &str) -> TestEventBuilder<Unsequenced> {
        TestEventBuilder::<Unsequenced>::new(label)
    }
}

/// Build out a test event
pub struct TestEventBuilder<S: SeqState> {
    label: String,
    seq: S::Seq,
    id: Option<u64>,
    data: Option<InterfoldEventData>,
    aggregate_id: Option<u64>,
    e3_id: Option<E3id>,
    ts: Option<u128>,
}

impl TestEventBuilder<Unsequenced> {
    /// Create a new test event
    pub fn new(label: &str) -> Self {
        Self {
            label: label.to_owned(),
            seq: (),
            id: None,
            aggregate_id: None,
            data: None,
            e3_id: None,
            ts: None,
        }
    }

    /// make it a sequenced event
    pub fn seq(self, seq: u64) -> TestEventBuilder<Sequenced> {
        TestEventBuilder::<Sequenced> {
            seq,
            label: self.label,
            id: self.id,
            data: self.data,
            aggregate_id: self.aggregate_id,
            e3_id: self.e3_id,
            ts: self.ts,
        }
    }
}

impl<S: SeqState> TestEventBuilder<S> {
    /// Add an e3_id based on a u64 this takes preference over e3_id()
    pub fn id(mut self, id: u64) -> Self {
        self.id = Some(id);
        self
    }

    /// Ensure the event holds the given aggregate_id this takes preference over e3_id()
    pub fn aggregate_id(mut self, id: u64) -> Self {
        self.aggregate_id = Some(id);
        self
    }

    /// Ensure the event holds the given e3_id.
    pub fn e3_id(mut self, e3_id: E3id) -> Self {
        self.e3_id = Some(e3_id);
        self
    }

    /// Ensure the event holds a ts
    pub fn ts(mut self, ts: u128) -> Self {
        self.ts = Some(ts);
        self
    }

    /// Ensure the event holds the given InterfoldEventData object. This overrides all other params
    /// aiside from seq(n)
    pub fn data(mut self, data: impl Into<InterfoldEventData>) -> Self {
        self.data = Some(data.into());
        self
    }

    fn get_built_event(self) -> InterfoldEvent<Unsequenced> {
        let event = self.data.unwrap_or(
            TestEvent {
                msg: self.label,
                entropy: self.id.unwrap_or(0),
                e3_id: resolve_e3_id(self.e3_id, self.id, self.aggregate_id),
            }
            .into(),
        );

        InterfoldEvent::<Unsequenced>::new_with_timestamp(
            event,
            None,
            self.ts.unwrap_or(0),
            None,
            EventSource::Evm,
        )
    }
}

impl TestEventBuilder<Unsequenced> {
    /// Build the event
    pub fn build(self) -> InterfoldEvent<Unsequenced> {
        self.get_built_event()
    }
}

impl TestEventBuilder<Sequenced> {
    /// Build the event
    pub fn build(self) -> InterfoldEvent<Sequenced> {
        let seq = self.seq;
        let unseq = self.get_built_event();
        unseq.into_sequenced(seq)
    }
}

fn resolve_e3_id(e3_id: Option<E3id>, id: Option<u64>, aggregate_id: Option<u64>) -> Option<E3id> {
    match (e3_id, id, aggregate_id) {
        (Some(_), Some(id), Some(agg)) if agg != 0 => Some(E3id::new(id.to_string(), agg)),
        (Some(e3), Some(id), _) => Some(E3id::new(id.to_string(), e3.chain_id())),
        (Some(e3), _, Some(agg)) if agg != 0 => Some(E3id::new(e3.e3_id(), agg)),
        (None, Some(id), Some(agg)) if agg != 0 => Some(E3id::new(id.to_string(), agg)),
        (e3, _, _) => e3,
    }
}
