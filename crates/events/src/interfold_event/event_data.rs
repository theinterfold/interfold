// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use super::*;
use crate::{AggregateId, E3id, WithAggregateId};
use serde::{Deserialize, Serialize};
use std::fmt;

/// Generates `InterfoldEventData`, `EventType`, and their conversions from one variant list.
///
/// Each variant wraps the payload type of the same name. The list order is the bincode
/// discriminant order of persisted events, so new variants go at the end.
macro_rules! interfold_event_data {
    ($($(#[$attr:meta])* $variant:ident),* $(,)?) => {
        #[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
        pub enum InterfoldEventData {
            $($(#[$attr])* $variant($variant),)*
        }

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
        }

        impl From<&InterfoldEventData> for EventType {
            fn from(data: &InterfoldEventData) -> Self {
                match data {
                    $(InterfoldEventData::$variant(_) => EventType::$variant,)*
                }
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

interfold_event_data!(
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
    PkGenerationProofSigned,
    DkgProofSigned,
    InterfoldError,
    E3RequestComplete,
    E3Failed,
    E3StageChanged,
    Shutdown,
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
    CommitmentConsistencyViolation,
    /// This is a test event to use in testing
    TestEvent,
    InputPublished,
    RewardsDistributed,
    RewardCredited,
    RewardClaimed,
    CiphernodeBondUpdated,
    CiphernodeDeregistrationRequested,
    CommitteeFormationFailed,
    CommitteeActivationChanged,
    CommitteeViabilityUpdated,
    EvmLogObserved,
    BondOwnerSet,
    DkgFoldAttestationContextEstablished,
    CommitteeMemberExcluded,
    AggregationInputsReady,
    CommitteePublicKeyChunkPublished,
    CiphertextOutputReferencePublished,
    DkgCoordination,
    CommitmentRosterSelected,
    BondOwnerSetAt,
    AdmissionUpdated,
    TicketBalanceUpdatedAt,
    OperatorActivationChangedAt,
    ConfigurationUpdatedAt,
    PlaintextVerificationResumed,
    EligibilityConfigurationVersionUpdated,
    EligibilityConfigurationVersionUpdatedAt,
    BondingAssetConfigUpdated,
    BondingAssetConfigUpdatedAt,
);

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

impl From<InterfoldEventData> for EventType {
    fn from(data: InterfoldEventData) -> Self {
        (&data).into()
    }
}

impl InterfoldEventData {
    pub fn event_type(&self) -> String {
        EventType::from(self).as_str().to_string()
    }

    /// The E3 that this payload belongs to. The match lists every variant, so a new variant must
    /// state whether it carries an E3: the E3 chain selects the event's aggregate.
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
            InterfoldEventData::PublishDocumentRequested(ref data) => Some(data.meta.e3_id.clone()),
            InterfoldEventData::DocumentReceived(ref data) => Some(data.meta.e3_id.clone()),
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
            InterfoldEventData::CommitteeMemberExcluded(ref data) => Some(data.e3_id.clone()),
            InterfoldEventData::AggregationInputsReady(ref data) => Some(data.e3_id.clone()),
            InterfoldEventData::E3Failed(ref data) => Some(data.e3_id.clone()),
            InterfoldEventData::E3StageChanged(ref data) => Some(data.e3_id.clone()),
            InterfoldEventData::DecryptionShareProofSigned(ref data) => Some(data.e3_id.clone()),
            InterfoldEventData::ShareDecryptionProofPending(ref data) => Some(data.e3_id.clone()),
            InterfoldEventData::PkAggregationProofPending(ref data) => Some(data.e3_id.clone()),
            InterfoldEventData::PkAggregationProofSigned(ref data) => Some(data.e3_id.clone()),
            InterfoldEventData::AggregationProofPending(ref data) => Some(data.e3_id.clone()),
            InterfoldEventData::AggregationProofSigned(ref data) => Some(data.e3_id.clone()),
            InterfoldEventData::PlaintextVerificationResumed(ref data) => Some(data.e3_id.clone()),
            InterfoldEventData::DKGRecursiveAggregationComplete(ref data) => {
                Some(data.e3_id.clone())
            }
            InterfoldEventData::DKGInnerProofReady(ref data) => Some(data.e3_id.clone()),
            InterfoldEventData::DkgCoordination(ref data) => Some(data.e3_id.clone()),
            InterfoldEventData::CommitmentRosterSelected(ref data) => Some(data.e3_id.clone()),
            InterfoldEventData::CommitmentConsistencyCheckRequested(ref data) => {
                Some(data.e3_id.clone())
            }
            InterfoldEventData::CommitmentConsistencyCheckComplete(ref data) => {
                Some(data.e3_id.clone())
            }
            InterfoldEventData::CommitmentConsistencyViolation(ref data) => {
                Some(data.e3_id.clone())
            }
            InterfoldEventData::InputPublished(ref data) => Some(data.e3_id.clone()),
            InterfoldEventData::RewardsDistributed(ref data) => Some(data.e3_id.clone()),
            InterfoldEventData::RewardCredited(ref data) => Some(data.e3_id.clone()),
            InterfoldEventData::RewardClaimed(ref data) => Some(data.e3_id.clone()),
            InterfoldEventData::CommitteeFormationFailed(ref data) => Some(data.e3_id.clone()),
            InterfoldEventData::CommitteeActivationChanged(ref data) => Some(data.e3_id.clone()),
            InterfoldEventData::CommitteeViabilityUpdated(ref data) => Some(data.e3_id.clone()),
            InterfoldEventData::EvmLogObserved(ref data) => data.e3_id.clone(),
            InterfoldEventData::DkgFoldAttestationContextEstablished(ref data) => {
                Some(data.e3_id.clone())
            }
            InterfoldEventData::CommitteePublicKeyChunkPublished(ref data) => {
                Some(data.e3_id.clone())
            }
            InterfoldEventData::CiphertextOutputReferencePublished(ref data) => {
                Some(data.e3_id.clone())
            }
            // The failed request keeps the E3 that the work belonged to. Without this arm the
            // error logs for a failed computation have an empty `e3_id` field.
            InterfoldEventData::ComputeRequestError(ref data) => Some(data.request().e3_id.clone()),
            InterfoldEventData::CiphernodeAdded(_)
            | InterfoldEventData::CiphernodeRemoved(_)
            | InterfoldEventData::TicketBalanceUpdated(_)
            | InterfoldEventData::ConfigurationUpdated(_)
            | InterfoldEventData::OperatorActivationChanged(_)
            | InterfoldEventData::InterfoldError(_)
            | InterfoldEventData::Shutdown(_)
            | InterfoldEventData::EncryptionKeyCollectionFailed(_)
            | InterfoldEventData::ThresholdShareCollectionFailed(_)
            | InterfoldEventData::ComputeRequest(_)
            | InterfoldEventData::OutgoingSyncRequested(_)
            | InterfoldEventData::HistoricalEvmSyncStart(_)
            | InterfoldEventData::HistoricalNetSyncStart(_)
            | InterfoldEventData::HistoricalNetSyncEventsReceived(_)
            | InterfoldEventData::SyncEffect(_)
            | InterfoldEventData::SyncEnded(_)
            | InterfoldEventData::EffectsEnabled(_)
            | InterfoldEventData::NetReady(_)
            | InterfoldEventData::CiphernodeBondUpdated(_)
            | InterfoldEventData::CiphernodeDeregistrationRequested(_)
            | InterfoldEventData::BondOwnerSet(_)
            | InterfoldEventData::BondOwnerSetAt(_)
            | InterfoldEventData::AdmissionUpdated(_)
            | InterfoldEventData::TicketBalanceUpdatedAt(_)
            | InterfoldEventData::OperatorActivationChangedAt(_)
            | InterfoldEventData::ConfigurationUpdatedAt(_)
            | InterfoldEventData::EligibilityConfigurationVersionUpdated(_)
            | InterfoldEventData::EligibilityConfigurationVersionUpdatedAt(_)
            | InterfoldEventData::BondingAssetConfigUpdated(_)
            | InterfoldEventData::BondingAssetConfigUpdatedAt(_) => None,
        }
    }
}

impl WithAggregateId for InterfoldEventData {
    fn get_aggregate_id(&self) -> AggregateId {
        if let InterfoldEventData::EvmLogObserved(event) = self {
            return AggregateId::from_chain_id(Some(event.chain_id));
        }
        let chain_id = self.get_e3_id().map(|e3_id| e3_id.chain_id());
        AggregateId::from_chain_id(chain_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn document_events_use_their_e3_chain_aggregate() {
        let meta = DocumentMeta::new(E3id::new("7", 1), DocumentKind::TrBFV, vec![], None);
        let value = e3_utils::ArcBytes::from_bytes(b"document");
        let publish = InterfoldEventData::PublishDocumentRequested(PublishDocumentRequested {
            meta: meta.clone(),
            value: value.clone(),
        });
        let received = InterfoldEventData::DocumentReceived(DocumentReceived { meta, value });
        let expected = AggregateId::from_chain_id(Some(1));

        assert_eq!(publish.get_aggregate_id(), expected);
        assert_eq!(received.get_aggregate_id(), expected);
    }
}
