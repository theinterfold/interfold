// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use actix::Message;
use serde::{Deserialize, Serialize};
use std::fmt::{self, Display};

use super::{
    AccusationQuorumReached, CommitteeFinalizeRequested, ComputeRequest, E3StageChanged,
    InterfoldEventData, PlaintextAggregated, PublicKeyAggregated, PublishDocumentRequested,
    TicketGenerated,
};

/// The closed set of side-effect intents that startup recovery may re-drive.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RecoverableEffect {
    ComputeRequest(ComputeRequest),
    TicketGenerated(TicketGenerated),
    CommitteeFinalizeRequested(CommitteeFinalizeRequested),
    PublicKeyAggregated(PublicKeyAggregated),
    PlaintextAggregated(PlaintextAggregated),
    PublishDocumentRequested(PublishDocumentRequested),
    AccusationQuorumReached(AccusationQuorumReached),
    E3StageChanged(E3StageChanged),
}

impl RecoverableEffect {
    fn event_type(&self) -> &'static str {
        match self {
            Self::ComputeRequest(_) => "ComputeRequest",
            Self::TicketGenerated(_) => "TicketGenerated",
            Self::CommitteeFinalizeRequested(_) => "CommitteeFinalizeRequested",
            Self::PublicKeyAggregated(_) => "PublicKeyAggregated",
            Self::PlaintextAggregated(_) => "PlaintextAggregated",
            Self::PublishDocumentRequested(_) => "PublishDocumentRequested",
            Self::AccusationQuorumReached(_) => "AccusationQuorumReached",
            Self::E3StageChanged(_) => "E3StageChanged",
        }
    }

    pub fn e3_id(&self) -> &crate::E3id {
        match self {
            Self::ComputeRequest(effect) => &effect.e3_id,
            Self::TicketGenerated(effect) => &effect.e3_id,
            Self::CommitteeFinalizeRequested(effect) => &effect.e3_id,
            Self::PublicKeyAggregated(effect) => &effect.e3_id,
            Self::PlaintextAggregated(effect) => &effect.e3_id,
            Self::PublishDocumentRequested(effect) => &effect.meta.e3_id,
            Self::AccusationQuorumReached(effect) => &effect.e3_id,
            Self::E3StageChanged(effect) => &effect.e3_id,
        }
    }

    pub fn is_compute(&self) -> bool {
        matches!(self, Self::ComputeRequest(_))
    }

    fn into_event_data(self) -> InterfoldEventData {
        match self {
            Self::ComputeRequest(effect) => effect.into(),
            Self::TicketGenerated(effect) => effect.into(),
            Self::CommitteeFinalizeRequested(effect) => effect.into(),
            Self::PublicKeyAggregated(effect) => effect.into(),
            Self::PlaintextAggregated(effect) => effect.into(),
            Self::PublishDocumentRequested(effect) => effect.into(),
            Self::AccusationQuorumReached(effect) => effect.into(),
            Self::E3StageChanged(effect) => effect.into(),
        }
    }
}

impl TryFrom<InterfoldEventData> for RecoverableEffect {
    type Error = InterfoldEventData;

    fn try_from(effect: InterfoldEventData) -> Result<Self, Self::Error> {
        match effect {
            InterfoldEventData::ComputeRequest(effect) => Ok(Self::ComputeRequest(effect)),
            InterfoldEventData::TicketGenerated(effect) => Ok(Self::TicketGenerated(effect)),
            InterfoldEventData::CommitteeFinalizeRequested(effect) => {
                Ok(Self::CommitteeFinalizeRequested(effect))
            }
            InterfoldEventData::PublicKeyAggregated(effect) => {
                Ok(Self::PublicKeyAggregated(effect))
            }
            InterfoldEventData::PlaintextAggregated(effect) => {
                Ok(Self::PlaintextAggregated(effect))
            }
            InterfoldEventData::PublishDocumentRequested(effect) => {
                Ok(Self::PublishDocumentRequested(effect))
            }
            InterfoldEventData::AccusationQuorumReached(effect) => {
                Ok(Self::AccusationQuorumReached(effect))
            }
            InterfoldEventData::E3StageChanged(effect) => Ok(Self::E3StageChanged(effect)),
            unsupported => Err(unsupported),
        }
    }
}

/// Internal startup-recovery envelope for a durable effect intent whose
/// corresponding completion event is absent from the event log.
///
/// Keeping the original payload inside a distinct event type lets effect
/// executors retry after `EffectsEnabled` without replaying the domain event
/// into state-building subscribers a second time.
#[derive(Message, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[rtype(result = "()")]
pub struct EffectRetry {
    effect: RecoverableEffect,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnsupportedRecoverableEffect {
    event_type: String,
}

impl Display for UnsupportedRecoverableEffect {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} is not a recoverable effect", self.event_type)
    }
}

impl std::error::Error for UnsupportedRecoverableEffect {}

impl EffectRetry {
    pub fn new(effect: InterfoldEventData) -> Result<Self, UnsupportedRecoverableEffect> {
        let event_type = effect.event_type();
        let effect = effect
            .try_into()
            .map_err(|_| UnsupportedRecoverableEffect { event_type })?;
        Ok(Self { effect })
    }

    pub fn effect(&self) -> &RecoverableEffect {
        &self.effect
    }

    pub fn into_effect(self) -> InterfoldEventData {
        self.effect.into_event_data()
    }
}

impl Display for EffectRetry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "EffectRetry({})", self.effect.event_type())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{E3id, TestEvent};

    #[test]
    fn retry_envelope_accepts_only_the_closed_effect_set() {
        let supported = CommitteeFinalizeRequested {
            e3_id: E3id::new("1", 1),
        };
        assert!(EffectRetry::new(supported.into()).is_ok());
        assert!(EffectRetry::new(TestEvent::new("state", 1).into()).is_err());
    }
}
