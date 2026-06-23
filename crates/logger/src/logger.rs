// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use actix::{Actor, Addr, Context, Handler};
use e3_events::{
    prelude::Event, BusHandle, E3Stage, EventBus, EventContextAccessors, EventType, InterfoldEvent,
    InterfoldEventData, SeqState, Subscribe,
};
use std::marker::PhantomData;
use tracing::{debug, error, info, warn};

pub trait EventLogging: Event {
    fn log(&self, logger_name: &str);
}

/// Attach the standard, passive protocol-event observer to a node bus.
///
/// Keeping this wiring here prevents node assembly from depending on logger
/// actor details. The observer only subscribes; it never publishes or changes
/// event ordering.
pub fn attach_protocol_logger(name: &str, bus: &BusHandle) -> Addr<SimpleLogger<InterfoldEvent>> {
    SimpleLogger::<InterfoldEvent>::attach(name, bus.event_bus().clone())
}

/// Optional protocol-event logger.
///
/// EventStore remains the authoritative event history. This actor emits a
/// compact, structured tracing record for operators and OTLP collectors without
/// serializing multi-megabyte cryptographic payloads into application logs.
pub struct SimpleLogger<E: EventLogging> {
    name: String,
    _p: PhantomData<E>,
}

impl<E: EventLogging> SimpleLogger<E> {
    pub fn attach(name: &str, bus: Addr<EventBus<E>>) -> Addr<Self> {
        let addr = Self {
            name: name.to_owned(),
            _p: PhantomData,
        }
        .start();
        bus.do_send(Subscribe::<E>::new(
            EventType::All,
            addr.clone().recipient(),
        ));
        info!(node = %name, "protocol event logging ready");
        addr
    }
}

impl<E: EventLogging> Actor for SimpleLogger<E> {
    type Context = Context<Self>;
}

impl<E: EventLogging> Handler<E> for SimpleLogger<E> {
    type Result = ();

    fn handle(&mut self, msg: E, _: &mut Self::Context) -> Self::Result {
        msg.log(&self.name);
    }
}

#[derive(Clone, Copy)]
enum Severity {
    Error,
    Warn,
    Info,
    Debug,
}

fn severity(data: &InterfoldEventData) -> Severity {
    use InterfoldEventData as E;
    match data {
        E::InterfoldError(_)
        | E::E3Failed(_)
        | E::CommitteeFormationFailed(_)
        | E::ProofVerificationFailed(_)
        | E::SignedProofFailed(_)
        | E::ThresholdShareCollectionFailed(_)
        | E::EncryptionKeyCollectionFailed(_)
        | E::ComputeRequestError(_)
        | E::CommitmentConsistencyViolation(_) => Severity::Error,

        E::ProofFailureAccusation(_)
        | E::AccusationVote(_)
        | E::AccusationQuorumReached(_)
        | E::SlashExecuted(_)
        | E::CommitteeMemberExpelled(_)
        | E::AggregatorChanged(_) => Severity::Warn,

        E::EvmLogObserved(event) if !event.known => Severity::Warn,

        E::E3Requested(_)
        | E::CommitteeRequested(_)
        | E::TicketGenerated(_)
        | E::TicketSubmitted(_)
        | E::CommitteeFinalizeRequested(_)
        | E::CommitteeFinalized(_)
        | E::CommitteePublished(_)
        | E::E3StageChanged(_)
        | E::CiphertextOutputPublished(_)
        | E::PlaintextOutputPublished(_)
        | E::E3RequestComplete(_)
        | E::PublicKeyAggregated(_)
        | E::PlaintextAggregated(_)
        | E::KeyshareCreated(_)
        | E::DecryptionshareCreated(_)
        | E::CiphernodeAdded(_)
        | E::CiphernodeRemoved(_)
        | E::TicketBalanceUpdated(_)
        | E::OperatorActivationChanged(_) => Severity::Info,

        _ => Severity::Debug,
    }
}

fn stage(data: &InterfoldEventData) -> &'static str {
    use InterfoldEventData as E;
    match data {
        E::E3Requested(_) => "request",
        E::CommitteeRequested(_)
        | E::CiphernodeSelected(_)
        | E::TicketGenerated(_)
        | E::TicketSubmitted(_)
        | E::CommitteeFinalizeRequested(_)
        | E::CommitteeFinalized(_)
        | E::CommitteeFormationFailed(_)
        | E::CommitteeMemberExpelled(_)
        | E::CommitteeViabilityUpdated(_) => "committee",
        E::EncryptionKeyPending(_)
        | E::EncryptionKeyCreated(_)
        | E::EncryptionKeyReceived(_)
        | E::EncryptionKeyCollectionFailed(_) => "dkg_setup",
        E::ThresholdSharePending(_)
        | E::ThresholdShareCreated(_)
        | E::ThresholdShareCollectionFailed(_)
        | E::DkgProofSigned(_)
        | E::ShareVerificationDispatched(_)
        | E::ShareVerificationComplete(_)
        | E::DecryptionKeyShared(_)
        | E::DKGInnerProofReady(_)
        | E::DKGRecursiveAggregationComplete(_)
        | E::CommitmentConsistencyCheckRequested(_)
        | E::CommitmentConsistencyCheckComplete(_)
        | E::CommitmentConsistencyViolation(_) => "dkg_shares",
        E::KeyshareCreated(_)
        | E::PkGenerationProofSigned(_)
        | E::PkAggregationProofPending(_)
        | E::PkAggregationProofSigned(_)
        | E::PublicKeyAggregated(_)
        | E::CommitteePublished(_) => "key_publication",
        E::InputPublished(_)
        | E::ComputeRequest(_)
        | E::ComputeResponse(_)
        | E::ComputeRequestError(_)
        | E::CiphertextOutputPublished(_) => "computation",
        E::DecryptionShareProofsPending(_)
        | E::DecryptionShareProofSigned(_)
        | E::ShareDecryptionProofPending(_)
        | E::DecryptionshareCreated(_)
        | E::AggregationProofPending(_)
        | E::AggregationProofSigned(_)
        | E::PlaintextAggregated(_) => "decryption",
        E::PlaintextOutputPublished(_)
        | E::RewardsDistributed(_)
        | E::RewardCredited(_)
        | E::RewardClaimed(_)
        | E::E3RequestComplete(_)
        | E::CommitteeActivationChanged(_) => "settlement",
        E::E3StageChanged(event) => lifecycle_stage(&event.new_stage),
        E::E3Failed(event) => failure_stage(&event.failed_at_stage),
        E::ProofVerificationFailed(event) => proof_stage(&format!("{:?}", event.proof_type)),
        E::ProofVerificationPassed(event) => proof_stage(&format!("{:?}", event.proof_type)),
        E::SignedProofFailed(event) => proof_stage(&format!("{:?}", event.proof_type)),
        E::ProofFailureAccusation(_)
        | E::AccusationVote(_)
        | E::AccusationQuorumReached(_)
        | E::SlashExecuted(_) => "dkg_shares",
        E::EvmLogObserved(event) => match event.event_name.as_str() {
            "CommitteeFormed" | "CommitteeFinalized" => "committee",
            "TreasuryCredited"
            | "TreasuryClaimed"
            | "SlashedFundsEscrowed"
            | "SlashedFundsEscrowedToRefund"
            | "RoutingFailed"
            | "E3FailureProcessed"
            | "SlashProposed" => "settlement",
            _ => "node",
        },
        _ => "node",
    }
}

fn lifecycle_stage(stage: &E3Stage) -> &'static str {
    match stage {
        E3Stage::None | E3Stage::Requested => "request",
        E3Stage::CommitteeFinalized => "committee",
        E3Stage::KeyPublished => "key_publication",
        E3Stage::CiphertextReady => "computation",
        E3Stage::Complete | E3Stage::Failed => "settlement",
    }
}

fn failure_stage(stage: &E3Stage) -> &'static str {
    match stage {
        E3Stage::None | E3Stage::Requested => "request",
        E3Stage::CommitteeFinalized => "dkg_shares",
        E3Stage::KeyPublished => "computation",
        E3Stage::CiphertextReady => "decryption",
        E3Stage::Complete | E3Stage::Failed => "settlement",
    }
}

fn proof_stage(proof: &str) -> &'static str {
    if proof.contains("C6") || proof.contains("C7") || proof.contains("Decryption") {
        "decryption"
    } else if proof.contains("C5") || proof.contains("Pk") {
        "key_publication"
    } else {
        "dkg_shares"
    }
}

fn compact_error(value: &str) -> String {
    const MAX_CHARS: usize = 600;
    let mut chars = value.chars();
    let compact: String = chars.by_ref().take(MAX_CHARS).collect();
    if chars.next().is_some() {
        format!("{compact}…")
    } else {
        compact
    }
}

impl<S: SeqState> EventLogging for InterfoldEvent<S> {
    fn log(&self, logger_name: &str) {
        let data = self.get_data();
        let event_type = match data {
            InterfoldEventData::EvmLogObserved(event) => {
                format!("{}::{}", event.contract, event.event_name)
            }
            _ => self.event_type(),
        };
        let e3_id = self
            .get_e3_id()
            .map(|id| id.to_string())
            .unwrap_or_default();
        let error_message = match data {
            InterfoldEventData::InterfoldError(error) => compact_error(&error.message),
            _ => String::new(),
        };
        let stage = stage(data);
        let observation = matches!(
            data,
            InterfoldEventData::EvmLogObserved(_)
                | InterfoldEventData::InputPublished(_)
                | InterfoldEventData::PlaintextOutputPublished(_)
                | InterfoldEventData::RewardsDistributed(_)
                | InterfoldEventData::RewardCredited(_)
                | InterfoldEventData::RewardClaimed(_)
                | InterfoldEventData::CommitteeFormationFailed(_)
                | InterfoldEventData::CommitteeActivationChanged(_)
                | InterfoldEventData::CommitteeViabilityUpdated(_)
        );

        macro_rules! emit {
            ($macro:ident) => {
                $macro!(
                    node = %logger_name,
                    event_type = %event_type,
                    e3_id = %e3_id,
                    stage,
                    observation,
                    event_id = %self.id(),
                    causation_id = %self.causation_id(),
                    origin_id = %self.origin_id(),
                    source = ?self.source(),
                    block = ?self.block(),
                    error = %error_message,
                    "protocol event"
                )
            };
        }

        match severity(data) {
            Severity::Error => emit!(error),
            Severity::Warn => emit!(warn),
            Severity::Info => emit!(info),
            Severity::Debug => emit!(debug),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lifecycle_and_failure_stages_are_explicit() {
        assert_eq!(lifecycle_stage(&E3Stage::CommitteeFinalized), "committee");
        assert_eq!(failure_stage(&E3Stage::CommitteeFinalized), "dkg_shares");
        assert_eq!(failure_stage(&E3Stage::CiphertextReady), "decryption");
        assert_eq!(proof_stage("C5PkAggregation"), "key_publication");
        assert_eq!(proof_stage("C7DecryptionAggregation"), "decryption");
    }
}
