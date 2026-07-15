// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Durable open-loop detection for startup effect recovery.

use crate::replay_spool::{query_page, REPLAY_QUERY_PAGE_SIZE};
use actix::Recipient;
use anyhow::{bail, Context, Result};
use e3_events::{
    AggregateId, ComputeRequestKind, CorrelationId, DocumentMeta, E3Stage, E3id, Event,
    EventContextAccessors, EventContextSeq, EventSource, EventStoreQueryBy, InterfoldEvent,
    InterfoldEventData, SeqAgg, TicketId,
};
use e3_utils::ArcBytes;
use std::collections::HashMap;

const MAX_OPEN_EFFECTS: usize = 50_000;
const MAX_OPEN_EFFECT_BYTES: usize = 128 * 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
enum EffectKey {
    Compute {
        e3_id: E3id,
        request: Box<ComputeRequestKind>,
    },
    Ticket {
        e3_id: E3id,
        node: String,
        ticket_id: u64,
    },
    FinalizeCommittee(E3id),
    PublishCommittee(E3id),
    PublishPlaintext(E3id),
    ProcessFailure(E3id),
    PublishDocument {
        meta: DocumentMeta,
        value: ArcBytes,
    },
    Slash {
        e3_id: E3id,
        operator: String,
        reason: [u8; 32],
    },
}

impl EffectKey {
    fn e3_id(&self) -> &E3id {
        match self {
            Self::Compute { e3_id, .. }
            | Self::Ticket { e3_id, .. }
            | Self::Slash { e3_id, .. }
            | Self::FinalizeCommittee(e3_id)
            | Self::PublishCommittee(e3_id)
            | Self::PublishPlaintext(e3_id)
            | Self::ProcessFailure(e3_id) => e3_id,
            Self::PublishDocument { meta, .. } => &meta.e3_id,
        }
    }
}

struct OpenIntent {
    timestamp: u128,
    bytes: usize,
    payload: InterfoldEventData,
}

#[derive(Default)]
struct OpenEffectDetector {
    intents: HashMap<EffectKey, OpenIntent>,
    compute_requests: HashMap<(E3id, CorrelationId), EffectKey>,
    open_bytes: usize,
}

impl OpenEffectDetector {
    fn observe(&mut self, event: &InterfoldEvent) -> Result<()> {
        let timestamp = event.ts();
        match event.get_data() {
            // Only the node that originated an effect owns its retry. Canonical EVM failure
            // transitions are the exception: every configured chain writer already consumes them.
            InterfoldEventData::ComputeRequest(data) if event.source() == EventSource::Local => {
                let key = EffectKey::Compute {
                    e3_id: data.e3_id.clone(),
                    request: Box::new(data.request.clone()),
                };
                self.compute_requests
                    .insert((data.e3_id.clone(), data.correlation_id), key.clone());
                if self.compute_requests.len() > MAX_OPEN_EFFECTS {
                    bail!(
                        "open effect recovery exceeds compute-correlation bound of {}",
                        MAX_OPEN_EFFECTS
                    );
                }
                self.insert(key, timestamp, event.get_data().clone())?;
            }
            InterfoldEventData::TicketGenerated(data) if event.source() == EventSource::Local => {
                let TicketId::Score(ticket_id) = data.ticket_id;
                self.insert(
                    EffectKey::Ticket {
                        e3_id: data.e3_id.clone(),
                        node: normalize_node(&data.node),
                        ticket_id,
                    },
                    timestamp,
                    event.get_data().clone(),
                )?;
            }
            InterfoldEventData::CommitteeFinalizeRequested(data)
                if event.source() == EventSource::Local =>
            {
                self.insert(
                    EffectKey::FinalizeCommittee(data.e3_id.clone()),
                    timestamp,
                    event.get_data().clone(),
                )?;
            }
            InterfoldEventData::PublicKeyAggregated(data)
                if event.source() == EventSource::Local =>
            {
                self.insert(
                    EffectKey::PublishCommittee(data.e3_id.clone()),
                    timestamp,
                    event.get_data().clone(),
                )?;
            }
            InterfoldEventData::PlaintextAggregated(data)
                if event.source() == EventSource::Local =>
            {
                self.insert(
                    EffectKey::PublishPlaintext(data.e3_id.clone()),
                    timestamp,
                    event.get_data().clone(),
                )?;
            }
            InterfoldEventData::PublishDocumentRequested(data)
                if event.source() == EventSource::Local =>
            {
                self.insert(
                    EffectKey::PublishDocument {
                        meta: data.meta.clone(),
                        value: data.value.clone(),
                    },
                    timestamp,
                    event.get_data().clone(),
                )?;
            }
            InterfoldEventData::AccusationQuorumReached(data)
                if event.source() == EventSource::Local
                    && matches!(
                        data.outcome,
                        e3_events::AccusationOutcome::AccusedFaulted
                            | e3_events::AccusationOutcome::Equivocation
                    )
                    && !data.votes_for.is_empty()
                    && !data.evidence.is_empty() =>
            {
                self.insert(
                    EffectKey::Slash {
                        e3_id: data.e3_id.clone(),
                        operator: normalize_node(&data.accused.to_string()),
                        reason: data.proof_type.onchain_reason(),
                    },
                    timestamp,
                    event.get_data().clone(),
                )?;
            }
            InterfoldEventData::E3StageChanged(data) if data.new_stage == E3Stage::Failed => {
                self.close_e3(&data.e3_id, true);
                self.insert(
                    EffectKey::ProcessFailure(data.e3_id.clone()),
                    timestamp,
                    event.get_data().clone(),
                )?;
            }

            InterfoldEventData::ComputeResponse(data) => {
                self.complete_compute(&data.e3_id, data.correlation_id)
            }
            InterfoldEventData::ComputeRequestError(data) => {
                let request = data.request();
                self.complete_compute(&request.e3_id, request.correlation_id);
            }
            InterfoldEventData::TicketSubmitted(data) => self.remove(&EffectKey::Ticket {
                e3_id: data.e3_id.clone(),
                node: normalize_node(&data.node),
                ticket_id: data.ticket_id,
            }),
            InterfoldEventData::CommitteeFinalized(data) => {
                self.remove(&EffectKey::FinalizeCommittee(data.e3_id.clone()));
                self.close_tickets(&data.e3_id);
            }
            InterfoldEventData::CommitteeFormationFailed(data) => {
                self.remove(&EffectKey::FinalizeCommittee(data.e3_id.clone()));
                self.close_tickets(&data.e3_id);
            }
            InterfoldEventData::CommitteePublished(data) => {
                self.remove(&EffectKey::PublishCommittee(data.e3_id.clone()));
            }
            InterfoldEventData::PlaintextOutputPublished(data) => {
                self.remove(&EffectKey::PublishPlaintext(data.e3_id.clone()));
            }
            InterfoldEventData::DocumentReceived(data) => {
                self.remove(&EffectKey::PublishDocument {
                    meta: data.meta.clone(),
                    value: data.value.clone(),
                });
            }
            InterfoldEventData::EvmLogObserved(data) => self.observe_evm_completion(data),
            InterfoldEventData::E3RequestComplete(data) => self.close_e3(&data.e3_id, false),
            InterfoldEventData::E3Failed(data) => self.close_e3(&data.e3_id, true),
            InterfoldEventData::E3StageChanged(data) if data.new_stage == E3Stage::Complete => {
                self.close_e3(&data.e3_id, false);
            }
            _ => {}
        }
        Ok(())
    }

    fn insert(
        &mut self,
        key: EffectKey,
        timestamp: u128,
        payload: InterfoldEventData,
    ) -> Result<()> {
        let bytes = bincode::serialized_size(&payload)
            .context("failed to size recoverable effect intent")?
            .try_into()
            .context("recoverable effect size does not fit usize")?;
        if let Some(previous) = self.intents.remove(&key) {
            self.open_bytes = self.open_bytes.saturating_sub(previous.bytes);
        }
        self.open_bytes = self
            .open_bytes
            .checked_add(bytes)
            .context("open effect byte count overflow")?;
        self.intents.insert(
            key,
            OpenIntent {
                timestamp,
                bytes,
                payload,
            },
        );
        if self.intents.len() > MAX_OPEN_EFFECTS || self.open_bytes > MAX_OPEN_EFFECT_BYTES {
            bail!(
                "open effect recovery exceeds startup bounds: {} intents / {} bytes (limits: {} / {})",
                self.intents.len(),
                self.open_bytes,
                MAX_OPEN_EFFECTS,
                MAX_OPEN_EFFECT_BYTES
            );
        }
        Ok(())
    }

    fn remove(&mut self, key: &EffectKey) {
        if let Some(intent) = self.intents.remove(key) {
            self.open_bytes = self.open_bytes.saturating_sub(intent.bytes);
        }
        if matches!(key, EffectKey::Compute { .. }) {
            self.compute_requests.retain(|_, mapped| mapped != key);
        }
    }

    fn complete_compute(&mut self, e3_id: &E3id, correlation_id: CorrelationId) {
        if let Some(key) = self
            .compute_requests
            .remove(&(e3_id.clone(), correlation_id))
        {
            self.remove(&key);
        }
    }

    fn close_tickets(&mut self, e3_id: &E3id) {
        self.retain(|key| !matches!(key, EffectKey::Ticket { e3_id: id, .. } if id == e3_id));
    }

    fn close_e3(&mut self, e3_id: &E3id, preserve_failure_processing: bool) {
        self.retain(|key| {
            key.e3_id() != e3_id
                || (preserve_failure_processing
                    && matches!(key, EffectKey::ProcessFailure(_) | EffectKey::Slash { .. }))
        });
        self.compute_requests
            .retain(|(request_e3_id, _), _| request_e3_id != e3_id);
    }

    fn retain(&mut self, keep: impl Fn(&EffectKey) -> bool) {
        let mut removed_bytes = 0usize;
        self.intents.retain(|key, intent| {
            let retain = keep(key);
            if !retain {
                removed_bytes = removed_bytes.saturating_add(intent.bytes);
            }
            retain
        });
        self.open_bytes = self.open_bytes.saturating_sub(removed_bytes);
    }

    fn observe_evm_completion(&mut self, event: &e3_events::EvmLogObserved) {
        let Some(e3_id) = event.e3_id.clone() else {
            return;
        };
        if event.contract == "Interfold" && event.event_name == "E3FailureProcessed" {
            self.remove(&EffectKey::ProcessFailure(e3_id));
            return;
        }
        if event.contract != "SlashingManager" || event.event_name != "SlashProposed" {
            return;
        }
        let Some(operator) = event.topics.get(3).and_then(|topic| topic_address(topic)) else {
            return;
        };
        let data = event.data.extract_bytes();
        let Some(reason) = data.get(..32).and_then(|bytes| bytes.try_into().ok()) else {
            return;
        };
        self.remove(&EffectKey::Slash {
            e3_id,
            operator,
            reason,
        });
    }

    fn finish(self) -> Vec<InterfoldEventData> {
        let mut open: Vec<_> = self.intents.into_values().collect();
        open.sort_by_key(|intent| intent.timestamp);
        open.into_iter().map(|intent| intent.payload).collect()
    }
}

fn normalize_node(node: &str) -> String {
    node.to_ascii_lowercase()
}

fn topic_address(topic: &str) -> Option<String> {
    let hex = topic.strip_prefix("0x").unwrap_or(topic);
    if hex.len() != 64 || !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    Some(format!("0x{}", &hex[24..]).to_ascii_lowercase())
}

/// Scan the complete durable log in bounded pages and return only effect intents
/// for which no matching completion or terminal lifecycle event exists.
pub(crate) async fn detect_open_effects(
    eventstore: &Recipient<EventStoreQueryBy<SeqAgg>>,
    mut aggregates: Vec<AggregateId>,
) -> Result<Vec<InterfoldEventData>> {
    aggregates.sort_unstable();
    aggregates.dedup();
    let mut detector = OpenEffectDetector::default();

    for aggregate_id in aggregates {
        let mut cursor = 1u64;
        loop {
            let page = query_page(eventstore, aggregate_id, cursor).await?;
            if page.is_empty() {
                break;
            }
            if page.len() > REPLAY_QUERY_PAGE_SIZE {
                bail!(
                    "EventStore returned {} effect-scan events for aggregate {}, exceeding page limit {}",
                    page.len(),
                    aggregate_id,
                    REPLAY_QUERY_PAGE_SIZE
                );
            }

            let mut expected_sequence = cursor;
            for event in &page {
                if event.aggregate_id() != aggregate_id || event.seq() != expected_sequence {
                    bail!(
                        "EventStore effect scan lost continuity for aggregate {}: expected sequence {}, got aggregate {} sequence {}",
                        aggregate_id,
                        expected_sequence,
                        event.aggregate_id(),
                        event.seq()
                    );
                }
                detector.observe(event)?;
                expected_sequence = expected_sequence
                    .checked_add(1)
                    .context("EventStore effect-scan sequence overflow")?;
            }
            cursor = expected_sequence;
            if page.len() < REPLAY_QUERY_PAGE_SIZE {
                break;
            }
        }
    }

    Ok(detector.finish())
}

#[cfg(test)]
mod tests {
    use super::*;
    use e3_events::{
        CommitteeFinalizeRequested, CommitteeFinalized, E3StageChanged,
        EventConstructorWithTimestamp, TicketGenerated, TicketSubmitted, Unsequenced,
    };

    fn event(data: InterfoldEventData, timestamp: u128, sequence: u64) -> InterfoldEvent {
        InterfoldEvent::<Unsequenced>::new_with_timestamp(
            data,
            None,
            timestamp,
            None,
            EventSource::Local,
        )
        .into_sequenced(sequence)
    }

    #[test]
    fn detects_only_the_unmatched_blockchain_write() {
        let e3_id = E3id::new("7", 1);
        let mut detector = OpenEffectDetector::default();
        detector
            .observe(&event(
                TicketGenerated {
                    e3_id: e3_id.clone(),
                    ticket_id: TicketId::Score(11),
                    node: "0xAAA".to_owned(),
                    party_index: None,
                }
                .into(),
                1,
                1,
            ))
            .unwrap();
        detector
            .observe(&event(
                CommitteeFinalizeRequested {
                    e3_id: e3_id.clone(),
                }
                .into(),
                2,
                2,
            ))
            .unwrap();
        detector
            .observe(&event(
                TicketSubmitted {
                    e3_id,
                    node: "0xaaa".to_owned(),
                    ticket_id: 11,
                    score: "11".to_owned(),
                    chain_id: 1,
                }
                .into(),
                3,
                3,
            ))
            .unwrap();

        let open = detector.finish();
        assert_eq!(open.len(), 1);
        assert!(matches!(
            open[0],
            InterfoldEventData::CommitteeFinalizeRequested(_)
        ));
    }

    #[test]
    fn committee_completion_closes_finalize_and_ticket_effects() {
        let e3_id = E3id::new("8", 1);
        let mut detector = OpenEffectDetector::default();
        detector
            .observe(&event(
                TicketGenerated {
                    e3_id: e3_id.clone(),
                    ticket_id: TicketId::Score(1),
                    node: "0x01".to_owned(),
                    party_index: None,
                }
                .into(),
                1,
                1,
            ))
            .unwrap();
        detector
            .observe(&event(
                CommitteeFinalizeRequested {
                    e3_id: e3_id.clone(),
                }
                .into(),
                2,
                2,
            ))
            .unwrap();
        detector
            .observe(&event(
                CommitteeFinalized {
                    e3_id,
                    committee: vec![],
                    scores: vec![],
                    chain_id: 1,
                }
                .into(),
                3,
                3,
            ))
            .unwrap();

        assert!(detector.finish().is_empty());
    }

    #[test]
    fn failed_stage_remains_open_until_failure_processing_is_observed() {
        let e3_id = E3id::new("9", 1);
        let mut detector = OpenEffectDetector::default();
        detector
            .observe(&event(
                E3StageChanged {
                    e3_id: e3_id.clone(),
                    previous_stage: E3Stage::Requested,
                    new_stage: E3Stage::Failed,
                }
                .into(),
                1,
                1,
            ))
            .unwrap();
        assert_eq!(detector.intents.len(), 1);

        detector
            .observe(&event(
                e3_events::EvmLogObserved {
                    contract: "Interfold".to_owned(),
                    chain_id: 1,
                    e3_id: Some(e3_id),
                    event_name: "E3FailureProcessed".to_owned(),
                    signature: None,
                    known: true,
                    topics: vec![],
                    data: ArcBytes::from_bytes(&[]),
                }
                .into(),
                2,
                2,
            ))
            .unwrap();
        assert!(detector.finish().is_empty());
    }
}
