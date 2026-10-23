// SPDX-License-Identifier: LGPL-3.0-only

//! Rebuild unresolved C0 inputs from the event log, including the snapshotted prefix.

use super::{dkg_has_ended, validate_received_key};
use actix::Recipient;
use anyhow::{ensure, Context, Result};
use e3_committee::CiphernodesCommitteeSize;
use e3_events::{
    AggregateId, Committee, CorrelationId, E3id, EncryptionKeyReceived, EventContextAccessors,
    EventContextSeq, EventSource, EventStoreQueryBy, EventStoreQueryResponse, InterfoldEvent,
    InterfoldEventData, ProofType, SeqAgg, TypedEvent,
};
use e3_request::E3Meta;
use e3_utils::actix::channel;
use std::collections::{HashMap, HashSet};
use std::time::Duration;

async fn read_page(
    eventstore: &Recipient<EventStoreQueryBy<SeqAgg>>,
    aggregate: AggregateId,
    cursor: u64,
    limit: u64,
) -> Result<(Vec<InterfoldEvent>, u64)> {
    let (recipient, response) = channel::oneshot::<EventStoreQueryResponse>();
    tokio::time::timeout(Duration::from_secs(60), async {
        eventstore
            .send(
                EventStoreQueryBy::<SeqAgg>::new(
                    CorrelationId::new(),
                    [(aggregate, cursor)].into(),
                    recipient,
                )
                .with_limit(limit)
                .with_max_bytes(16 * 1024 * 1024),
            )
            .await?;
        let response = response.await?;
        let head = response.log_head();
        let events = response.into_events()?;
        Ok((
            events,
            head.context("C0 recovery event-store log head is missing")?,
        ))
    })
    .await
    .context("C0 recovery event-store query timed out")?
}

pub(crate) async fn recover_pending_verifications(
    eventstore: &Recipient<EventStoreQueryBy<SeqAgg>>,
    aggregates: &[AggregateId],
    active_e3s: &HashSet<E3id>,
    committees: &HashMap<E3id, Committee>,
    metadata: &HashMap<E3id, E3Meta>,
) -> Result<Vec<TypedEvent<EncryptionKeyReceived>>> {
    let mut pending: HashMap<(E3id, u64), TypedEvent<EncryptionKeyReceived>> = HashMap::new();
    let mut closed = HashSet::new();
    if active_e3s.is_empty() {
        return Ok(Vec::new());
    }
    for aggregate in aggregates.iter().copied() {
        let mut cursor = 1u64;
        let mut limit = 1_024;
        loop {
            let (events, head) = read_page(eventstore, aggregate, cursor, limit).await?;
            if events.is_empty() {
                if cursor > head {
                    break;
                }
                // Filtering can empty a count- or byte-limited page before the log ends.
                // Probe one physical record at a time so neither limit can hide a later input.
                if limit != 1 {
                    limit = 1;
                    continue;
                }
                cursor = cursor
                    .checked_add(1)
                    .context("C0 recovery sequence overflow")?;
                continue;
            }
            limit = 1_024;
            for event in events {
                // A one-event read is empty when the router quarantines that legacy record.
                // Check each skipped sequence so a later C0 input remains recoverable without
                // accepting a missing or out-of-order event.
                while cursor < event.seq() {
                    ensure!(
                        read_page(eventstore, aggregate, cursor, 1)
                            .await?
                            .0
                            .is_empty(),
                        "C0 recovery event-store sequence gap"
                    );
                    cursor = cursor
                        .checked_add(1)
                        .context("C0 recovery sequence overflow")?;
                }
                ensure!(
                    event.aggregate_id() == aggregate && event.seq() == cursor,
                    "C0 recovery event-store sequence gap"
                );
                cursor = cursor
                    .checked_add(1)
                    .context("C0 recovery sequence overflow")?;
                let source = event.source();
                let (data, ec) = event.into_components();
                match data {
                    InterfoldEventData::EncryptionKeyReceived(input)
                        if active_e3s.contains(&input.e3_id) && !closed.contains(&input.e3_id) =>
                    {
                        let key = (input.e3_id.clone(), input.key.party_id);
                        if pending.contains_key(&key) {
                            continue;
                        }
                        let Some(meta) = metadata.get(&input.e3_id) else {
                            continue;
                        };
                        let Some(signer) = committees
                            .get(&input.e3_id)
                            .and_then(|committee| {
                                committee
                                    .members()
                                    .get(usize::try_from(input.key.party_id).ok()?)
                            })
                            .and_then(|address| address.parse().ok())
                        else {
                            continue;
                        };
                        if CiphernodesCommitteeSize::from_threshold(
                            meta.threshold_m,
                            meta.threshold_n,
                        )
                        .is_ok()
                            && validate_received_key(&input, &signer, meta.params_preset).is_ok()
                        {
                            pending.insert(key, TypedEvent::new(input, ec));
                        }
                    }
                    InterfoldEventData::EncryptionKeyCreated(output)
                        if source == EventSource::Local && output.external =>
                    {
                        let key = (output.e3_id, output.key.party_id);
                        if pending
                            .get(&key)
                            .is_some_and(|input| input.key == output.key)
                        {
                            pending.remove(&key);
                        }
                    }
                    InterfoldEventData::ProofVerificationFailed(output)
                        if source == EventSource::Local
                            && output.proof_type == ProofType::C0PkBfv =>
                    {
                        let key = (output.e3_id, output.accused_party_id);
                        if pending.get(&key).is_some_and(|input| {
                            input.key.signed_payload.as_ref() == Some(&output.signed_payload)
                        }) {
                            pending.remove(&key);
                        }
                    }
                    InterfoldEventData::E3RequestComplete(output)
                        if active_e3s.contains(&output.e3_id) =>
                    {
                        pending.retain(|(e3_id, _), _| e3_id != &output.e3_id);
                        closed.insert(output.e3_id);
                    }
                    InterfoldEventData::E3StageChanged(output)
                        if source == EventSource::Evm
                            && active_e3s.contains(&output.e3_id)
                            && dkg_has_ended(&output.new_stage) =>
                    {
                        pending.retain(|(e3_id, _), _| e3_id != &output.e3_id);
                        closed.insert(output.e3_id);
                    }
                    _ => {}
                }
            }
        }
    }
    let mut inputs: Vec<_> = pending.into_values().collect();
    inputs.sort_by_key(|input| (input.aggregate_id(), input.seq()));
    Ok(inputs)
}

#[cfg(test)]
#[path = "recovery_sequence_tests.rs"]
mod tests;
