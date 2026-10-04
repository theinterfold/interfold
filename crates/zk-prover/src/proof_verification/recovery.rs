// SPDX-License-Identifier: LGPL-3.0-only

//! Rebuild unresolved C0 inputs from the event log, including the snapshotted prefix.

use super::{dkg_has_ended, validate_received_key};
use actix::Recipient;
use anyhow::{ensure, Context, Result};
use e3_events::{
    AggregateId, Committee, CorrelationId, E3id, EncryptionKeyReceived, EventContextAccessors,
    EventContextSeq, EventSource, EventStoreQueryBy, EventStoreQueryResponse, InterfoldEventData,
    ProofType, SeqAgg, TypedEvent,
};
use e3_request::E3Meta;
use e3_utils::actix::channel;
use e3_zk_helpers::CiphernodesCommitteeSize;
use std::collections::{HashMap, HashSet};
use std::time::Duration;

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
        loop {
            let (recipient, response) = channel::oneshot::<EventStoreQueryResponse>();
            let events = tokio::time::timeout(Duration::from_secs(60), async {
                eventstore
                    .send(
                        EventStoreQueryBy::<SeqAgg>::new(
                            CorrelationId::new(),
                            [(aggregate, cursor)].into(),
                            recipient,
                        )
                        .with_limit(1_024)
                        .with_max_bytes(16 * 1024 * 1024),
                    )
                    .await?;
                response.await?.into_events()
            })
            .await
            .context("C0 recovery event-store query timed out")??;
            if events.is_empty() {
                break;
            }
            for event in events {
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
