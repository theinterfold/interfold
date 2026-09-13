// SPDX-License-Identifier: LGPL-3.0-only

//! Rebuild in-flight DHT publication and receive state from the durable event log.

use super::{
    ContentHash, RecoveredDocumentState, MAX_BUFFERED_NOTIFICATIONS, MAX_PENDING_PUBLICATIONS,
    MAX_PENDING_PUBLICATION_BYTES, MAX_RECEIVED_DOCUMENTS,
};
use actix::Recipient;
use anyhow::{ensure, Context, Result};
use e3_events::{
    AggregateId, CorrelationId, E3Stage, E3id, Event, EventContextAccessors, EventContextSeq,
    EventSource, EventStoreQueryBy, EventStoreQueryResponse, InterfoldEventData, SeqAgg,
};
use e3_utils::actix::channel;
use std::collections::{HashMap, HashSet, VecDeque};

pub async fn recover_document_state(
    eventstore: &Recipient<EventStoreQueryBy<SeqAgg>>,
    aggregates: &[AggregateId],
    interested_e3s: &HashSet<E3id>,
) -> Result<RecoveredDocumentState> {
    let mut publications = HashMap::new();
    let mut received = HashSet::new();
    let mut closed = VecDeque::new();
    let mut publication_bytes = 0usize;

    for aggregate_id in aggregates.iter().copied() {
        let mut cursor = 1u64;
        loop {
            let (recipient, response) = channel::oneshot::<EventStoreQueryResponse>();
            eventstore
                .send(
                    EventStoreQueryBy::<SeqAgg>::new(
                        CorrelationId::new(),
                        HashMap::from([(aggregate_id, cursor)]),
                        recipient,
                    )
                    .with_limit(1),
                )
                .await
                .context("document recovery event-store router stopped")?;
            let mut events = response
                .await
                .context("document recovery event-store query had no response")?
                .into_events()?;
            let Some(event) = events.pop() else {
                break;
            };
            ensure!(
                event.aggregate_id() == aggregate_id && event.seq() == cursor,
                "document recovery event-store sequence gap"
            );
            cursor = cursor
                .checked_add(1)
                .context("document recovery sequence overflow")?;

            match event.get_data() {
                InterfoldEventData::PublishDocumentRequested(request)
                    if !closed.contains(&request.meta.e3_id)
                        && request.meta.expires_at > chrono::Utc::now() =>
                {
                    let id = (
                        request.meta.e3_id.clone(),
                        ContentHash::from_content(&request.value),
                    );
                    if !publications.contains_key(&id) {
                        publication_bytes = publication_bytes
                            .checked_add(request.value.size())
                            .context("document publication outbox size overflow")?;
                        ensure!(
                            publications.len() < MAX_PENDING_PUBLICATIONS
                                && publication_bytes <= MAX_PENDING_PUBLICATION_BYTES,
                            "document publication outbox exceeds recovery limits"
                        );
                        publications.insert(id, request.clone());
                    }
                }
                InterfoldEventData::DocumentReceived(document)
                    if interested_e3s.contains(&document.meta.e3_id)
                        && !closed.contains(&document.meta.e3_id) =>
                {
                    received.insert((
                        document.meta.e3_id.clone(),
                        ContentHash::from_content(&document.value),
                    ));
                    ensure!(
                        received.len() <= MAX_RECEIVED_DOCUMENTS,
                        "received-document cache exceeds recovery limit"
                    );
                }
                InterfoldEventData::E3StageChanged(change)
                    if event.source() == EventSource::Evm
                        && matches!(
                            change.new_stage,
                            E3Stage::KeyPublished
                                | E3Stage::CiphertextReady
                                | E3Stage::Complete
                                | E3Stage::Failed
                        ) =>
                {
                    if !closed.contains(&change.e3_id) {
                        if closed.len() == MAX_BUFFERED_NOTIFICATIONS {
                            closed.pop_front();
                        }
                        closed.push_back(change.e3_id.clone());
                    }
                    publications.retain(|(id, _), request| {
                        if id == &change.e3_id {
                            publication_bytes =
                                publication_bytes.saturating_sub(request.value.size());
                            false
                        } else {
                            true
                        }
                    });
                    received.retain(|(id, _)| id != &change.e3_id);
                }
                _ => {}
            }
        }
    }

    Ok(RecoveredDocumentState {
        publications: publications.into_values().collect(),
        received,
        closed_e3s: closed,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::event_conversion::ReceivableDocument;
    use e3_ciphernode_builder::EventSystem;
    use e3_events::{
        AggregateConfig, DecryptionKeyShared, DocumentKind, DocumentMeta, DocumentReceived,
        E3StageChanged, EventConstructorWithTimestamp, InterfoldEvent, Proof, ProofPayload,
        ProofType, PublishDocumentRequested, SignedProofPayload, StoreEventRequested,
        StoreEventResponse, Unsequenced,
    };
    use e3_utils::ArcBytes;
    use std::time::Duration;

    async fn append(
        system: &EventSystem,
        data: InterfoldEventData,
        ts: u128,
        source: EventSource,
    ) -> Result<()> {
        let event = InterfoldEvent::<Unsequenced>::new_with_timestamp(data, None, ts, None, source);
        let (recipient, response) = channel::oneshot::<StoreEventResponse>();
        system
            .eventstore_router()?
            .send(StoreEventRequested::new(event, recipient))
            .await?;
        response.await?;
        Ok(())
    }

    #[actix::test]
    async fn durable_document_outbox_and_receipts_follow_chain_lifecycle() -> Result<()> {
        let aggregate = AggregateId::new(1);
        let system =
            EventSystem::new()
                .with_fresh_bus()
                .with_aggregate_config(AggregateConfig::new(HashMap::from([(
                    aggregate,
                    Duration::ZERO,
                )])));
        let e3_id = E3id::new("7", 1);
        let value = ArcBytes::from_bytes(b"durable document");
        let request = PublishDocumentRequested {
            meta: DocumentMeta::new(
                e3_id.clone(),
                DocumentKind::TrBFV,
                vec![],
                Some(chrono::Utc::now() + chrono::Duration::hours(1)),
            ),
            value: value.clone(),
        };
        append(&system, request.clone().into(), 1, EventSource::Local).await?;
        append(
            &system,
            DocumentReceived {
                meta: request.meta.clone(),
                value: value.clone(),
            }
            .into(),
            2,
            EventSource::Net,
        )
        .await?;

        let reader = system.eventstore_reader()?.seq();
        let interests = HashSet::from([e3_id.clone()]);
        let recovered = recover_document_state(&reader, &[aggregate], &interests).await?;
        assert_eq!(recovered.publications, vec![request.clone()]);
        assert!(recovered
            .received
            .contains(&(e3_id.clone(), ContentHash::from_content(&value))));

        append(
            &system,
            E3StageChanged {
                e3_id: e3_id.clone(),
                previous_stage: E3Stage::CommitteeFinalized,
                new_stage: E3Stage::KeyPublished,
            }
            .into(),
            3,
            EventSource::Evm,
        )
        .await?;
        let recovered = recover_document_state(&reader, &[aggregate], &interests).await?;
        assert!(recovered.publications.is_empty());
        assert!(recovered.received.is_empty());
        assert!(recovered.closed_e3s.contains(&e3_id));

        let proof_type = ProofType::C4aSkShareDecryption;
        let decryption = PublishDocumentRequested {
            meta: request.meta.clone(),
            value: ArcBytes::from_bytes(
                &ReceivableDocument::DecryptionKeyShared(DecryptionKeyShared {
                    e3_id: e3_id.clone(),
                    party_id: 0,
                    node: "test-node".to_string(),
                    signed_sk_decryption_proof: SignedProofPayload {
                        payload: ProofPayload {
                            e3_id: e3_id.clone(),
                            proof_type,
                            proof: Proof::new(
                                proof_type.circuit_names()[0],
                                ArcBytes::from_bytes(&[1]),
                                ArcBytes::from_bytes(&[2]),
                            ),
                        },
                        signature: ArcBytes::from_bytes(&[3; 65]),
                    },
                    signed_e_sm_decryption_proofs: vec![],
                    external: false,
                })
                .to_bytes()?,
            ),
        };
        append(&system, decryption.into(), 4, EventSource::Local).await?;
        let recovered = recover_document_state(&reader, &[aggregate], &interests).await?;
        assert!(recovered.publications.is_empty());

        append(
            &system,
            E3StageChanged {
                e3_id: e3_id.clone(),
                previous_stage: E3Stage::KeyPublished,
                new_stage: E3Stage::CiphertextReady,
            }
            .into(),
            5,
            EventSource::Evm,
        )
        .await?;
        let recovered = recover_document_state(&reader, &[aggregate], &interests).await?;
        assert!(recovered.publications.is_empty());

        append(
            &system,
            E3StageChanged {
                e3_id: e3_id.clone(),
                previous_stage: E3Stage::CiphertextReady,
                new_stage: E3Stage::Complete,
            }
            .into(),
            6,
            EventSource::Evm,
        )
        .await?;
        let recovered = recover_document_state(&reader, &[aggregate], &interests).await?;
        assert!(recovered.publications.is_empty());
        assert!(recovered.received.is_empty());
        assert!(recovered.closed_e3s.contains(&e3_id));
        Ok(())
    }
}
