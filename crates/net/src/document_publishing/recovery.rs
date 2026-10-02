// SPDX-License-Identifier: LGPL-3.0-only

//! Rebuild in-flight DHT publication and receive state from the durable event log.

use super::{
    ContentHash, RecoveredDocumentState, MAX_PENDING_PUBLICATIONS, MAX_PENDING_PUBLICATION_BYTES,
    MAX_RECEIVED_DOCUMENTS,
};
use crate::domain::closed_e3s::record_closed_e3;
use crate::domain::{EventConversionService, RestorableDocuments};
use actix::Recipient;
use anyhow::{ensure, Context, Result};
use e3_events::{
    AggregateId, CorrelationId, E3Stage, E3id, Event, EventContextAccessors, EventContextSeq,
    EventSource, EventStoreQueryBy, EventStoreQueryResponse, InterfoldEvent, InterfoldEventData,
    PublishDocumentRequested, SeqAgg,
};
use e3_utils::actix::channel;
use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet, VecDeque};

fn derived_publication(
    data: &InterfoldEventData,
    source: EventSource,
) -> Result<Option<PublishDocumentRequested>> {
    if source != EventSource::Local {
        return Ok(None);
    }
    match data {
        InterfoldEventData::ThresholdShareCreated(event) => {
            EventConversionService::threshold_share_to_request(event.clone())
        }
        InterfoldEventData::EncryptionKeyCreated(event) => {
            EventConversionService::encryption_key_to_request(event.clone())
        }
        InterfoldEventData::DecryptionKeyShared(event) => {
            EventConversionService::decryption_key_to_request(event.clone())
        }
        _ => Ok(None),
    }
}

fn track_publication(
    publications: &mut HashMap<(E3id, ContentHash), PublishDocumentRequested>,
    publication_bytes: &mut usize,
    closed: &VecDeque<E3id>,
    request: PublishDocumentRequested,
) -> Result<()> {
    if closed.contains(&request.meta.e3_id) || request.meta.expires_at <= chrono::Utc::now() {
        return Ok(());
    }
    let id = (
        request.meta.e3_id.clone(),
        ContentHash::from_content(&request.value),
    );
    let publication_count = publications.len();
    match publications.entry(id) {
        Entry::Occupied(mut existing) => {
            existing.insert(request);
        }
        Entry::Vacant(entry) => {
            let new_bytes = publication_bytes
                .checked_add(request.value.size())
                .context("document publication outbox size overflow")?;
            ensure!(
                publication_count < MAX_PENDING_PUBLICATIONS
                    && new_bytes <= MAX_PENDING_PUBLICATION_BYTES,
                "document publication outbox exceeds recovery limits"
            );
            *publication_bytes = new_bytes;
            entry.insert(request);
        }
    }
    Ok(())
}

/// Events in one event-store page that recovery reads.
const RECOVERY_PAGE_EVENTS: u64 = 1_024;
/// Bytes in one event-store page that recovery reads. A page holds at least one event, also when
/// that event is larger.
const RECOVERY_PAGE_BYTES: u64 = 16 * 1024 * 1024;

/// Read up to `limit` events of `aggregate_id` from sequence `cursor` on, in one bounded page.
async fn read_page(
    eventstore: &Recipient<EventStoreQueryBy<SeqAgg>>,
    aggregate_id: AggregateId,
    cursor: u64,
    limit: u64,
) -> Result<Vec<InterfoldEvent>> {
    let (recipient, response) = channel::oneshot::<EventStoreQueryResponse>();
    eventstore
        .send(
            EventStoreQueryBy::<SeqAgg>::new(
                CorrelationId::new(),
                HashMap::from([(aggregate_id, cursor)]),
                recipient,
            )
            .with_limit(limit)
            .with_max_bytes(RECOVERY_PAGE_BYTES),
        )
        .await
        .context("document recovery event-store router stopped")?;
    response
        .await
        .context("document recovery event-store query had no response")?
        .into_events()
}

pub async fn recover_document_state(
    eventstore: &Recipient<EventStoreQueryBy<SeqAgg>>,
    aggregates: &[AggregateId],
    interested_e3s: &HashSet<E3id>,
) -> Result<RecoveredDocumentState> {
    let mut publications = HashMap::new();
    let mut received = HashSet::new();
    let mut restorable = RestorableDocuments::default();
    let now = chrono::Utc::now();
    let mut closed = VecDeque::new();
    let mut publication_bytes = 0usize;

    for aggregate_id in aggregates.iter().copied() {
        let mut cursor = 1u64;
        let mut page = VecDeque::new();
        loop {
            if page.is_empty() {
                page = read_page(eventstore, aggregate_id, cursor, RECOVERY_PAGE_EVENTS)
                    .await?
                    .into();
            }
            let Some(event) = page.pop_front() else {
                break;
            };
            // The event-store router drops legacy events that were written to the wrong aggregate
            // store, so a page can skip a sequence number. A one-event read at that number is then
            // empty: recovery stops there, so that a node with such a legacy store still starts.
            // A missing event is an error.
            if event.seq() != cursor
                && read_page(eventstore, aggregate_id, cursor, 1)
                    .await?
                    .is_empty()
            {
                break;
            }
            ensure!(
                event.aggregate_id() == aggregate_id && event.seq() == cursor,
                "document recovery event-store sequence gap"
            );
            cursor = cursor
                .checked_add(1)
                .context("document recovery sequence overflow")?;

            if let Some(request) = derived_publication(event.get_data(), event.source())? {
                track_publication(&mut publications, &mut publication_bytes, &closed, request)?;
            }

            match event.get_data() {
                InterfoldEventData::PublishDocumentRequested(request) => {
                    track_publication(
                        &mut publications,
                        &mut publication_bytes,
                        &closed,
                        request.clone(),
                    )?;
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
                    restorable.push(document.clone(), now);
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
                    record_closed_e3(&mut closed, &change.e3_id);
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
                    restorable.remove_e3(&change.e3_id);
                }
                _ => {}
            }
        }
    }

    Ok(RecoveredDocumentState {
        publications: publications.into_values().collect(),
        received,
        restorable,
        closed_e3s: closed,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::event_conversion::ReceivableDocument;
    use actix::Actor;
    use e3_ciphernode_builder::{EventStoreAddrs, EventSystem};
    use e3_events::{
        AggregateConfig, DecryptionKeyShared, DocumentKind, DocumentMeta, DocumentReceived,
        E3StageChanged, EncryptionKey, EncryptionKeyCreated, EventConstructorWithTimestamp,
        InterfoldEvent, Proof, ProofPayload, ProofType, PublishDocumentRequested,
        SignedProofPayload, StoreEventRequested, StoreEventResponse, Unsequenced,
    };
    use e3_utils::ArcBytes;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
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
        let mut recovered = recover_document_state(&reader, &[aggregate], &interests).await?;
        assert_eq!(recovered.publications, vec![request.clone()]);
        assert!(recovered
            .received
            .contains(&(e3_id.clone(), ContentHash::from_content(&value))));
        assert_eq!(
            recovered.restorable.pop(chrono::Utc::now()),
            Some(DocumentReceived {
                meta: request.meta.clone(),
                value: value.clone(),
            })
        );

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
        let mut recovered = recover_document_state(&reader, &[aggregate], &interests).await?;
        assert!(recovered.publications.is_empty());
        assert!(recovered.received.is_empty());
        assert_eq!(recovered.restorable.pop(chrono::Utc::now()), None);
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

    #[actix::test]
    async fn persisted_artifact_recovers_missing_publication_request() -> Result<()> {
        let aggregate = AggregateId::new(1);
        let system =
            EventSystem::new()
                .with_fresh_bus()
                .with_aggregate_config(AggregateConfig::new(HashMap::from([(
                    aggregate,
                    Duration::ZERO,
                )])));
        let artifact = EncryptionKeyCreated {
            e3_id: E3id::new("8", 1),
            key: Arc::new(EncryptionKey::new(0, ArcBytes::from_bytes(&[9; 32]))),
            external: false,
        };
        append(&system, artifact.clone().into(), 1, EventSource::Local).await?;

        let recovered = recover_document_state(
            &system.eventstore_reader()?.seq(),
            &[aggregate],
            &HashSet::new(),
        )
        .await?;

        assert_eq!(recovered.publications.len(), 1);
        let publication = &recovered.publications[0];
        assert_eq!(publication.meta.e3_id, artifact.e3_id);
        assert!(matches!(
            ReceivableDocument::from_bytes(&publication.value)?,
            ReceivableDocument::EncryptionKeyCreated(recovered) if recovered == artifact
        ));
        Ok(())
    }

    /// Forwards event-store queries and counts them.
    struct CountingReader {
        inner: Recipient<EventStoreQueryBy<SeqAgg>>,
        queries: Arc<AtomicUsize>,
    }

    impl actix::Actor for CountingReader {
        type Context = actix::Context<Self>;
    }

    impl actix::Handler<EventStoreQueryBy<SeqAgg>> for CountingReader {
        type Result = ();

        fn handle(&mut self, query: EventStoreQueryBy<SeqAgg>, _: &mut Self::Context) {
            self.queries.fetch_add(1, Ordering::SeqCst);
            self.inner
                .try_send(query)
                .expect("the event store accepts the query");
        }
    }

    #[actix::test]
    async fn recovery_reads_the_event_log_in_pages() -> Result<()> {
        let aggregate = AggregateId::new(1);
        let system =
            EventSystem::new()
                .with_fresh_bus()
                .with_aggregate_config(AggregateConfig::new(HashMap::from([(
                    aggregate,
                    Duration::ZERO,
                )])));
        for ts in 1..=50u128 {
            let request = PublishDocumentRequested {
                meta: DocumentMeta::new(
                    E3id::new("9", 1),
                    DocumentKind::TrBFV,
                    vec![],
                    Some(chrono::Utc::now() + chrono::Duration::hours(1)),
                ),
                value: ArcBytes::from_bytes(&ts.to_le_bytes()),
            };
            append(&system, request.into(), ts, EventSource::Local).await?;
        }
        let queries = Arc::new(AtomicUsize::new(0));
        let reader = CountingReader {
            inner: system.eventstore_reader()?.seq(),
            queries: queries.clone(),
        }
        .start()
        .recipient();

        let recovered = recover_document_state(&reader, &[aggregate], &HashSet::new()).await?;

        assert_eq!(recovered.publications.len(), 50);
        // One page holds every event, and an empty page ends the aggregate.
        assert_eq!(queries.load(Ordering::SeqCst), 2);
        Ok(())
    }

    /// The event-store router drops a legacy event that was written to the wrong aggregate store.
    /// Recovery stops at that event instead of failing startup on the skipped sequence number.
    #[actix::test]
    async fn recovery_stops_at_a_quarantined_legacy_event() -> Result<()> {
        let aggregate = AggregateId::new(1);
        let system =
            EventSystem::new()
                .with_fresh_bus()
                .with_aggregate_config(AggregateConfig::new(HashMap::from([(
                    aggregate,
                    Duration::ZERO,
                )])));
        let request = |e3_id: E3id, value: &[u8]| PublishDocumentRequested {
            meta: DocumentMeta::new(
                e3_id,
                DocumentKind::TrBFV,
                vec![],
                Some(chrono::Utc::now() + chrono::Duration::hours(1)),
            ),
            value: ArcBytes::from_bytes(value),
        };
        let before = request(E3id::new("1", 1), b"before");
        append(&system, before.clone().into(), 1, EventSource::Local).await?;
        let EventStoreAddrs::InMem(stores) = system.eventstore_addrs()? else {
            anyhow::bail!("expected in-memory event stores");
        };
        let misrouted = InterfoldEvent::<Unsequenced>::new_with_timestamp(
            request(E3id::new("2", 2), b"misrouted").into(),
            None,
            2,
            None,
            EventSource::Local,
        );
        let (recipient, response) = channel::oneshot::<StoreEventResponse>();
        stores[&1]
            .send(StoreEventRequested::new(misrouted, recipient))
            .await?;
        response.await?;
        append(
            &system,
            request(E3id::new("3", 1), b"after").into(),
            3,
            EventSource::Local,
        )
        .await?;

        let recovered = recover_document_state(
            &system.eventstore_reader()?.seq(),
            &[aggregate],
            &HashSet::new(),
        )
        .await?;

        assert_eq!(recovered.publications, vec![before]);
        Ok(())
    }
}
