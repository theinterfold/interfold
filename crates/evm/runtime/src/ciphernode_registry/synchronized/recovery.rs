// SPDX-License-Identifier: LGPL-3.0-only

use super::*;
use e3_events::{AggregateId, CorrelationId, EventStoreQueryBy, EventStoreQueryResponse, SeqAgg};

/// Scan retained chain history, including intents before per-E3 snapshot cursors. Shared canonical
/// facts must already be restored; no transaction runs while this gate is being rebuilt.
pub async fn recover_synchronized_publications(
    store: &Recipient<EventStoreQueryBy<SeqAgg>>,
    chain: u64,
    keys: &CanonicalPublicKeys,
) -> Result<Vec<SynchronizedDkgPublicationReady>> {
    let aggregate = AggregateId::new(chain.try_into()?);
    let mut cursor = 1;
    let mut pending = HashMap::new();
    let mut closed = HashSet::new();
    loop {
        let (recipient, response) = e3_utils::actix::channel::oneshot::<EventStoreQueryResponse>();
        store
            .send(
                EventStoreQueryBy::<SeqAgg>::new(
                    CorrelationId::new(),
                    HashMap::from([(aggregate, cursor)]),
                    recipient,
                )
                .with_limit(1024)
                .with_max_bytes(16 * 1024 * 1024),
            )
            .await?;
        let events = response
            .await
            .context("publication recovery query had no response")?
            .into_events()?;
        if events.is_empty() {
            break;
        }
        for event in events {
            anyhow::ensure!(
                event.aggregate_id() == aggregate && event.seq() == cursor,
                "publication recovery event-store sequence gap"
            );
            cursor += 1;
            let terminal = match event.get_data() {
                InterfoldEventData::E3RequestComplete(data)
                    if event.source() != EventSource::Net =>
                {
                    Some(&data.e3_id)
                }
                InterfoldEventData::E3Failed(data)
                    if event.source() == EventSource::Evm && event.block().is_some() =>
                {
                    Some(&data.e3_id)
                }
                InterfoldEventData::E3StageChanged(data)
                    if event.source() == EventSource::Evm
                        && event.block().is_some()
                        && data.new_stage.is_terminal() =>
                {
                    Some(&data.e3_id)
                }
                _ => None,
            };
            if let Some(id) = terminal {
                pending.remove(id);
                closed.insert(id.clone());
                continue;
            }
            if let InterfoldEventData::SynchronizedDkgPublicationReady(intent) = event.get_data() {
                anyhow::ensure!(
                    intent.e3_id.chain_id() == chain,
                    "publication intent in another chain aggregate"
                );
                if event.source() == EventSource::Local
                    && !closed.contains(&intent.e3_id)
                    && keys.public_key(&intent.e3_id).is_none()
                {
                    pending
                        .entry(intent.e3_id.clone())
                        .or_insert_with(|| intent.clone());
                }
            }
        }
    }
    // Validate only surviving intents: terminal history wins even over obsolete candidates.
    for intent in pending.values() {
        keys.synchronized_selection(&intent.e3_id)
            .context("recovered publication has no selection")?
            .validate_publication(
                keys.synchronized_context(&intent.e3_id)
                    .context("recovered publication has no frozen context")?,
                intent,
            )?;
    }
    Ok(pending.into_values().collect())
}
