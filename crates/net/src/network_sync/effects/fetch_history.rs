// SPDX-License-Identifier: LGPL-3.0-only

//! Bounded historical-event fetching, validation, and recovery retries.

use super::*;
use crate::events::call_and_await_response;
use crate::net_interface_handle::NetEventSubscriber;
use anyhow::ensure;
use e3_events::EventId;
use libp2p::PeerId;
use rand::seq::SliceRandom;
use std::time::Duration;

/// Peers whose histories a node merges for each aggregate.
const HISTORY_SOURCES: usize = 2;
/// Peers a node asks for one aggregate before it accepts history that no peer observed live.
const MAX_HISTORY_PEERS: usize = 4;
/// Fetch time kept back for each source that a failed source leaves the node short of.
const SOURCE_RESERVE: Duration = Duration::from_secs(60);
/// Least fetch time that a source that another peer can replace gets.
const MIN_SOURCE_TIME: Duration = Duration::from_secs(30);

/// Fetch one aggregate's history from several admitted peers and merge it by event ID.
///
/// A peer can lack part of the range, for example after a restart or a reset, and still answer
/// `Done`. So the node asks two peers, each from `since` and with every page pinned to that peer,
/// and keeps the union. It asks up to four peers while none of the successful ones observed the
/// whole range live (its `observed_from` is at or before `since`); that time is a hint, and the two
/// sources are what the node relies on. A peer that fails is replaced by another one. A peer that a
/// later peer can replace gets one attempt per page, and the fetch time less a reserve for the
/// sources that would replace it, so slow or silent peers cannot use up the deadline before the
/// node reaches a healthy one. One connected peer serves alone.
pub(in crate::actors::net_sync_manager) async fn fetch_historical_events_for_aggregate(
    net_cmds: &mpsc::Sender<NetCommand>,
    net_events: &NetEventSubscriber,
    aggregate_id: AggregateId,
    since: u128,
    budget: &mut SyncFetchBudget,
    network: &NetworkPolicy,
) -> Result<Vec<InterfoldEvent<Unsequenced>>> {
    let mut peers = budget.within(admitted_peers(net_cmds, net_events)).await?;
    ensure!(!peers.is_empty(), "No connected peers available");
    peers.shuffle(&mut rand::rng());
    fetch_history_from_peers(
        net_cmds,
        net_events,
        peers,
        aggregate_id,
        since,
        budget,
        network,
    )
    .await
}

/// Fetch one aggregate's history from `peers`, in their order, as
/// [`fetch_historical_events_for_aggregate`] describes.
pub(in crate::actors::net_sync_manager) async fn fetch_history_from_peers(
    net_cmds: &mpsc::Sender<NetCommand>,
    net_events: &NetEventSubscriber,
    peers: Vec<PeerId>,
    aggregate_id: AggregateId,
    since: u128,
    budget: &mut SyncFetchBudget,
    network: &NetworkPolicy,
) -> Result<Vec<InterfoldEvent<Unsequenced>>> {
    let mut merged: HashMap<EventId, InterfoldEvent<Unsequenced>> = HashMap::new();
    let mut sources = 0usize;
    let mut vouched = false;
    let mut last_error = None;
    let candidates = peers.len().min(MAX_HISTORY_PEERS);
    for (index, peer) in peers.into_iter().take(MAX_HISTORY_PEERS).enumerate() {
        if sources >= HISTORY_SOURCES && vouched {
            break;
        }
        let later = candidates - index - 1;
        let requester = DirectRequester::builder(net_cmds.clone(), net_events.clone())
            .max_retries(attempts_per_page(later, sources))
            .retry_timeout(SYNC_FETCH_RETRY_TIMEOUT)
            .build();
        let source_time = source_time(later, sources, budget.remaining()?);
        let history = match fetch_all_batched_events_with_budget::<InterfoldEvent<Unsequenced>>(
            requester,
            PeerTarget::Specific(peer),
            aggregate_id,
            since,
            100,
            budget,
            source_time,
        )
        .await
        .and_then(|history| {
            validate_historical_events(aggregate_id, history.events, network)
                .map(|events| (events, history.observed_from))
        }) {
            Ok(history) => history,
            Err(error) => {
                if budget.is_exhausted() {
                    return Err(error);
                }
                warn!(%peer, %aggregate_id, "History fetch from a peer failed: {error:#}");
                last_error = Some(error);
                continue;
            }
        };
        let (events, observed_from) = history;
        sources += 1;
        vouched |= observed_from.is_some_and(|observed| observed <= since);
        for event in events {
            merge_by_event_id(&mut merged, event)?;
        }
    }
    if sources == 0 {
        return Err(
            last_error.unwrap_or_else(|| anyhow::anyhow!("No admitted peer served the history"))
        );
    }
    if !vouched {
        warn!(
            %aggregate_id,
            since,
            sources,
            "No peer observed the requested history range live; it may be incomplete"
        );
    }
    let mut events: Vec<_> = merged.into_values().collect();
    events.sort_by_key(|event| event.ts());
    Ok(events)
}

/// Whether the `later` peers can still supply the sources that the node lacks if this peer fails.
fn replaceable(later: usize, sources: usize) -> bool {
    later >= HISTORY_SOURCES.saturating_sub(sources)
}

/// Attempts for each page of one peer's history. A peer that a later peer can replace gets one
/// attempt: a silent peer then costs one request timeout, and four peers fit the fetch deadline.
/// Otherwise it gets every retry.
fn attempts_per_page(later: usize, sources: usize) -> u32 {
    if replaceable(later, sources) {
        1
    } else {
        SYNC_FETCH_MAX_RETRIES
    }
}

/// The fetch time of one peer's history. A peer that a later peer can replace leaves a reserve for
/// each source that the node would then still lack. Otherwise the peer can use all `remaining`.
fn source_time(later: usize, sources: usize, remaining: Duration) -> Option<Duration> {
    replaceable(later, sources).then(|| {
        let missing = HISTORY_SOURCES.saturating_sub(sources) as u32;
        remaining
            .saturating_sub(SOURCE_RESERVE * missing)
            .max(MIN_SOURCE_TIME)
    })
}

/// Keep one copy of each event. Peers stamp the same event with their own reception time, so the
/// earliest timestamp wins, which makes the choice independent of the order of the peers. The event
/// ID does not fix the whole payload, so two copies with one ID must carry one payload; otherwise
/// the fetch fails rather than drop one of them.
fn merge_by_event_id(
    merged: &mut HashMap<EventId, InterfoldEvent<Unsequenced>>,
    event: InterfoldEvent<Unsequenced>,
) -> Result<()> {
    match merged.entry(event.id()) {
        std::collections::hash_map::Entry::Vacant(entry) => {
            entry.insert(event);
        }
        std::collections::hash_map::Entry::Occupied(mut entry) => {
            ensure!(
                entry.get().get_data() == event.get_data(),
                "history peers served different payloads under event ID {}",
                event.id()
            );
            if event.ts() < entry.get().ts() {
                entry.insert(event);
            }
        }
    }
    Ok(())
}

/// The connected peers that passed network admission.
async fn admitted_peers(
    net_cmds: &mpsc::Sender<NetCommand>,
    net_events: &NetEventSubscriber,
) -> Result<Vec<PeerId>> {
    call_and_await_response(
        net_cmds.clone(),
        net_events.clone(),
        NetCommand::AdmittedPeers {
            correlation_id: CorrelationId::new(),
        },
        |event| match event {
            NetEvent::AdmittedPeers { peers, .. } => Some(Ok(peers.clone())),
            _ => None,
        },
        ADMITTED_PEERS_TIMEOUT,
    )
    .await
}

/// Deadline for the swarm to list its admitted peers.
const ADMITTED_PEERS_TIMEOUT: Duration = Duration::from_secs(10);

pub(in crate::actors::net_sync_manager) fn validate_historical_events(
    aggregate_id: AggregateId,
    events: Vec<InterfoldEvent<Unsequenced>>,
    network: &NetworkPolicy,
) -> Result<Vec<InterfoldEvent<Unsequenced>>> {
    for event in &events {
        // The peer supplies the context ID. The merge keeps one event per ID, so a mislabeled
        // event could hide another peer's copy of a different event.
        let payload_id = EventId::hash(event.get_data());
        if event.id() != payload_id {
            bail!(
                "historical sync peer returned event {} whose payload has ID {}",
                event.id(),
                payload_id
            );
        }
        if event.aggregate_id() != aggregate_id {
            bail!(
                "historical sync peer returned event for aggregate {} while fetching {}",
                event.aggregate_id(),
                aggregate_id
            );
        }
        if !EventTranslationService::is_forwardable_event(event) {
            bail!(
                "historical sync peer returned non-forwardable event type {}",
                event.event_type()
            );
        }
        network.validate_event(event)?;
    }
    Ok(events)
}

pub(in crate::actors::net_sync_manager) fn eligible_sync_cursor(
    since: &BTreeMap<AggregateId, u128>,
    network: &NetworkPolicy,
) -> BTreeMap<AggregateId, u128> {
    since
        .iter()
        .filter_map(|(aggregate_id, timestamp)| {
            aggregate_id
                .to_chain_id()
                .filter(|chain_id| network.allows_chain(*chain_id))
                .map(|_| (*aggregate_id, *timestamp))
        })
        .collect()
}

pub(in crate::actors::net_sync_manager) async fn handle_sync_request_event(
    net_cmds: mpsc::Sender<NetCommand>,
    net_events: NetEventSubscriber,
    event: TypedEvent<HistoricalNetSyncStart>,
    address: impl Into<Recipient<TypedEvent<SyncRequestSucceeded>>>,
    wait_for_event: bool,
    network: NetworkPolicy,
) -> Result<()> {
    info!("Sync request event received");
    let (event, ctx) = event.into_components();
    let sync_cursor = eligible_sync_cursor(&event.since, &network);
    let excluded_aggregates = event.since.len().saturating_sub(sync_cursor.len());
    if excluded_aggregates > 0 {
        info!(
            excluded_aggregates,
            "Excluded local or foreign aggregates from historical peer sync"
        );
    }
    if sync_cursor.is_empty() {
        address.into().try_send(TypedEvent::new(
            SyncRequestSucceeded {
                response: SyncResponseValue {
                    events: vec![],
                    ts: 0,
                },
            },
            ctx,
        ))?;
        return Ok(());
    }

    info!("Checking for AllPeersDialed...");
    if wait_for_event {
        info!("Waiting for peer connection...");
        let has_peers = await_event(
            &net_events,
            |e| match e {
                NetEvent::ConnectionEstablished { .. } => {
                    info!("Peer connection established");
                    Some(true)
                }
                NetEvent::AllPeersDialed { total: 0, .. } => {
                    info!("No peers configured, proceeding without sync");
                    Some(false)
                }
                _ => None,
            },
            NET_READY_CONNECT_TIMEOUT,
        )
        .await
        .context("No peer connections established within timeout")?;

        if !has_peers {
            let value = SyncRequestSucceeded {
                response: SyncResponseValue {
                    events: vec![],
                    ts: 0,
                },
            };

            address.into().try_send(TypedEvent::new(value, ctx))?;
            return Ok(());
        }
    }
    info!("handle_sync_request_event: ready to sync");

    let mut all_events: Vec<InterfoldEvent<Unsequenced>> = Vec::new();
    let mut latest_timestamp: u128 = 0;
    let mut failed_aggregates: Vec<AggregateId> = Vec::new();
    let mut budget = SyncFetchBudget::production();

    for (aggregate_id, since) in &sync_cursor {
        info!(
            "Requesting batched events for aggregate_id={} since={}",
            aggregate_id, since
        );
        match fetch_historical_events_for_aggregate(
            &net_cmds,
            &net_events,
            *aggregate_id,
            *since,
            &mut budget,
            &network,
        )
        .await
        {
            Ok(events) => {
                info!(
                    "Received {} events for aggregate_id={}",
                    events.len(),
                    aggregate_id
                );
                for interfold_event in events {
                    let ts = interfold_event.ts();
                    if ts > latest_timestamp {
                        latest_timestamp = ts;
                    }
                    all_events.push(interfold_event);
                }
            }
            Err(e) => {
                if budget.is_exhausted() {
                    return Err(e).context("historical net sync exhausted its global budget");
                }
                warn!(
                    "Failed to fetch events for aggregate_id={}: {e}. Continuing with available events.",
                    aggregate_id
                );
                failed_aggregates.push(*aggregate_id);
            }
        }
    }

    // If any aggregate failed, retry a few recovery rounds. Prefer a fresh
    // ConnectionEstablished signal when one arrives, but do not depend on it:
    // a connected peer may simply be slow or temporarily stalled.
    if !failed_aggregates.is_empty() {
        info!(
            "Sync fetch failed for {} aggregates — starting recovery retries...",
            failed_aggregates.len()
        );
        let mut recovery_attempt = 0;

        while !failed_aggregates.is_empty() && recovery_attempt < SYNC_RECOVERY_MAX_ATTEMPTS {
            recovery_attempt += 1;

            // The wait counts against the fetch deadline too.
            let wait = match budget.remaining() {
                Ok(remaining) => SYNC_RECOVERY_RETRY_INTERVAL.min(remaining),
                Err(error) => {
                    return Err(error).context("historical net sync exhausted its global budget")
                }
            };
            match await_event(
                &net_events,
                |e| {
                    if matches!(e, NetEvent::ConnectionEstablished { .. }) {
                        Some(())
                    } else {
                        None
                    }
                },
                wait,
            )
            .await
            {
                Ok(()) => {
                    info!(
                        attempt = recovery_attempt,
                        "Peer reconnected, retrying failed aggregates"
                    );
                }
                Err(_) => {
                    info!(
                        attempt = recovery_attempt,
                        retry_after = ?SYNC_RECOVERY_RETRY_INTERVAL,
                        "No new peer connection observed; retrying failed aggregates against current peers"
                    );
                }
            }

            let mut still_failed = Vec::new();
            for aggregate_id in failed_aggregates {
                let since = sync_cursor.get(&aggregate_id).copied().unwrap_or(0);
                match fetch_historical_events_for_aggregate(
                    &net_cmds,
                    &net_events,
                    aggregate_id,
                    since,
                    &mut budget,
                    &network,
                )
                .await
                {
                    Ok(events) => {
                        info!(
                            attempt = recovery_attempt,
                            "Retry succeeded: {} events for aggregate_id={}",
                            events.len(),
                            aggregate_id
                        );
                        for interfold_event in events {
                            let ts = interfold_event.ts();
                            if ts > latest_timestamp {
                                latest_timestamp = ts;
                            }
                            all_events.push(interfold_event);
                        }
                    }
                    Err(e) => {
                        if budget.is_exhausted() {
                            return Err(e)
                                .context("historical net sync exhausted its global budget");
                        }
                        warn!(
                            attempt = recovery_attempt,
                            "Retry failed for aggregate_id={}: {e}", aggregate_id
                        );
                        still_failed.push(aggregate_id);
                    }
                }
            }

            failed_aggregates = still_failed;
        }

        if !failed_aggregates.is_empty() {
            bail!(
                "failed to fetch historical net events for aggregates: {:?} after {} recovery attempts",
                failed_aggregates,
                SYNC_RECOVERY_MAX_ATTEMPTS
            );
        }
    }

    info!(
        "Sync complete: collected {} events across {} aggregates, latest_timestamp={}",
        all_events.len(),
        sync_cursor.len(),
        latest_timestamp
    );

    let value = SyncRequestSucceeded {
        response: SyncResponseValue {
            events: all_events,
            ts: latest_timestamp,
        },
    };

    address.into().try_send(TypedEvent::new(value, ctx))?;
    Ok(())
}

#[cfg(test)]
mod merge_tests {
    use super::*;
    use e3_events::{E3id, EventConstructorWithTimestamp, EventSource, KeyshareCreated};
    use e3_utils::ArcBytes;

    fn keyshare(pubkey: &[u8], ts: u128) -> InterfoldEvent<Unsequenced> {
        InterfoldEvent::<Unsequenced>::new_with_timestamp(
            KeyshareCreated {
                pubkey: ArcBytes::from_bytes(pubkey),
                e3_id: E3id::new("1", 1),
                node: "node-1".to_string(),
                party_id: 1,
                signed_pk_generation_proof: None,
            }
            .into(),
            None,
            ts,
            None,
            EventSource::Net,
        )
    }

    /// `payload`'s event under the context of `label`, as two payloads with one ID would arrive.
    fn under_the_id_of(
        payload: &[u8],
        label: &InterfoldEvent<Unsequenced>,
    ) -> InterfoldEvent<Unsequenced> {
        #[derive(serde::Serialize)]
        struct Raw<'a> {
            payload: &'a InterfoldEventData,
            ctx: &'a e3_events::EventContext<Unsequenced>,
        }
        let (data, _) = keyshare(payload, 5).into_components();
        let (_, ctx) = label.clone().into_components();
        let bytes = bincode::serialize(&Raw {
            payload: &data,
            ctx: &ctx,
        })
        .unwrap();
        InterfoldEvent::from_bytes(&bytes).unwrap()
    }

    #[test]
    fn copies_of_one_event_merge_to_the_earliest_and_different_payloads_fail() {
        let mut merged = HashMap::new();
        merge_by_event_id(&mut merged, keyshare(&[1], 20)).unwrap();
        merge_by_event_id(&mut merged, keyshare(&[1], 10)).unwrap();
        assert_eq!(merged.len(), 1);
        assert_eq!(merged.values().next().unwrap().ts(), 10);

        let conflicting = under_the_id_of(&[2], &keyshare(&[1], 30));
        assert!(merge_by_event_id(&mut merged, conflicting).is_err());
    }
}
