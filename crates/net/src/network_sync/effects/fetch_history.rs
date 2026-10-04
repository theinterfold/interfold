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

/// Fetch one aggregate's history from several admitted peers and merge it by event ID.
///
/// A peer can lack part of the range, for example after a restart or a reset, and still answer
/// `Done`. So the node asks two peers, each from `since` and with every page pinned to that peer,
/// and keeps the union. It asks up to four peers while none of the successful ones observed the
/// whole range live (its `observed_from` is at or before `since`). A peer that fails is replaced by
/// another one. One connected peer serves alone.
pub(in crate::actors::net_sync_manager) async fn fetch_historical_events_for_aggregate(
    net_cmds: &mpsc::Sender<NetCommand>,
    net_events: &NetEventSubscriber,
    aggregate_id: AggregateId,
    since: u128,
    budget: &mut SyncFetchBudget,
    network: &NetworkPolicy,
) -> Result<Vec<InterfoldEvent<Unsequenced>>> {
    let mut peers = admitted_peers(net_cmds, net_events).await?;
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
    for peer in peers.into_iter().take(MAX_HISTORY_PEERS) {
        if sources >= HISTORY_SOURCES && vouched {
            break;
        }
        let requester = DirectRequester::builder(net_cmds.clone(), net_events.clone())
            .max_retries(SYNC_FETCH_MAX_RETRIES)
            .retry_timeout(SYNC_FETCH_RETRY_TIMEOUT)
            .build();
        let history = match fetch_all_batched_events_with_budget::<InterfoldEvent<Unsequenced>>(
            requester,
            PeerTarget::Specific(peer),
            aggregate_id,
            since,
            100,
            budget,
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
            merge_by_event_id(&mut merged, event);
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

/// Keep one copy of each event. Peers stamp the same event with their own reception time, so the
/// earliest timestamp wins, which makes the choice independent of the order of the peers.
fn merge_by_event_id(
    merged: &mut HashMap<EventId, InterfoldEvent<Unsequenced>>,
    event: InterfoldEvent<Unsequenced>,
) {
    match merged.entry(event.id()) {
        std::collections::hash_map::Entry::Vacant(entry) => {
            entry.insert(event);
        }
        std::collections::hash_map::Entry::Occupied(mut entry) => {
            if event.ts() < entry.get().ts() {
                entry.insert(event);
            }
        }
    }
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

            match await_event(
                &net_events,
                |e| {
                    if matches!(e, NetEvent::ConnectionEstablished { .. }) {
                        Some(())
                    } else {
                        None
                    }
                },
                SYNC_RECOVERY_RETRY_INTERVAL,
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
