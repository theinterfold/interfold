// SPDX-License-Identifier: LGPL-3.0-only

//! Bounded historical-event fetching, validation, and recovery retries.

use super::*;
use crate::net_interface_handle::NetEventSubscriber;

pub(in crate::actors::net_sync_manager) async fn fetch_historical_events_for_aggregate(
    net_cmds: &mpsc::Sender<NetCommand>,
    net_events: &NetEventSubscriber,
    aggregate_id: AggregateId,
    since: u128,
    budget: &mut SyncFetchBudget,
    network: &NetworkPolicy,
) -> Result<Vec<InterfoldEvent<Unsequenced>>> {
    let requester = DirectRequester::builder(net_cmds.clone(), net_events.clone())
        .max_retries(SYNC_FETCH_MAX_RETRIES)
        .retry_timeout(SYNC_FETCH_RETRY_TIMEOUT)
        .build();

    let events = fetch_all_batched_events_with_budget::<InterfoldEvent<Unsequenced>>(
        requester,
        PeerTarget::Random,
        aggregate_id,
        since,
        100,
        budget,
    )
    .await?;

    validate_historical_events(aggregate_id, events, network)
}

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
    has_connected_peers: bool,
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
    } else if !has_connected_peers {
        // `AllPeersDialed` was already observed with zero successful connections and
        // readiness published `NetReady` through its connect-timeout fallback. Every
        // fetch below would fail with "No connected peers available", burn the retry
        // budget, and then `bail!` — which `trap_fut` converts into an error event
        // rather than a completion, so startup would wait on a `SyncRequestSucceeded`
        // that can never arrive and die at `startup_timeout_secs` in a crash loop.
        //
        // A node that cannot reach a peer has no history to import. Complete the phase
        // with an empty result so it boots and serves the chain; the background
        // bootstrap retries and live gossip remain responsible for catching it up.
        warn!(
            aggregates = sync_cursor.len(),
            "Skipping historical peer sync: no peer connections are available. \
             The node will start from local state and catch up over live gossip"
        );
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
