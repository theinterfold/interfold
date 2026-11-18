// SPDX-License-Identifier: LGPL-3.0-only

//! Bounded historical-event fetching, validation, and recovery retries.

use super::history_source::{
    fetch_source, Additions, FetchDeadline, HistoryRange, HistorySize, LatestTs, MergedEvents,
    SourceHistory, MAX_KEPT_HISTORY,
};
use super::*;
use crate::direct_requester::WithoutPeer;
use crate::events::call_and_await_response;
use crate::net_interface_handle::NetEventSubscriber;
use anyhow::ensure;
use e3_events::{HistoryProgress, TimestampClaim};
use libp2p::PeerId;
use rand::seq::SliceRandom;
use std::sync::Arc;
use std::time::Duration;

/// Attempts for each history page from a peer that no later peer can replace, and the delay
/// before the first retry. A replaceable peer gets one attempt.
const SYNC_FETCH_MAX_RETRIES: u32 = 3;
const SYNC_FETCH_RETRY_TIMEOUT: Duration = Duration::from_secs(5);
/// If a historical sync fetch fails, wait this long for a fresh connection before retrying anyway
/// against currently connected peers.
const SYNC_RECOVERY_RETRY_INTERVAL: Duration = Duration::from_secs(15);
/// Number of recovery rounds to try for failed aggregates after the initial fetch pass.
const SYNC_RECOVERY_MAX_ATTEMPTS: usize = 3;
/// Peers whose histories a node merges for each aggregate.
const HISTORY_SOURCES: usize = 2;
/// Peers a node asks for one aggregate before it accepts history that no peer observed live.
const MAX_HISTORY_PEERS: usize = 4;
/// Fetch time kept back for each source that a failed source leaves the node short of.
const SOURCE_RESERVE: Duration = Duration::from_secs(60);
/// Least fetch time that a source that another peer can replace gets.
const MIN_SOURCE_TIME: Duration = Duration::from_secs(30);
/// Most fetch time of a peer that the node asks, once it has its sources, only because none of
/// them observed the range live. Such a peer also gets at most half of the time left.
const PROBE_TIME: Duration = Duration::from_secs(30);
/// Most events of one page of the node's own stored history that it reads for the timestamp check.
const STORED_PAGE_EVENTS: u64 = 1_000;
/// Most bytes of one such page.
const STORED_PAGE_BYTES: u64 = 8 * 1024 * 1024;
/// Deadline for the node's event store to answer one such page.
const STORED_PAGE_TIMEOUT: Duration = Duration::from_secs(30);
/// Most timestamps that the node keeps from its own stored history for the check, over all
/// aggregates. The history after the snapshot cursors is short; a longer one fails the fetch
/// rather than grow without bound.
const MAX_STORED_CLAIMS: usize = 100_000;

/// What a peer's history must fit at this node.
pub(in crate::actors::net_sync_manager) struct HistoryBounds {
    pub(in crate::actors::net_sync_manager) max_bytes: usize,
    /// The latest event time that the node accepts now: the current time plus its clock-drift
    /// allowance. The node publishes the history at its latest event time and applies the
    /// allowance again then; it has only grown since a source was checked.
    pub(in crate::actors::net_sync_manager) latest_ts: LatestTs,
    /// The node's event store. A peer's event must not take the timestamp of a stored event.
    pub(in crate::actors::net_sync_manager) eventstore: Recipient<EventStoreQueryBy<TsAgg>>,
}

/// One aggregate's history from its sources, and the admitted peers that the node can still ask
/// for the live-history hint.
pub(in crate::actors::net_sync_manager) struct AggregateHistory {
    range: HistoryRange,
    merged: MergedEvents,
    limit: HistorySize,
    /// Whether a peer that served the history observed the whole range live: its `observed_from`
    /// is at or before `since`.
    vouched: bool,
    /// Peers that the node has not asked, as many as keep it within [`MAX_HISTORY_PEERS`].
    further: Vec<PeerId>,
}

impl AggregateHistory {
    /// An empty history of `aggregate_id` after `since`, at a node that stores `stored` there and
    /// accepts event times up to `latest_ts`.
    pub(in crate::actors::net_sync_manager) fn new(
        aggregate_id: AggregateId,
        since: u128,
        stored: Arc<HashMap<u128, TimestampClaim>>,
        latest_ts: LatestTs,
    ) -> Self {
        Self {
            range: HistoryRange {
                aggregate_id,
                since,
                stored,
                latest_ts,
            },
            merged: MergedEvents::default(),
            limit: MAX_KEPT_HISTORY,
            vouched: false,
            further: Vec::new(),
        }
    }

    fn with_max_bytes(mut self, max_bytes: usize) -> Self {
        self.limit.bytes = max_bytes;
        self
    }

    pub(in crate::actors::net_sync_manager) fn size(&self) -> HistorySize {
        self.merged.size()
    }

    /// The merged events in timestamp order. A history that no peer observed live may be
    /// incomplete, which is logged.
    pub(in crate::actors::net_sync_manager) fn into_events(
        self,
    ) -> Vec<InterfoldEvent<Unsequenced>> {
        if !self.vouched {
            warn!(
                aggregate_id = %self.range.aggregate_id,
                since = self.range.since,
                "No peer observed the requested history range live; it may be incomplete"
            );
        }
        self.merged.into_events()
    }
}

fn held(histories: &[AggregateHistory]) -> HistorySize {
    histories.iter().map(AggregateHistory::size).sum()
}

/// Fetch one aggregate's history from several admitted peers and merge it by event ID.
///
/// A peer can lack part of the range, for example after a restart or a reset, and still answer
/// `Done`. So the node needs two sources, each asked from `since` with every page pinned to that
/// peer, and keeps the union. A peer that fails is replaced by another one, and the fetch fails
/// when the listed peers do not supply two sources, so that recovery asks again; one connected
/// peer serves alone. A peer that a later peer can replace gets one attempt per page, and the fetch
/// time less a reserve for the sources that would replace it, so slow or silent peers cannot use up
/// the deadline before the node reaches a healthy one. While none of the sources observed the
/// whole range live, [`ask_further_peers`] can ask more peers once every aggregate has its sources.
/// `held_elsewhere` is the history that the fetch holds for other aggregates.
pub(in crate::actors::net_sync_manager) async fn fetch_historical_events_for_aggregate(
    net_cmds: &mpsc::Sender<NetCommand>,
    net_events: &NetEventSubscriber,
    history: AggregateHistory,
    deadline: &mut FetchDeadline,
    network: &NetworkPolicy,
    held_elsewhere: HistorySize,
) -> Result<AggregateHistory> {
    let mut peers = deadline
        .within(admitted_peers(net_cmds, net_events))
        .await?;
    ensure!(!peers.is_empty(), "No connected peers available");
    peers.shuffle(&mut rand::rng());
    fetch_history_from_peers(
        net_cmds,
        net_events,
        peers,
        history,
        deadline,
        network,
        held_elsewhere,
    )
    .await
}

/// Fetch one aggregate's history from its sources among `peers`, in their order, into the empty
/// `history`, as [`fetch_historical_events_for_aggregate`] describes.
pub(in crate::actors::net_sync_manager) async fn fetch_history_from_peers(
    net_cmds: &mpsc::Sender<NetCommand>,
    net_events: &NetEventSubscriber,
    peers: Vec<PeerId>,
    mut history: AggregateHistory,
    deadline: &mut FetchDeadline,
    network: &NetworkPolicy,
    held_elsewhere: HistorySize,
) -> Result<AggregateHistory> {
    let aggregate_id = history.range.aggregate_id;
    let since = history.range.since;
    let mut sources = 0usize;
    let mut last_error = None;
    let candidates = peers.len().min(MAX_HISTORY_PEERS);
    let required = HISTORY_SOURCES.min(candidates);
    let mut peers = peers.into_iter().take(MAX_HISTORY_PEERS).enumerate();
    for (index, peer) in peers.by_ref() {
        let later = candidates - index - 1;
        if sources + later + 1 < required {
            break;
        }
        let requester = DirectRequester::builder(net_cmds.clone(), net_events.clone())
            .max_retries(attempts_per_page(later, sources))
            .retry_timeout(SYNC_FETCH_RETRY_TIMEOUT)
            .build();
        let source_time = source_time(later, sources, deadline.remaining()?);
        let room = history.limit.minus(held_elsewhere.plus(history.size()));
        let fetched = fetch_validated_history(
            requester,
            peer,
            &history,
            deadline,
            network,
            source_time,
            room,
        )
        .await;
        match fetched {
            Ok((kept, observed_from)) => {
                sources += 1;
                history.vouched |= observed_from.is_some_and(|observed| observed <= since);
                // Two sources that conflict give no way to tell which one is wrong, so the
                // aggregate fails and recovery asks again.
                history.merged.extend(kept)?;
                if sources == required {
                    break;
                }
            }
            Err(error) => {
                if deadline.has_passed() {
                    return Err(error);
                }
                warn!(%peer, %aggregate_id, "History fetch from a peer failed: {error:#}");
                last_error = Some(error);
            }
        }
    }
    if sources < required {
        let error =
            last_error.unwrap_or_else(|| anyhow::anyhow!("No admitted peer served the history"));
        return Err(error.context(format!(
            "{sources} of the {required} history sources that the node needs served it"
        )));
    }
    history.further = peers.map(|(_, peer)| peer).collect();
    Ok(history)
}

/// Ask further peers for an aggregate whose sources did not observe its range live, until one
/// did, as long as the deadline allows. The node does this only after every aggregate has its
/// sources, so these optional reads cannot leave a required one without time. Each peer gets
/// one attempt per page and at most [`PROBE_TIME`] and half of the time left. A peer that fails, that
/// serves a different payload under an event ID that the sources served, or that puts another
/// event at the timestamp of a source's event, adds nothing: the sources stand, and the history
/// keeps its incompleteness warning.
pub(in crate::actors::net_sync_manager) async fn ask_further_peers(
    history: &mut AggregateHistory,
    net_cmds: &mpsc::Sender<NetCommand>,
    net_events: &NetEventSubscriber,
    deadline: &mut FetchDeadline,
    network: &NetworkPolicy,
    held_elsewhere: HistorySize,
) {
    let aggregate_id = history.range.aggregate_id;
    for peer in std::mem::take(&mut history.further) {
        if history.vouched || deadline.has_passed() {
            return;
        }
        let Ok(remaining) = deadline.remaining() else {
            return;
        };
        let requester = DirectRequester::builder(net_cmds.clone(), net_events.clone())
            .max_retries(1)
            .retry_timeout(SYNC_FETCH_RETRY_TIMEOUT)
            .build();
        let probe_time = Some(PROBE_TIME.min(remaining / 2));
        let room = history.limit.minus(held_elsewhere.plus(history.size()));
        let fetched = fetch_validated_history(
            requester, peer, history, deadline, network, probe_time, room,
        )
        .await;
        let (kept, observed_from) = match fetched {
            Ok(fetched) => fetched,
            Err(error) => {
                warn!(%peer, %aggregate_id, "History fetch from a further peer failed: {error:#}");
                continue;
            }
        };
        if let Err(error) = history.merged.extend(kept) {
            warn!(%peer, %aggregate_id, "History from a further peer is not used: {error:#}");
            continue;
        }
        history.vouched |= observed_from.is_some_and(|observed| observed <= history.range.since);
    }
}

/// What one peer's history adds to `history`, checked, with one copy of each event, and its
/// live-history time.
async fn fetch_validated_history(
    requester: DirectRequester<WithoutPeer>,
    peer: PeerId,
    history: &AggregateHistory,
    deadline: &mut FetchDeadline,
    network: &NetworkPolicy,
    source_time: Option<Duration>,
    room: HistorySize,
) -> Result<(Additions, Option<u128>)> {
    let mut source = SourceHistory::new(&history.range, &history.merged, network, room);
    let requester = requester.to(PeerTarget::Specific(peer));
    let observed_from = fetch_source(&requester, &mut source, deadline, source_time).await?;
    Ok((source.finish()?, observed_from))
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

/// The claims on their timestamps of the records that the node's store of `aggregate_id` holds at
/// or after `since`, including legacy records of another aggregate, read in pages. More than
/// `capacity` of them fail the read.
pub(in crate::actors::net_sync_manager) async fn stored_event_ids(
    eventstore: &Recipient<EventStoreQueryBy<TsAgg>>,
    aggregate_id: AggregateId,
    since: u128,
    capacity: usize,
) -> Result<HashMap<u128, TimestampClaim>> {
    let mut stored = HashMap::new();
    let mut from = since;
    loop {
        let (recipient, response) = e3_utils::actix::channel::oneshot::<EventStoreQueryResponse>();
        eventstore
            .try_send(
                EventStoreQueryBy::<TsAgg>::new(
                    CorrelationId::new(),
                    HashMap::from([(aggregate_id, from)]),
                    recipient,
                )
                .with_limit(STORED_PAGE_EVENTS)
                .with_max_bytes(STORED_PAGE_BYTES)
                .in_timestamp_order()
                // A legacy record of another aggregate in this store is not the aggregate's
                // event, but it holds its timestamp in the store.
                .with_misrouted(),
            )
            .context("the event store did not take the read of this node's stored history")?;
        let response = tokio::time::timeout(STORED_PAGE_TIMEOUT, response)
            .await
            .context("the event store did not answer the read of this node's stored history")?
            .context("the event store dropped the read of this node's stored history")?;
        let progress = response.history();
        for event in response.into_events()? {
            stored.insert(event.ts(), TimestampClaim::of(&event)?);
        }
        ensure!(
            stored.len() <= capacity,
            "this node stores more than {capacity} events after the history cursors"
        );
        match progress {
            Some(HistoryProgress {
                exhausted: true, ..
            }) => return Ok(stored),
            Some(HistoryProgress {
                last_scanned_ts: Some(last),
                ..
            }) if last < u128::MAX => from = last + 1,
            _ => bail!(
                "the event store read this node's stored history of aggregate {aggregate_id} \
                 without progress"
            ),
        }
    }
}

pub(in crate::actors::net_sync_manager) async fn handle_sync_request_event(
    net_cmds: mpsc::Sender<NetCommand>,
    net_events: NetEventSubscriber,
    event: TypedEvent<HistoricalNetSyncStart>,
    address: impl Into<Recipient<TypedEvent<SyncRequestSucceeded>>>,
    wait_for_event: bool,
    network: NetworkPolicy,
    bounds: HistoryBounds,
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

    let mut histories: Vec<AggregateHistory> = Vec::new();
    let mut failed_aggregates: Vec<AggregateId> = Vec::new();
    let mut last_error: Option<anyhow::Error> = None;
    let mut deadline = FetchDeadline::production();
    // A peer's event must not take the timestamp of an event that the node stores after the
    // cursor, or of one that startup publishes with the history. The read counts against the
    // fetch deadline.
    let mut stored = HashMap::new();
    let mut capacity = MAX_STORED_CLAIMS;
    for (aggregate_id, since) in &sync_cursor {
        let mut claims = deadline
            .within(stored_event_ids(
                &bounds.eventstore,
                *aggregate_id,
                *since,
                capacity,
            ))
            .await?;
        capacity -= claims.len();
        for (ts, claim) in event.reserved.get(aggregate_id).into_iter().flatten() {
            claims.entry(*ts).or_insert(*claim);
        }
        stored.insert(*aggregate_id, Arc::new(claims));
    }
    let empty_history = |aggregate_id: AggregateId, since: u128| {
        AggregateHistory::new(
            aggregate_id,
            since,
            stored.get(&aggregate_id).cloned().unwrap_or_default(),
            bounds.latest_ts.clone(),
        )
        .with_max_bytes(bounds.max_bytes)
    };

    for (aggregate_id, since) in &sync_cursor {
        info!(
            "Requesting batched events for aggregate_id={} since={}",
            aggregate_id, since
        );
        match fetch_historical_events_for_aggregate(
            &net_cmds,
            &net_events,
            empty_history(*aggregate_id, *since),
            &mut deadline,
            &network,
            held(&histories),
        )
        .await
        {
            Ok(history) => {
                info!(
                    "Received {} events for aggregate_id={}",
                    history.size().events,
                    aggregate_id
                );
                histories.push(history);
            }
            Err(e) => {
                if deadline.has_passed() {
                    return Err(e).context("historical net sync exhausted its deadline");
                }
                warn!(
                    "Failed to fetch events for aggregate_id={}: {e:#}. Continuing with available events.",
                    aggregate_id
                );
                last_error = Some(e);
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
            let wait = match deadline.remaining() {
                Ok(remaining) => SYNC_RECOVERY_RETRY_INTERVAL.min(remaining),
                Err(error) => {
                    return Err(error).context("historical net sync exhausted its deadline")
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
                    empty_history(aggregate_id, since),
                    &mut deadline,
                    &network,
                    held(&histories),
                )
                .await
                {
                    Ok(history) => {
                        info!(
                            attempt = recovery_attempt,
                            "Retry succeeded: {} events for aggregate_id={}",
                            history.size().events,
                            aggregate_id
                        );
                        histories.push(history);
                    }
                    Err(e) => {
                        if deadline.has_passed() {
                            return Err(e).context("historical net sync exhausted its deadline");
                        }
                        warn!(
                            attempt = recovery_attempt,
                            "Retry failed for aggregate_id={}: {e:#}", aggregate_id
                        );
                        last_error = Some(e);
                        still_failed.push(aggregate_id);
                    }
                }
            }

            failed_aggregates = still_failed;
        }

        if !failed_aggregates.is_empty() {
            let error = last_error
                .unwrap_or_else(|| anyhow::anyhow!("no admitted peer served the history"));
            return Err(error.context(format!(
                "failed to fetch historical net events for aggregates {:?} after {} recovery attempts",
                failed_aggregates, SYNC_RECOVERY_MAX_ATTEMPTS
            )));
        }
    }

    // Every aggregate has its sources. Only now does the node ask further peers for the
    // live-history hint, in the time left: their failures fail nothing.
    let mut held_now = held(&histories);
    let mut all_events: Vec<InterfoldEvent<Unsequenced>> = Vec::new();
    for mut history in histories {
        let elsewhere = held_now.minus(history.size());
        ask_further_peers(
            &mut history,
            &net_cmds,
            &net_events,
            &mut deadline,
            &network,
            elsewhere,
        )
        .await;
        held_now = elsewhere.plus(history.size());
        all_events.extend(history.into_events());
    }
    let latest_timestamp = all_events.iter().map(|event| event.ts()).max().unwrap_or(0);

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
