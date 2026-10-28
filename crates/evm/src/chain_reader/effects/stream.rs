// SPDX-License-Identifier: LGPL-3.0-only

//! Historical catch-up and confirmed live-log ingestion loop.

use super::provider_recovery::{get_new_provider_or_exit, sleep_or_shutdown, ReaderStop};
use super::*;

#[instrument(name = "evm_interface", skip_all)]
pub(in crate::actors::evm_read_interface) async fn stream_from_evm<
    P: Provider + Clone + 'static,
>(
    provider: EthProvider<P>,
    provider_factory: Option<ProviderFactory<P>>,
    next: EvmEventProcessor,
    mut shutdown: oneshot::Receiver<()>,
    bus: &BusHandle,
    filters: Filters,
    progress: Option<IngestionProgressSink>,
) {
    let chain_id = provider.chain_id();
    let stop = read_chain(
        provider,
        provider_factory,
        &next,
        &mut shutdown,
        bus,
        filters,
        progress.as_ref(),
    )
    .await;
    if let ReaderStop::Failed(reason) = stop {
        // The gateway fails closed on this message: startup fails at once, and a running node
        // exits so that its supervisor restarts it.
        error!(chain_id, %reason, "Chain reader stopped");
        let stopped = InterfoldEvmEvent::ReaderStopped(EvmReaderStopped::new(chain_id, &reason));
        match tokio::time::timeout(STOP_REPORT_TIMEOUT, next.send(stopped)).await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => bus.err(
                EType::Evm,
                anyhow!(
                    "could not report that the chain {chain_id} reader stopped ({reason}): {error}"
                ),
            ),
            Err(_) => bus.err(
                EType::Evm,
                anyhow!(
                    "timed out while reporting that the chain {chain_id} reader stopped: {reason}"
                ),
            ),
        }
    }
}

async fn read_chain<P: Provider + Clone + 'static>(
    provider: EthProvider<P>,
    provider_factory: Option<ProviderFactory<P>>,
    next: &EvmEventProcessor,
    shutdown: &mut oneshot::Receiver<()>,
    bus: &BusHandle,
    filters: Filters,
    progress: Option<&IngestionProgressSink>,
) -> ReaderStop {
    let chain_id = provider.chain_id();
    let mut timestamp_tracker = TimestampTracker::new();
    let mut backoff = Backoff::new(MAX_RECONNECT_DELAY_SECS);
    // One window for the whole session. The provider's range cap is discovered during the
    // historical sync and then reused by every backfill, so a narrow provider is paid for once
    // rather than on every reconnect.
    let mut log_window = filters.log_window();
    let mut current_provider = provider;
    let mut consecutive_failures: u32 = 0;

    // ── Phase 1: Historical sync ──
    //
    // The node needs the full history, so a failure is retried like a failed backfill below,
    // including provider recreation. Startup has its own deadline for an RPC that never recovers.

    let mut sync = HistoricalSync::new(filters.start_block);
    let latest_block = loop {
        match sync
            .run(
                current_provider.provider(),
                &filters.historical,
                filters.confirmations(),
                chain_id,
                next,
                &mut timestamp_tracker,
                &mut log_window,
                progress,
            )
            .await
        {
            Ok(head) => break head,
            Err(e) => {
                consecutive_failures += 1;
                warn!(chain_id, error = %e, consecutive_failures, "Historical sync failed, retrying");
                if consecutive_failures >= MAX_RETRIES_BEFORE_RECREATE {
                    current_provider = match get_new_provider_or_exit(
                        &provider_factory,
                        shutdown,
                        chain_id,
                        &mut backoff,
                    )
                    .await
                    {
                        Ok(p) => p,
                        Err(stop) => return stop,
                    };
                    consecutive_failures = 0;
                    continue;
                }
                if sleep_or_shutdown(backoff.next_delay(), shutdown).await {
                    return ReaderStop::Shutdown;
                }
            }
        }
    };
    info!(chain_id, "Historical sync succeeded");
    backoff.reset();
    consecutive_failures = 0;

    next.do_send(InterfoldEvmEvent::HistoricalSyncComplete(
        HistoricalSyncComplete::new(chain_id, sync.last_id()),
    ));

    // ── Phase 2: Live event loop with provider lifecycle management ──
    //
    // Single flat loop: backfill → subscribe → consume stream → repeat.
    // On transport death, immediately recreate the provider.
    // On transient errors, retry with exponential backoff.

    let mut last_block = latest_block;

    loop {
        // Step 1: Backfill any blocks missed since last_block
        match backfill_to_head(
            current_provider.provider(),
            &filters.current,
            chain_id,
            next,
            &mut timestamp_tracker,
            &mut last_block,
            filters.confirmations(),
            &mut log_window,
            progress,
        )
        .await
        {
            Ok(_) => {
                backoff.reset();
                consecutive_failures = 0;
            }
            Err(e) => {
                consecutive_failures += 1;
                warn!(chain_id, error = %e, consecutive_failures, "Backfill failed");
                if consecutive_failures >= MAX_RETRIES_BEFORE_RECREATE {
                    current_provider = match get_new_provider_or_exit(
                        &provider_factory,
                        shutdown,
                        chain_id,
                        &mut backoff,
                    )
                    .await
                    {
                        Ok(p) => p,
                        Err(stop) => return stop,
                    };
                    consecutive_failures = 0;
                    continue;
                }
                if sleep_or_shutdown(backoff.next_delay(), shutdown).await {
                    return ReaderStop::Shutdown;
                }
                continue;
            }
        }

        // Step 2: Subscribe to live events
        let sub_result = current_provider
            .provider()
            .subscribe_logs(&filters.current)
            .await
            .map_err(|e| anyhow!("{}", e));

        match sub_result {
            Ok(subscription) => {
                backoff.reset();
                consecutive_failures = 0;
                let sub_id: B256 = *subscription.local_id();
                let mut stream = subscription.into_stream();
                info!(chain_id, "Live event subscription active");

                let stop = consume_live_logs(
                    current_provider.provider(),
                    &mut stream,
                    &filters.current,
                    chain_id,
                    next,
                    &mut timestamp_tracker,
                    &mut last_block,
                    filters.confirmations(),
                    &mut log_window,
                    Duration::from_secs(CONFIRMED_BACKFILL_INTERVAL_SECS),
                    shutdown,
                    progress,
                )
                .await;
                match stop {
                    LiveStop::Shutdown => {
                        info!("Shutdown signal received, stopping EVM stream");
                        let _ = current_provider.provider().unsubscribe(sub_id).await;
                        return ReaderStop::Shutdown;
                    }
                    LiveStop::StreamEnded => {
                        consecutive_failures += 1;
                        warn!(
                            chain_id,
                            consecutive_failures, "Live event stream ended, will reconnect"
                        );
                    }
                    LiveStop::LiveLogBackfillFailed(error) => {
                        consecutive_failures += 1;
                        warn!(
                            chain_id,
                            error = %error,
                            consecutive_failures,
                            "Backfill after a live log failed; reconnecting"
                        );
                    }
                    LiveStop::PollBackfillFailed(error) => {
                        consecutive_failures += 1;
                        warn!(
                            chain_id,
                            error = %error,
                            consecutive_failures,
                            "Confirmed live-log backfill failed; reconnecting"
                        );
                    }
                }

                if consecutive_failures >= MAX_RETRIES_BEFORE_RECREATE {
                    current_provider = match get_new_provider_or_exit(
                        &provider_factory,
                        shutdown,
                        chain_id,
                        &mut backoff,
                    )
                    .await
                    {
                        Ok(p) => p,
                        Err(stop) => return stop,
                    };
                    consecutive_failures = 0;
                } else if consecutive_failures > 0
                    && sleep_or_shutdown(backoff.next_delay(), shutdown).await
                {
                    return ReaderStop::Shutdown;
                }
            }
            Err(e) => {
                consecutive_failures += 1;
                error!(chain_id, error = %e, consecutive_failures, "Failed to subscribe to live events");
                if consecutive_failures >= MAX_RETRIES_BEFORE_RECREATE {
                    current_provider = match get_new_provider_or_exit(
                        &provider_factory,
                        shutdown,
                        chain_id,
                        &mut backoff,
                    )
                    .await
                    {
                        Ok(p) => p,
                        Err(stop) => return stop,
                    };
                    consecutive_failures = 0;
                } else {
                    bus.err(EType::Evm, anyhow!("{}", e));
                    if sleep_or_shutdown(backoff.next_delay(), shutdown).await {
                        return ReaderStop::Shutdown;
                    }
                }
            }
        }
    }
}
