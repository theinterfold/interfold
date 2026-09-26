// SPDX-License-Identifier: LGPL-3.0-only

//! Historical catch-up and confirmed live-log ingestion loop.

use super::provider_recovery::{get_new_provider_or_exit, sleep_or_shutdown};
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
) {
    let chain_id = provider.chain_id();
    let mut timestamp_tracker = TimestampTracker::new();
    let mut backoff = Backoff::new(MAX_RECONNECT_DELAY_SECS);
    // One window for the whole session. The provider's range cap is discovered during the
    // historical sync and then reused by every backfill, so a narrow provider is paid for once
    // rather than on every reconnect.
    let mut log_window = LogWindow::new();

    // ── Phase 1: Historical sync (must succeed, fatal on failure) ──

    let latest_block = match provider.provider().get_block_number().await {
        Ok(bn) => crate::domain::reorg::confirmed_head(bn, filters.confirmations()),
        Err(e) => {
            error!(chain_id, error = %e, "Failed to get latest block number");
            bus.err(EType::Evm, anyhow!(e));
            return;
        }
    };

    let last_id = match fetch_logs_chunked(
        provider.provider(),
        &filters.historical,
        filters.start_block,
        latest_block,
        chain_id,
        &next,
        &mut timestamp_tracker,
        &mut log_window,
    )
    .await
    {
        Ok(id) => {
            info!(chain_id, "Historical sync succeeded");
            id
        }
        Err(e) => {
            error!(chain_id, error = %e, "Failed to fetch historical events — node cannot operate without full state, exiting");
            bus.err(EType::Evm, anyhow!(e));
            return;
        }
    };

    next.do_send(InterfoldEvmEvent::HistoricalSyncComplete(
        HistoricalSyncComplete::new(chain_id, last_id),
    ));

    // ── Phase 2: Live event loop with provider lifecycle management ──
    //
    // Single flat loop: backfill → subscribe → consume stream → repeat.
    // On transport death, immediately recreate the provider.
    // On transient errors, retry with exponential backoff.

    let mut last_block = latest_block;
    let mut current_provider = provider;
    let mut consecutive_failures: u32 = 0;

    loop {
        // Step 1: Backfill any blocks missed since last_block
        match backfill_to_head(
            current_provider.provider(),
            &filters.current,
            chain_id,
            &next,
            &mut timestamp_tracker,
            &mut last_block,
            filters.confirmations(),
            &mut log_window,
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
                    let Some(p) = get_new_provider_or_exit(
                        &provider_factory,
                        &mut shutdown,
                        chain_id,
                        &mut backoff,
                        bus,
                    )
                    .await
                    else {
                        return;
                    };
                    current_provider = p;
                    consecutive_failures = 0;
                    continue;
                }
                if sleep_or_shutdown(backoff.next_delay(), &mut shutdown).await {
                    return;
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
                let mut confirmation_poll =
                    tokio::time::interval(Duration::from_secs(CONFIRMED_BACKFILL_INTERVAL_SECS));
                confirmation_poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                // Tokio intervals tick immediately once. The outer loop already backfilled, so
                // consume that tick and wait for the configured period before querying again.
                confirmation_poll.tick().await;
                info!(chain_id, "Live event subscription active");

                loop {
                    select! {
                        maybe_log = stream.next() => {
                            match maybe_log {
                                Some(log) => {
                                    if let Err(error) = process_live_log(
                                        current_provider.provider(), log, chain_id, &next,
                                        &mut timestamp_tracker, &mut last_block,
                                        filters.confirmations(),
                                    ).await {
                                        consecutive_failures += 1;
                                        warn!(
                                            chain_id,
                                            error = %error,
                                            consecutive_failures,
                                            "Live log rejected; reconnecting for canonical backfill"
                                        );
                                        break;
                                    }
                                }
                                None => {
                                    // Stream ended (server-side close, idle timeout, etc.)
                                    consecutive_failures += 1;
                                    warn!(chain_id, consecutive_failures, "Live event stream ended, will reconnect");
                                    break;
                                }
                            }
                        }
                        _ = confirmation_poll.tick(), if filters.confirmations() > 0 => {
                            if let Err(error) = backfill_to_head(
                                current_provider.provider(),
                                &filters.current,
                                chain_id,
                                &next,
                                &mut timestamp_tracker,
                                &mut last_block,
                                filters.confirmations(),
                                &mut log_window,
                            ).await {
                                consecutive_failures += 1;
                                warn!(
                                    chain_id,
                                    error = %error,
                                    consecutive_failures,
                                    "Confirmed live-log backfill failed; reconnecting"
                                );
                                break;
                            }
                        }
                        _ = &mut shutdown => {
                            info!("Shutdown signal received, stopping EVM stream");
                            let _ = current_provider.provider().unsubscribe(sub_id).await;
                            return;
                        }
                    }
                }

                if consecutive_failures >= MAX_RETRIES_BEFORE_RECREATE {
                    let Some(p) = get_new_provider_or_exit(
                        &provider_factory,
                        &mut shutdown,
                        chain_id,
                        &mut backoff,
                        bus,
                    )
                    .await
                    else {
                        return;
                    };
                    current_provider = p;
                    consecutive_failures = 0;
                } else if consecutive_failures > 0
                    && sleep_or_shutdown(backoff.next_delay(), &mut shutdown).await
                {
                    return;
                }
            }
            Err(e) => {
                consecutive_failures += 1;
                error!(chain_id, error = %e, consecutive_failures, "Failed to subscribe to live events");
                if consecutive_failures >= MAX_RETRIES_BEFORE_RECREATE {
                    let Some(p) = get_new_provider_or_exit(
                        &provider_factory,
                        &mut shutdown,
                        chain_id,
                        &mut backoff,
                        bus,
                    )
                    .await
                    else {
                        return;
                    };
                    current_provider = p;
                    consecutive_failures = 0;
                } else {
                    bus.err(EType::Evm, anyhow!("{}", e));
                    if sleep_or_shutdown(backoff.next_delay(), &mut shutdown).await {
                        return;
                    }
                }
            }
        }
    }
}
