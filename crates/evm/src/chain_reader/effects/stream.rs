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
    ingestion_status: crate::EvmIngestionStatus,
) {
    let chain_id = provider.chain_id();
    ingestion_status.configure(chain_id, filters.confirmations());
    let mut timestamp_tracker = TimestampTracker::new();
    let mut backoff = Backoff::new(MAX_RECONNECT_DELAY_SECS);

    // ── Phase 1: Historical sync (must succeed, fatal on failure) ──

    let (raw_head, head_timestamp_secs) = match read_rpc_head(&provider).await {
        Ok(head) => head,
        Err(e) => {
            ingestion_status.record_error(format!("failed to read RPC head: {e}"));
            error!(chain_id, error = %e, "Failed to get latest block number");
            bus.err(EType::Evm, anyhow!(e));
            return;
        }
    };
    let latest_block = crate::domain::reorg::confirmed_head(raw_head, filters.confirmations());
    ingestion_status.record_progress(
        chain_id,
        filters.confirmations(),
        raw_head,
        filters.start_block.saturating_sub(1).min(latest_block),
        head_timestamp_secs,
    );

    let last_id = match fetch_logs_chunked(
        provider.provider(),
        &filters.historical,
        filters.start_block,
        latest_block,
        chain_id,
        &next,
        &mut timestamp_tracker,
    )
    .await
    {
        Ok(id) => {
            ingestion_status.record_progress(
                chain_id,
                filters.confirmations(),
                raw_head,
                latest_block,
                head_timestamp_secs,
            );
            info!(chain_id, "Historical sync succeeded");
            id
        }
        Err(e) => {
            ingestion_status.record_error(format!("historical sync failed: {e:#}"));
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
        )
        .await
        {
            Ok(_) => {
                if let Err(error) = refresh_rpc_progress(
                    &current_provider,
                    &ingestion_status,
                    last_block,
                    filters.confirmations(),
                )
                .await
                {
                    ingestion_status.record_error(format!("RPC progress check failed: {error:#}"));
                    consecutive_failures += 1;
                    warn!(chain_id, %error, consecutive_failures, "RPC progress check failed");
                    if consecutive_failures >= MAX_RETRIES_BEFORE_RECREATE {
                        let Some(p) = get_new_provider_or_exit(
                            &provider_factory,
                            &mut shutdown,
                            chain_id,
                            &mut backoff,
                            bus,
                            &ingestion_status,
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
                backoff.reset();
                consecutive_failures = 0;
            }
            Err(e) => {
                ingestion_status.record_error(format!("confirmed backfill failed: {e:#}"));
                consecutive_failures += 1;
                warn!(chain_id, error = %e, consecutive_failures, "Backfill failed");
                if consecutive_failures >= MAX_RETRIES_BEFORE_RECREATE {
                    let Some(p) = get_new_provider_or_exit(
                        &provider_factory,
                        &mut shutdown,
                        chain_id,
                        &mut backoff,
                        bus,
                        &ingestion_status,
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
                                        ingestion_status.record_error(format!(
                                            "live log processing failed: {error:#}"
                                        ));
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
                                    ingestion_status.record_error("live event stream ended");
                                    consecutive_failures += 1;
                                    warn!(chain_id, consecutive_failures, "Live event stream ended, will reconnect");
                                    break;
                                }
                            }
                        }
                        _ = confirmation_poll.tick() => {
                            if let Err(error) = backfill_to_head(
                                current_provider.provider(),
                                &filters.current,
                                chain_id,
                                &next,
                                &mut timestamp_tracker,
                                &mut last_block,
                                filters.confirmations(),
                            ).await {
                                ingestion_status.record_error(format!(
                                    "confirmed live-log backfill failed: {error:#}"
                                ));
                                consecutive_failures += 1;
                                warn!(
                                    chain_id,
                                    error = %error,
                                    consecutive_failures,
                                    "Confirmed live-log backfill failed; reconnecting"
                                );
                                break;
                            }
                            if let Err(error) = refresh_rpc_progress(
                                &current_provider,
                                &ingestion_status,
                                last_block,
                                filters.confirmations(),
                            ).await {
                                ingestion_status.record_error(format!(
                                    "RPC progress check failed: {error:#}"
                                ));
                                consecutive_failures += 1;
                                warn!(chain_id, %error, consecutive_failures, "RPC progress check failed");
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
                        &ingestion_status,
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
                ingestion_status.record_error(format!("live subscription failed: {e:#}"));
                consecutive_failures += 1;
                error!(chain_id, error = %e, consecutive_failures, "Failed to subscribe to live events");
                if consecutive_failures >= MAX_RETRIES_BEFORE_RECREATE {
                    let Some(p) = get_new_provider_or_exit(
                        &provider_factory,
                        &mut shutdown,
                        chain_id,
                        &mut backoff,
                        bus,
                        &ingestion_status,
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

async fn read_rpc_head<P: Provider + Clone>(
    provider: &EthProvider<P>,
) -> anyhow::Result<(u64, u64)> {
    let raw_head = provider.provider().get_block_number().await?;
    let block = provider
        .provider()
        .get_block_by_number(raw_head.into())
        .await?
        .ok_or_else(|| anyhow!("RPC returned no block at head {raw_head}"))?;
    Ok((raw_head, block.header.timestamp))
}

async fn refresh_rpc_progress<P: Provider + Clone>(
    provider: &EthProvider<P>,
    status: &crate::EvmIngestionStatus,
    cursor: u64,
    confirmations: u64,
) -> anyhow::Result<()> {
    let (raw_head, head_timestamp_secs) = read_rpc_head(provider).await?;
    status.record_progress(
        provider.chain_id(),
        confirmations,
        raw_head,
        cursor,
        head_timestamp_secs,
    );
    Ok(())
}
