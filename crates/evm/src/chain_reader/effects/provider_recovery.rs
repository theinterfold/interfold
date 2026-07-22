// SPDX-License-Identifier: LGPL-3.0-only

//! Provider recreation and shutdown-aware backoff.

use super::*;

pub(super) async fn sleep_or_shutdown(
    duration: Duration,
    shutdown: &mut oneshot::Receiver<()>,
) -> bool {
    select! {
        _ = tokio::time::sleep(duration) => false,
        _ = &mut *shutdown => {
            info!("Shutdown signal received during backoff");
            true
        }
    }
}

async fn recreate_provider<P: Provider + Clone + 'static>(
    factory: &ProviderFactory<P>,
    shutdown: &mut oneshot::Receiver<()>,
    chain_id: u64,
    backoff: &mut Backoff,
    ingestion_status: &crate::EvmIngestionStatus,
) -> Option<EthProvider<P>> {
    loop {
        if shutdown.try_recv().is_ok() {
            return None;
        }

        let delay = backoff.next_delay();
        warn!(
            chain_id,
            delay_secs = delay.as_secs(),
            "Waiting before provider recreation attempt"
        );
        if sleep_or_shutdown(delay, shutdown).await {
            return None;
        }

        let factory_clone = factory.clone();
        let result = retry_with_backoff(
            || {
                let f = factory_clone.clone();
                async move {
                    let provider = f().await.map_err(|e| {
                        warn!(chain_id, error = %e, "Factory failed to create provider");
                        RetryError::Retry(e)
                    })?;

                    // Health check: verify the new transport is actually alive
                    provider.provider().get_block_number().await.map_err(|e| {
                        warn!(chain_id, error = %e, "New provider failed health check");
                        RetryError::Retry(anyhow!("Health check failed: {}", e))
                    })?;

                    Ok(provider)
                }
            },
            PROVIDER_RECREATE_MAX_ATTEMPTS,
            PROVIDER_RECREATE_INITIAL_DELAY_MS,
        )
        .await;

        match result {
            Ok(new_provider) => {
                let new_chain_id = new_provider.chain_id();
                if new_chain_id != chain_id {
                    ingestion_status.record_error(format!(
                        "recreated RPC is on wrong chain: expected {chain_id}, got {new_chain_id}"
                    ));
                    error!(
                        chain_id,
                        new_chain_id, "Recreated provider is on wrong chain — fatal"
                    );
                    return None;
                }
                info!(chain_id, "Provider recreated and verified");
                backoff.reset();
                return Some(new_provider);
            }
            Err(e) => {
                ingestion_status.record_error(format!("provider recreation failed: {e:#}"));
                error!(
                    chain_id,
                    error = %e,
                    "All provider recreation attempts failed, will retry with longer backoff"
                );
                continue;
            }
        }
    }
}

pub(super) async fn get_new_provider_or_exit<P: Provider + Clone + 'static>(
    factory: &Option<ProviderFactory<P>>,
    shutdown: &mut oneshot::Receiver<()>,
    chain_id: u64,
    backoff: &mut Backoff,
    bus: &BusHandle,
    ingestion_status: &crate::EvmIngestionStatus,
) -> Option<EthProvider<P>> {
    let Some(factory) = factory else {
        error!(
            chain_id,
            "Transport died and no provider factory configured"
        );
        ingestion_status.record_error("transport died and no provider factory is configured");
        bus.err(
            EType::Evm,
            anyhow!("Transport died and no provider factory configured"),
        );
        return None;
    };
    let result = recreate_provider(factory, shutdown, chain_id, backoff, ingestion_status).await;
    if result.is_none() && shutdown.try_recv().is_err() {
        bus.err(
            EType::Evm,
            anyhow!("Provider recreation failed for chain {}", chain_id),
        );
    }
    result
}
