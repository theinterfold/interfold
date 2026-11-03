// SPDX-License-Identifier: LGPL-3.0-only

//! Bounded collection of per-chain historical EVM results.

use super::*;

pub async fn collect_historical_evm_events(
    mut receiver: Receiver<HistoricalEvmEventsReceived>,
    config: &EvmEventConfig,
) -> Result<Vec<InterfoldEvent<Unsequenced>>> {
    let mut collector = HistoricalEvmCollector::new(config);
    let progress_interval = Duration::from_secs(30);

    while !collector.is_complete() {
        match tokio::time::timeout(progress_interval, receiver.recv()).await {
            Ok(Some(mut msg)) => {
                let chain_id = msg.chain_id;
                if let CollectOutcome::Recorded {
                    chains_received,
                    chains_expected,
                } = collector.record(&mut msg)
                {
                    info!(
                        chain_id,
                        chains_received, chains_expected, "Received historical events from chain"
                    );
                }
            }
            Ok(None) => {
                let remaining = collector.remaining();
                bail!("historical EVM event channel closed before chains reported: {remaining:?}");
            }
            Err(_) => {
                info!(
                    remaining = ?collector.remaining(),
                    "Still waiting for historical events from chains"
                );
            }
        }
    }

    Ok(collector.into_events())
}
