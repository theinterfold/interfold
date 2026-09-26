// SPDX-License-Identifier: LGPL-3.0-only

use anyhow::{Context, Result};
use e3_config::AppConfig;
use e3_entrypoint::{fence::ProcessFence, net::bootstrap};
use std::time::Duration;
use tracing::info;

use crate::start::shutdown_signal;

pub async fn execute(mut config: AppConfig, peers: Vec<String>) -> Result<()> {
    let shutdown = shutdown_signal();
    tokio::pin!(shutdown);
    let _fence = ProcessFence::acquire(&config.db_file(), &config.name())?;
    config.add_peers(peers)?;

    let mut interface = tokio::select! {
        result = tokio::time::timeout(
            Duration::from_secs(config.startup_timeout_secs()),
            bootstrap::create(&config),
        ) => result.context("bootstrap startup timed out")??,
        _ = &mut shutdown => return Ok(()),
    };

    // The swarm owns only ephemeral network state. Dropping it closes the listeners and peers.
    let result = tokio::select! {
        result = interface.start() => result,
        _ = &mut shutdown => {
            info!("Stopping bootstrap-only networking");
            Ok(())
        }
    };
    if let Some(logs) = e3_logger::LogCollector::global() {
        logs.flush();
    }
    result
}
