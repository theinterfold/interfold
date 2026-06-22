// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use std::time::Duration;

use crate::{
    cli::{Cli, RemoteCli},
    owo,
};
use anyhow::Result;
use e3_ciphernode_builder::CiphernodeHandle;
use e3_config::AppConfig;
use e3_console::Console;
use e3_daemon_server::start_daemon_server;
use e3_events::{prelude::*, Shutdown};
use e3_utils::{colorize, Color};
use tokio::signal::unix::{signal, SignalKind};
use tracing::{error, info, instrument};

#[instrument(skip_all)]
pub async fn execute(mut config: AppConfig, peers: Vec<String>) -> Result<()> {
    // Register signal listeners immediately at startup
    let shutdown = shutdown_signal();
    tokio::pin!(shutdown);

    owo();

    // Cross-host fence: ensure only one instance runs against this data directory.
    // Acquired *before* binding the control port or spawning background work so a second
    // instance fails fast instead of racing on the shared data directory.
    // Held for the lifetime of this function (the running process); released on exit.
    let _fence = e3_entrypoint::fence::ProcessFence::acquire(&config.db_file(), &config.name())?;

    launch_socket_server(config.ctrl_port());

    let node = tokio::select! {
        // build the ciphernode and if it completes first return the result
        result = build_ciphernode(&mut config, peers) => result,
        // if the shutdown signal completes first then do shutdown without the node
        _ = &mut shutdown => {
            graceful_shutdown(None).await;
            return Ok(());
        }
    }?;

    if let Some(dashboard_port) = config.dashboard_port() {
        let chains = node
            .aggregate_ids()
            .iter()
            .copied()
            .filter(|aggregate| *aggregate != 0)
            .map(|aggregate| {
                let id = aggregate as u64;
                let name = config
                    .chains()
                    .iter()
                    .find(|chain| chain.chain_id == Some(id))
                    .map(|chain| chain.name.clone())
                    .unwrap_or_else(|| format!("Chain {id}"));
                e3_dashboard::DashboardChain { id, name }
            })
            .collect();
        let runtime = e3_dashboard::DashboardRuntime {
            node_name: config.name(),
            address: node.address.clone(),
            peer_id: node.peer_id.to_string(),
            quic_port: config.quic_port(),
            dashboard_port,
            version: env!("CARGO_PKG_VERSION").to_owned(),
            chains,
        };
        let state = e3_dashboard::DashboardState::new(
            runtime,
            node.eventstore(),
            node.aggregate_ids().to_vec(),
            node.network_status(),
            config.chains().clone(),
        );
        tokio::task::spawn_local(async move {
            if let Err(error) = e3_dashboard::start_dashboard(dashboard_port, state).await {
                error!(%error, "node dashboard stopped");
            }
        });
        info!("Dashboard available at http://127.0.0.1:{dashboard_port}");
    }

    info!(
        "LAUNCHING CIPHERNODE: ({}/{}/{})",
        config.name(),
        node.address,
        node.peer_id
    );

    shutdown.await;
    graceful_shutdown(Some(node)).await;

    Ok(())
}

/// Launch a socket server to read RemoteCli commands
pub fn launch_socket_server(ctrl_port: u16) {
    // Setup socket server for daemon
    tokio::task::spawn_local(start_daemon_server(ctrl_port, |body| async move {
        let (out, mut rx) = Console::channel();
        info!("CMD: {}", &colorize(&body, Color::Blue));
        let remote_cli: RemoteCli = serde_json::from_str(&body)?;
        let cli: Cli = remote_cli.try_into()?;
        let config_result = cli.load_config();
        cli.execute(out, config_result).await?;

        let mut output = String::new();
        while let Some(msg) = rx.recv().await {
            output.push_str(&format!("{msg}\n"));
        }
        Ok(output)
    }));
}

pub async fn build_ciphernode(
    config: &mut AppConfig,
    peers: Vec<String>,
) -> Result<CiphernodeHandle> {
    // add cli peers to the config
    config.add_peers(peers);

    let node = e3_entrypoint::start::start::execute(config).await?;

    Ok(node)
}

pub fn shutdown_signal() -> impl std::future::Future<Output = ()> {
    let mut sigint =
        signal(SignalKind::interrupt()).expect("Failed to create SIGINT signal stream");
    let mut sigterm =
        signal(SignalKind::terminate()).expect("Failed to create SIGTERM signal stream");

    async move {
        tokio::select! {
            _ = sigint.recv() => info!("SIGINT received"),
            _ = sigterm.recv() => info!("SIGTERM received"),
        }
    }
}

pub async fn graceful_shutdown(node: Option<CiphernodeHandle>) {
    info!("initiating graceful shutdown...");

    if let Some(node) = node {
        if let Err(e) = node.bus.publish_without_context(Shutdown) {
            error!("Shutdown failed to publish! {e}");
        }
    }

    tokio::time::sleep(Duration::from_secs(2)).await;
    info!("Graceful shutdown complete");
    if let Some(logs) = e3_logger::LogCollector::global() {
        logs.flush();
    }
}
