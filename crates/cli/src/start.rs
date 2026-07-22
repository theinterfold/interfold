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
use anyhow::{bail, Result};
use e3_ciphernode_builder::CiphernodeHandle;
use e3_config::AppConfig;
use e3_console::Console;
use e3_daemon_server::start_daemon_server;
use e3_utils::{colorize, Color};
use tokio::signal::unix::{signal, SignalKind};
use tracing::{error, info, instrument};

const SHUTDOWN_DEADLINE: Duration = Duration::from_secs(30);

#[instrument(skip_all)]
pub async fn execute(mut config: AppConfig, peers: Vec<String>) -> Result<()> {
    // Register signal listeners immediately at startup
    let shutdown = shutdown_signal();
    tokio::pin!(shutdown);

    owo();

    // Cross-host fence: ensure only one instance runs against this data directory.
    // Acquired before spawning background work so a second instance fails fast
    // instead of racing on the shared data directory.
    // Held for the lifetime of this function (the running process); released on exit.
    let _fence = e3_entrypoint::fence::ProcessFence::acquire(&config.db_file(), &config.name())?;

    let node = tokio::select! {
        // build the ciphernode and if it completes first return the result
        result = build_ciphernode(&mut config, peers) => result,
        // if the shutdown signal completes first then do shutdown without the node
        _ = &mut shutdown => {
            graceful_shutdown(None).await?;
            return Ok(());
        }
    }?;

    // A listening control socket is a service-availability signal. Do not bind
    // it until all required Ciphernode startup/readiness gates have succeeded.
    launch_socket_server(config.ctrl_port());

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
            e3_dashboard::ReadinessSources::new(
                node.store().clone(),
                node.evm_ingestion().to_vec(),
                node.evm_writers().to_vec(),
                e3_dashboard::ReadinessPolicy {
                    min_connected_peers: config.readiness_min_peers(),
                    max_rpc_poll_age_ms: config
                        .readiness_max_rpc_poll_age_secs()
                        .saturating_mul(1_000),
                    max_chain_head_age_ms: config
                        .readiness_max_chain_head_age_secs()
                        .saturating_mul(1_000),
                    max_sync_lag_blocks: config.readiness_max_sync_lag_blocks(),
                    max_outbox_age_ms: config.readiness_max_outbox_age_secs().saturating_mul(1_000),
                    max_active_e3_idle_ms: config
                        .readiness_max_active_e3_idle_secs()
                        .saturating_mul(1_000),
                },
            ),
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

    let network_supervisor = node.network_supervisor();
    let network_failure = tokio::select! {
        _ = &mut shutdown => None,
        exit = network_supervisor.wait_for_exit(), if network_supervisor.is_managed() => {
            Some(exit?)
        }
    };
    if let Some(exit) = network_failure {
        if let Err(shutdown_error) = graceful_shutdown(Some(node)).await {
            error!(%shutdown_error, "Graceful cleanup after network failure also failed");
        }
        bail!(
            "required network interface exited after readiness: {}",
            exit.reason
        );
    }

    graceful_shutdown(Some(node)).await?;

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

pub async fn graceful_shutdown(node: Option<CiphernodeHandle>) -> Result<()> {
    info!("initiating graceful shutdown...");

    let result = match node {
        Some(node) => node.shutdown(SHUTDOWN_DEADLINE).await,
        None => Ok(()),
    };

    if let Some(logs) = e3_logger::LogCollector::global() {
        logs.flush();
    }

    match result {
        Ok(()) => {
            info!("Graceful shutdown barrier complete");
            Ok(())
        }
        Err(error) => {
            error!(%error, "Graceful shutdown failed; process will exit unsuccessfully");
            Err(error)
        }
    }
}
