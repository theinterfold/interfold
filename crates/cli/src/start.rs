// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::{
    cli::{Cli, RemoteCli},
    node_v2, owo,
};
use anyhow::{bail, Context, Result};
use e3_ciphernode_config::NodeConfig;
use e3_console::Console;
use e3_daemon_server::start_daemon_server;
use e3_utils::{colorize, Color};
use tokio::signal::unix::{signal, SignalKind};
use tracing::{info, instrument, warn};

#[instrument(skip_all)]
pub async fn execute(mut config: NodeConfig, peers: Vec<String>, bootstrap: bool) -> Result<()> {
    // Register signal listeners immediately at startup
    let shutdown = shutdown_signal();
    tokio::pin!(shutdown);

    owo();

    // Cross-host fence: ensure only one instance runs against this data directory.
    // Acquired *before* binding the control port or spawning background work so a second
    // instance fails fast instead of racing on the shared data directory.
    // Held for the lifetime of this function (the running process); released on exit.
    let _fence = e3_entrypoint::fence::ProcessFence::acquire(&config.db_file(), &config.name())?;
    // A purge reads this record to check the store that this node uses (`store_record`).
    if let Err(error) = e3_entrypoint::store_record::write(&config.key_file(), &config.db_file()) {
        warn!(
            %error,
            "Could not record the node's store next to its key file, so a purge may not check \
             this store"
        );
    }

    launch_socket_server(config.ctrl_port());

    config.add_peers(peers)?;
    if bootstrap {
        let network = node_v2::bootstrap(&config).await?;
        info!("LAUNCHING BOOTSTRAP NODE: ({})", config.name());
        return tokio::select! {
            result = e3_node::launch::bootstrap(network) => result.context("the node stopped"),
            _ = &mut shutdown => {
                info!("stopped");
                Ok(())
            }
        };
    }
    if config.skip_proof_aggregation() && !cfg!(feature = "test-only-skip-proof-aggregation") {
        bail!(
            "`skip_proof_aggregation` is test/CI-only and this binary was built without the \
             `test-only-skip-proof-aggregation` Cargo feature"
        );
    }
    let node = node_v2::config(&config).await?;
    info!(
        "LAUNCHING CIPHERNODE: ({}/{})",
        config.name(),
        node.operator.address()
    );
    tokio::select! {
        result = e3_node::launch::launch(node) => result.context("the node stopped"),
        _ = &mut shutdown => {
            info!("stopped");
            Ok(())
        }
    }
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
