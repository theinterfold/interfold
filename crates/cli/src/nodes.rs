// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use anyhow::*;
use clap::Subcommand;
use e3_config::AppConfig;

use crate::{
    nodes_daemon, nodes_down, nodes_ps, nodes_purge, nodes_restart, nodes_start, nodes_status,
    nodes_stop, nodes_up,
};

#[derive(Subcommand, Clone, Debug)]
pub enum NodeCommands {
    /// Launch all nodes
    Up {
        /// Detached mode: Run nodes in the background
        #[arg(short, long)]
        detach: bool,

        /// Exclude nodes by name
        #[arg(short, long, value_delimiter = ',')]
        exclude: Vec<String>,
    },

    /// Shutdown all nodes
    Down,

    #[command(hide = true)]
    Daemon {
        /// Exclude nodes by name
        #[arg(short, long, value_delimiter = ',')]
        exclude: Vec<String>,
    },

    /// List all process statuses
    Ps,

    /// Delete `.interfold/data` and `.interfold/config` in the current directory, including each
    /// node's operator key and libp2p key. To clear a node's state and keep its identity, use
    /// `interfold node reset-data`.
    ///
    /// Refuses when it finds a running node whose state it deletes. Refuses when such a node holds
    /// key-share state for an E3 that it has not seen complete. Refuses when it cannot check such
    /// a node. The chain cannot restore a deleted key share.
    Purge {
        /// Confirm the deletion.
        #[arg(long)]
        yes: bool,

        /// Override the refusal for an active key share and for a node that the command cannot
        /// check. The node permanently loses its key share. Check first that each listed E3 is
        /// complete or failed on chain, and that one day has passed after its lifecycle deadline.
        /// The command checks the store that each node recorded at its last start; for a node that
        /// has not started with this release, it checks the store at the configured path.
        #[arg(long)]
        allow_active_e3s: bool,
    },

    /// Start an individual node in the nodes set
    Start {
        /// The id of the node
        #[arg(index = 1)]
        id: String,
    },

    /// Stop the individual node in the nodes set
    Stop {
        /// The id of the node
        #[arg(index = 1)]
        id: String,
    },

    /// Print the status of the individual node in the nodes set
    Status {
        /// The id of the node
        #[arg(index = 1)]
        id: String,
    },

    /// Stop and start the individual node in the nodes set
    Restart {
        /// The id of the node
        #[arg(index = 1)]
        id: String,
    },
}

pub async fn execute(
    command: NodeCommands,
    config: &AppConfig,
    verbose: u8,
    config_string: Option<String>,
    otel: Option<String>,
) -> Result<()> {
    match command {
        NodeCommands::Up { detach, exclude } => {
            nodes_up::execute(config, detach, exclude, verbose, config_string, otel).await?
        }
        NodeCommands::Down => nodes_down::execute().await?,
        NodeCommands::Ps => nodes_ps::execute().await?,
        NodeCommands::Daemon { exclude } => {
            nodes_daemon::execute(config, exclude, verbose, config_string, otel).await?
        }
        NodeCommands::Start { id } => nodes_start::execute(&id).await?,
        NodeCommands::Status { id } => nodes_status::execute(&id).await?,
        NodeCommands::Stop { id } => nodes_stop::execute(&id).await?,
        NodeCommands::Restart { id } => nodes_restart::execute(&id).await?,
        NodeCommands::Purge {
            yes,
            allow_active_e3s,
        } => nodes_purge::execute(config, config_string, yes, allow_active_e3s).await?,
    };

    Ok(())
}
