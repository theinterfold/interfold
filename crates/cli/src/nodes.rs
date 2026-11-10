// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use anyhow::*;
use clap::Subcommand;
use e3_ciphernode_config::NodeConfig;
use e3_console::Console;

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

    /// Delete the data of every node in the configuration. Every node keeps its operator key and
    /// libp2p key: this is `interfold node reset-data` for all of them, all or none.
    ///
    /// Refuses while a node runs, and while a node holds an E3 that has not ended: the chain cannot
    /// restore a deleted key share. Refuses too where it cannot tell.
    Purge {
        /// Confirm the deletion.
        #[arg(long)]
        yes: bool,

        /// Delete the data even when a node holds an E3 that has not ended, or when the command
        /// cannot check a node. The node gives up what it still owes each E3 the command lists.
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
    out: Console,
    command: NodeCommands,
    config: &NodeConfig,
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
        } => nodes_purge::execute(&out, config, config_string, yes, allow_active_e3s)?,
    };

    Ok(())
}
