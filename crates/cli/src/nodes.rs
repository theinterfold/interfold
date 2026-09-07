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

    /// Purge all local ciphernode data. This will delete all passwords and prior ciphernode
    /// events.
    Purge,

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

    /// Stop the individual node in the nodes set
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
        NodeCommands::Down => nodes_down::execute(config).await?,
        NodeCommands::Ps => nodes_ps::execute().await?,
        NodeCommands::Daemon { exclude } => {
            nodes_daemon::execute(config, exclude, verbose, config_string, otel).await?
        }
        NodeCommands::Start { id } => nodes_start::execute(config, &id).await?,
        NodeCommands::Status { id } => nodes_status::execute(config, &id).await?,
        NodeCommands::Stop { id } => nodes_stop::execute(config, &id).await?,
        NodeCommands::Restart { id } => nodes_restart::execute(config, &id).await?,
        NodeCommands::Purge => nodes_purge::execute().await?,
    };

    Ok(())
}
