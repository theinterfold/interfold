// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use anyhow::*;
use clap::Subcommand;
use e3_ciphernode_config::NodeConfig;
use e3_console::Console;

use crate::net_get_peer_id;

#[derive(Subcommand, Clone, Debug)]
pub enum NetCommands {
    /// Get the ciphernode's libp2p PeerId
    GetPeerId,
}

pub async fn execute(out: &Console, command: NetCommands, config: &NodeConfig) -> Result<()> {
    match command {
        NetCommands::GetPeerId => net_get_peer_id::execute(out, config).await?,
    };

    Ok(())
}
