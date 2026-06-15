// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use anyhow::Result;
use clap::Parser;
use cli::{Cli, RemoteCli};
use e3_console::Console;
use e3_daemon_server::{connect_daemon, run_on_daemon};
use e3_utils::{colorize, Color};
use tracing::info;

mod ciphernode;
mod cli;
mod config;
mod config_setup;
mod events;
pub mod helpers;
mod init;
mod net;
mod net_get_peer_id;
mod node;
mod nodes;
mod nodes_daemon;
mod nodes_down;
mod nodes_ps;
mod nodes_purge;
mod nodes_restart;
mod nodes_start;
mod nodes_status;
mod nodes_stop;
mod nodes_up;
pub mod noir;
mod password;
mod password_delete;
mod password_set;
mod print_env;
mod program;
mod purge_all;
mod rev;
mod start;
mod wallet;
mod wallet_get;
mod wallet_set;

const OWO: &str = r#"
╔═════════════════════════════════════════════════════════════════════════════╗

    ██╗███╗   ██╗████████╗███████╗██████╗ ███████╗ ██████╗ ██╗     ██████╗ 
    ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗██╔════╝██╔═══██╗██║     ██╔══██╗
    ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝█████╗  ██║   ██║██║     ██║  ██║
    ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗██╔══╝  ██║   ██║██║     ██║  ██║
    ██║██║ ╚████║   ██║   ███████╗██║  ██║██║     ╚██████╔╝███████╗██████╔╝
    ╚═╝╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝╚═╝      ╚═════╝ ╚══════╝╚═════╝ 
╚════════════════════════════[ I N T E R F O L D ]════════════════════════════╝
                                                                      
"#;

pub fn owo() {
    println!("\n\n\n\n\n{}", OWO);
    println!("\n\n\n\n");
}

#[actix::main]
pub async fn main() -> Result<()> {
    info!("COMPILATION ID: '{}'", helpers::compile_id::generate_id());
    let handle = Console::stdout();
    let out = handle.writer();
    let cli = Cli::parse();

    let config_result = cli.load_config();
    let maybe_server = connect_daemon(config_result.as_ref().ok()).await;
    let maybe_remote_command = TryInto::<RemoteCli>::try_into(cli.clone()).ok();

    // If the socket exists and the command can be parsed as remote
    if let Err(err) = if let (Some(server), Some(command)) = (maybe_server, maybe_remote_command) {
        // Run the command over the socket
        run_on_daemon(out, server, command).await
    } else {
        // Run the command locally
        cli.execute(out, config_result).await
    } {
        eprintln!("{}", colorize(err, Color::Red));
        std::process::exit(1);
    }
    handle.flush().await;
    Ok(())
}
