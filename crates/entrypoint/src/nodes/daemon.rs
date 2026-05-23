// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use anyhow::*;
use e3_config::{combine_unique, AppConfig, NodeDefinition};
use std::sync::Arc;
use std::{collections::HashMap, env};
use tokio::sync::Mutex;
use tracing::{error, info, instrument};

use super::process_manager::ProcessManager;
use super::server::server;

use super::nodes::{CommandMap, CommandParams};

/// Metadata used to workout launch charachteristics for swarm mode
#[derive(Clone, Debug)]
pub struct LaunchCommand {
    pub name: String,
    pub ip: String, // maybe this should be an actual socket addr?
    pub quic_port: u16,
    pub peers: Vec<String>,
}

impl LaunchCommand {
    pub fn from_definition(name: &str, ip: &str, definition: &NodeDefinition) -> Self {
        Self {
            name: name.to_owned(),
            ip: ip.to_owned(),
            quic_port: definition.quic_port,
            peers: vec![],
        }
    }

    pub fn to_multiaddr_str(&self) -> String {
        format!("/ip4/{}/udp/{}/quic-v1", self.ip, self.quic_port)
    }

    pub fn add_peers(&mut self, nodes: &Vec<LaunchCommand>) {
        let peers: Vec<String> = nodes
            .iter()
            .filter(|n| n.name != self.name)
            .map(|n| n.to_multiaddr_str())
            .collect();
        self.peers = combine_unique(&self.peers, &peers);
    }

    pub fn to_params(
        &self,
        verbose: u8,
        maybe_config_string: &Option<String>,
        maybe_otel: &Option<String>,
    ) -> Result<CommandParams> {
        let enclave_bin = env::current_exe()?.display().to_string();
        let mut args = vec![];
        args.push("start".to_string());

        args.push("--name".to_string());
        args.push(self.name.clone());

        if let Some(config_string) = maybe_config_string {
            args.push("--config".to_string());
            args.push(config_string.to_string());
        }

        if verbose > 0 {
            args.push(format!("-{}", "v".repeat(verbose as usize))); // -vvv
        }

        if let Some(otel) = maybe_otel {
            args.push("--otel".to_string());
            args.push(otel.to_string());
        }

        for peer in self.peers.iter() {
            args.push("--peer".to_string());
            args.push(peer.to_string());
        }

        Ok((enclave_bin, args))
    }
}

fn extract_commands(
    nodes: &HashMap<String, NodeDefinition>,
    ip: &str,
    exclude: Vec<String>,
    verbose: u8,
    maybe_config_string: Option<String>,
    maybe_otel: Option<String>,
) -> Result<CommandMap> {
    let mut exclude_list = exclude.clone();

    // Default should not be part of nodes set
    exclude_list.push("_default".to_string());

    // Filter all the nodes
    let mut filtered: Vec<LaunchCommand> = nodes
        .iter()
        .filter(|(name, _)| !exclude_list.contains(name))
        .map(|(name, value)| LaunchCommand::from_definition(name, ip, value))
        .collect();

    let peers = filtered.clone();
    for item in filtered.iter_mut() {
        item.add_peers(&peers);
    }

    let mut cmds = HashMap::new();
    for item in filtered.iter() {
        let params = item.to_params(verbose, &maybe_config_string, &maybe_otel)?;
        cmds.insert(item.name.clone(), params);
    }

    Ok(cmds)
}

#[instrument(skip_all)]
pub async fn execute(
    config: &AppConfig,
    exclude: Vec<String>,
    verbose: u8,
    maybe_config_string: Option<String>,
    maybe_otel: Option<String>,
) -> Result<()> {
    let command_map = extract_commands(
        config.nodes(),
        "127.0.0.1",
        exclude,
        verbose,
        maybe_config_string,
        maybe_otel,
    )?;

    let process_manager = Arc::new(Mutex::new(ProcessManager::from(command_map)));

    process_manager.lock().await.start_all().await?;

    let manager = process_manager.clone();
    let log_buffer = process_manager.lock().await.log_buffer();

    tokio::select! {
        res = server(manager.clone(), log_buffer) => {
            if let Err(e) = res { error!(%e, "Signal server errored"); }
        }
        _ = tokio::signal::ctrl_c() => {
            info!("SWARM: Received Ctrl+C shutting down...");
            manager.lock().await.terminate().await;
        }
    }

    Ok(())
}
