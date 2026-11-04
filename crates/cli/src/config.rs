// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::manifest::{self, Finding};
use anyhow::{bail, Result};
use clap::Subcommand;
use e3_ciphernode_config::NodeConfig;
use e3_cli::program_config::ProgramConfig;
use e3_console::{log, Console};

#[derive(Subcommand, Clone, Debug)]
pub enum ConfigCommands {
    /// Get a config parameter
    Get {
        /// The config parameter to get. If not provided, prints all config values
        param: Option<String>,
    },
    /// Compare configured contract addresses against the published deployment manifest
    Check {
        /// Only check this chain. Defaults to every chain in the config.
        #[arg(long)]
        chain: Option<String>,

        /// Fetch the manifest from this URL instead of the latest GitHub release
        #[arg(long)]
        manifest_url: Option<String>,
    },
}

pub async fn execute(
    out: Console,
    command: ConfigCommands,
    config: &NodeConfig,
    program: &ProgramConfig,
) -> Result<()> {
    match command {
        ConfigCommands::Get { param } => get(out, param, config, program),
        ConfigCommands::Check {
            chain,
            manifest_url,
        } => check(out, chain, manifest_url, config).await,
    }
}

/// Report configured addresses that no longer match the published deployment.
///
/// Exits non-zero when any address is wrong, so this can gate a node restart in
/// a supervisor or a CI job. A stale `deploy_block` or an unconfigured optional
/// contract is printed but does not fail the command.
async fn check(
    out: Console,
    chain_filter: Option<String>,
    manifest_url: Option<String>,
    config: &NodeConfig,
) -> Result<()> {
    let (published, source) = manifest::fetch(manifest_url.as_deref()).await?;
    log!(out, "Deployment manifest: {}", source);

    let chains: Vec<_> = config
        .chains()
        .iter()
        .filter(|c| match &chain_filter {
            Some(f) => &c.name == f,
            None => true,
        })
        .collect();

    if chains.is_empty() {
        match chain_filter {
            Some(name) => bail!("No chain named `{}` in the config", name),
            None => bail!("No chains configured"),
        }
    }

    let mut errors = 0usize;

    for chain in chains {
        let Some(network) = published.networks.get(&chain.name) else {
            // A local or private deployment is not described by the published
            // manifest. That is expected, not staleness worth reporting.
            log!(
                out,
                "{}: not in the published manifest, skipping",
                chain.name
            );
            continue;
        };

        let findings = manifest::compare(chain, network);

        if findings.is_empty() {
            log!(out, "{}: up to date", chain.name);
        } else {
            log!(out, "{}:", chain.name);
            for finding in &findings {
                if finding.is_error() {
                    errors += 1;
                }
                match finding {
                    Finding::AddressMismatch {
                        key,
                        configured,
                        published,
                    } => log!(
                        out,
                        "  STALE {}: config has {}, published is {}",
                        key,
                        configured,
                        published
                    ),
                    Finding::DeployBlockMismatch {
                        key,
                        configured,
                        published,
                    } => log!(
                        out,
                        "  warn  {}: deploy_block {}, published is {}",
                        key,
                        configured
                            .map(|b| b.to_string())
                            .unwrap_or_else(|| "unset".to_string()),
                        published
                    ),
                    Finding::Missing { key, published } => log!(
                        out,
                        "  note  {}: not configured, published is {}",
                        key,
                        published
                    ),
                    Finding::ChainIdMismatch {
                        configured,
                        published,
                    } => log!(
                        out,
                        "  STALE chain_id: config has {}, published is {}",
                        configured,
                        published
                    ),
                }
            }
        }

        if network.mocks {
            log!(
                out,
                "  note  {} is a mock deployment - proofs are accepted without being verified",
                chain.name
            );
        }
    }

    if errors > 0 {
        // Not "address(es)": a chain-id mismatch counts here too.
        bail!(
            "{} setting(s) do not match the published deployment. \
             Update your config, or re-run `interfold ciphernode setup`.",
            errors
        );
    }

    Ok(())
}

fn get(
    out: Console,
    param: Option<String>,
    config: &NodeConfig,
    program: &ProgramConfig,
) -> Result<()> {
    match param.as_deref() {
        Some("name") => {
            log!(out, "{}", config.name());
        }
        Some("peers") => {
            for peer in config.peers() {
                log!(out, "{}", peer);
            }
        }
        Some("network") => {
            log!(out, "{}", config.network().name());
        }
        Some("network_id") => {
            log!(out, "{}", config.network().id());
        }
        Some("quic_port") => {
            log!(out, "{}", config.quic_port());
        }
        Some("ctrl_port") => {
            log!(out, "{}", config.ctrl_port());
        }
        Some("address") => {
            if let Some(addr) = config.address() {
                log!(out, "{}", addr);
            }
        }
        Some("autonetkey") => {
            log!(out, "{}", config.autonetkey());
        }
        Some("autopassword") => {
            log!(out, "{}", config.autopassword());
        }
        Some("autowallet") => {
            log!(out, "{}", config.autowallet());
        }
        Some("otel") => {
            if let Some(otel) = config.otel() {
                log!(out, "{}", otel);
            }
        }
        Some("config_file") => {
            log!(out, "{}", config.config_file().display());
        }
        Some("config_yaml") => {
            log!(out, "{}", config.config_yaml().display());
        }
        Some("db_file") => {
            log!(out, "{}", config.db_file().display());
        }
        Some("key_file") => {
            log!(out, "{}", config.key_file().display());
        }
        Some("log_file") => {
            log!(out, "{}", config.log_file().display());
        }
        Some("work_dir") => {
            log!(out, "{}", config.work_dir().display());
        }
        Some("chains") => {
            for chain in config.chains() {
                log!(out, "{}", chain.name);
            }
        }
        Some("nodes") => {
            for (name, node_def) in config.nodes() {
                log!(out, "{}: {:?}", name, node_def);
            }
        }
        Some("program") => {
            log!(out, "{:?}", program);
        }
        Some(param) => {
            anyhow::bail!("Unknown config parameter: {}", param);
        }
        None => {
            log!(out, "name: {}", config.name());
            log!(out, "peers: {:?}", config.peers());
            log!(out, "network: {}", config.network().name());
            log!(out, "network_id: {}", config.network().id());
            log!(out, "quic_port: {}", config.quic_port());
            log!(out, "ctrl_port: {}", config.ctrl_port());
            log!(out, "address: {:?}", config.address());
            log!(out, "autonetkey: {}", config.autonetkey());
            log!(out, "autopassword: {}", config.autopassword());
            log!(out, "autowallet: {}", config.autowallet());
            log!(out, "otel: {:?}", config.otel());
            log!(out, "config_file: {}", config.config_file().display());
            log!(out, "config_yaml: {}", config.config_yaml().display());
            log!(out, "db_file: {}", config.db_file().display());
            log!(out, "key_file: {}", config.key_file().display());
            log!(out, "log_file: {}", config.log_file().display());
            log!(out, "work_dir: {}", config.work_dir().display());
            log!(out, "chains: {:?}", config.chains());
            log!(out, "nodes: {:?}", config.nodes());
            log!(out, "program: {:?}", program);
        }
    }
    Ok(())
}
