// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::ciphernode::{self, ChainArgs, CiphernodeCommands};
use crate::config::{self, ConfigCommands};
use crate::events::{self, EventsCommands};
use crate::faucet;
use crate::helpers::telemetry::{setup_simple_tracing, setup_tracing};
use crate::net::{self, NetCommands};
use crate::node::{self, NodeCommands as NodeStateCommands};
use crate::nodes::{self, NodeCommands};
use crate::noir::NoirCommands;
use crate::password::PasswordCommands;
use crate::program::{self, ProgramCommands};
use crate::wallet::WalletCommands;
use crate::{init, noir, password, purge_all, rev, wallet};
use crate::{print_env, start};
use anyhow::{bail, Result};
use clap::{command, ArgAction, Parser, Subcommand};
use e3_config::validation::ValidUrl;
use e3_config::{load_config, AppConfig};
use e3_console::{log, Console};
use e3_entrypoint::helpers::datastore::close_all_connections;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::str::FromStr;
use tracing::{info, instrument, Level};

#[derive(Parser, Clone, Debug)]
#[command(name = "interfold")]
#[command(about = "A CLI for interacting with Interfold the open-source protocol for Encrypted Execution Environments (E3)", long_about = None)]
#[command(version = env!("CARGO_PKG_VERSION"))]
pub struct Cli {
    /// Path to config file
    #[arg(short, long, global = true)]
    config: Option<String>,

    #[command(subcommand)]
    command: Commands,

    /// Indicate error levels by adding additional `-v` arguments. Eg. `interfold -vvv` will give you
    /// trace level output
    #[arg(
        short,
        long,
        action = ArgAction::Count,
        global = true
    )]
    pub verbose: u8,

    /// Silence all output. This argument cannot be used alongside `-v`
    #[arg(
        short,
        long,
        action = ArgAction::SetTrue,
        conflicts_with = "verbose",
        global = true
    )]
    quiet: bool,

    /// The node name (used for logs and open telemetry)
    #[arg(long, global = true)]
    pub name: Option<String>,

    /// Set the Open Telemetry collector grpc endpoint. Eg. http://localhost:4317
    #[arg(long = "otel", global = true)]
    pub otel: Option<ValidUrl>,
}

impl Cli {
    pub fn log_level(&self) -> Level {
        if self.quiet {
            Level::ERROR
        } else {
            match self.verbose {
                0 => Level::WARN,  //
                1 => Level::INFO,  // -v
                2 => Level::DEBUG, // -vv
                _ => Level::TRACE, // -vvv
            }
        }
    }

    #[instrument(skip_all)]
    pub async fn execute(self, out: Console, config_result: Result<AppConfig>) -> Result<()> {
        let log_level = self.log_level();
        // Attempt to load the config, but only treat "not found" as
        // the trigger for the init flow.  All other errors bubble up.
        let config = match config_result {
            Ok(cfg) => cfg,
            // If the file truly doesn't exist, fall back to init
            Err(e)
                if matches!(
                    e.downcast_ref::<std::io::Error>(),
                    Some(ioe) if ioe.kind() == std::io::ErrorKind::NotFound
                ) =>
            {
                // Existing init branch
                match self.command {
                    Commands::Rev { features } => rev::execute(out, features).await?,
                    Commands::Init {
                        path,
                        template,
                        skip_cleanup,
                        skip_install,
                    } => {
                        setup_simple_tracing(log_level);
                        init::execute(
                            path,
                            template,
                            skip_cleanup,
                            skip_install,
                            self.verbose > 0,
                        )
                        .await?
                    },
                    Commands::Ciphernode {
                        command: CiphernodeCommands::Setup {
                            network,
                            rpc_url,
                            config_dir,
                            password_stdin,
                            private_key_stdin,
                        }
                    } => {
                        ciphernode::setup::execute(
                            out,
                            network,
                            rpc_url,
                            config_dir,
                            password_stdin,
                            private_key_stdin,
                        )
                        .await?;
                    }
                    Commands::Start { .. } => {
                        log!(out,"No configuration found. Setting up interfold configuration...");
                        ciphernode::setup::execute(
                            out,
                            "sepolia".to_string(),
                            None,
                            None,
                            false,
                            false,
                        )
                        .await?;
                    },
                    Commands::Noir { command } => {
                        setup_simple_tracing(log_level);
                        noir::execute_without_config(out, command).await?
                    },
                    _ => bail!(
                        "Configuration file not found. Run `interfold ciphernode setup` to create a configuration."
                    ),
                };
                return Ok(());
            }
            // Any other error is fatal
            Err(e) => return Err(e),
        };

        // The purge commands delete the node folders. They write no log file, password, or wallet
        // there, because a later purge would treat such files as node state.
        let purges = matches!(
            self.command,
            Commands::PurgeAll { .. }
                | Commands::Nodes {
                    command: NodeCommands::Purge { .. }
                }
        );
        if purges {
            setup_simple_tracing(log_level);
        } else {
            setup_tracing(&config, log_level)?;
        }
        info!("Config loaded from: {:?}", config.config_file());

        // Config commands only read configuration, so they do not create a password or a wallet.
        let creates_secrets = !purges && !matches!(self.command, Commands::Config { .. });

        if creates_secrets && config.autopassword() {
            e3_entrypoint::password::set::autopassword(&config).await?;
        }

        if creates_secrets && config.autowallet() {
            e3_entrypoint::wallet::set::autowallet(&config).await?;
        }

        match self.command {
            Commands::Start { peers, bootstrap } => {
                start::execute(config, peers, bootstrap).await?
            }
            Commands::Init { .. } => {
                bail!("Cannot run `interfold init` when a configuration exists.");
            }
            Commands::Compile { dev } => {
                e3_support_scripts::program_compile(config.program().clone(), dev).await?
            }
            Commands::PrintEnv { vite, chain } => {
                print_env::execute(out, &config, &chain, vite).await?
            }
            Commands::Program { command } => program::execute(command, &config).await?,
            Commands::PurgeAll {
                yes,
                allow_active_e3s,
            } => {
                purge_all::execute(&config, self.config.clone(), yes, allow_active_e3s).await?;
            }
            Commands::Nodes { command } => {
                nodes::execute(
                    command,
                    &config,
                    self.verbose,
                    self.config,
                    self.otel.clone().map(Into::into),
                )
                .await?
            }
            Commands::Password { command } => password::execute(out, command, &config).await?,
            Commands::Wallet { command } => wallet::execute(out, command, config).await?,
            Commands::Ciphernode { command } => ciphernode::execute(out, command, &config).await?,
            Commands::Noir { command } => noir::execute(out, command, &config).await?,
            Commands::Net { command } => net::execute(&out, command, &config).await?,
            Commands::Events { command } => events::execute(out, command, &config).await?,
            Commands::Node { command } => node::execute(out, command, &config).await?,
            Commands::Rev { features } => rev::execute(out, features).await?,
            Commands::Config { command } => config::execute(out, command, &config).await?,
            Commands::Faucet { chain } => {
                faucet::execute(out, &config, chain.chain.as_deref()).await?
            }
        }

        close_all_connections();

        Ok(())
    }

    pub fn load_config(&self) -> Result<AppConfig> {
        let config = load_config(
            &self.name(),
            self.config.clone(),
            self.otel.clone().map(Into::into),
        )?;
        Ok(config)
    }

    pub fn name(&self) -> String {
        // If no name is provided assume we are working with the default node
        self.name.clone().unwrap_or("_default".to_string())
    }
}

#[derive(Subcommand, Clone, Debug)]
pub enum Commands {
    /// Start the application
    Start {
        #[arg(
            long = "peer",
            action = clap::ArgAction::Append,
            value_name = "PEER",
            help = "Sets a peer URL",
        )]
        peers: Vec<String>,
        #[arg(
            long,
            help = "Run as a bootstrap peer: networking and chain reads only, without committee \
                    work, proofs, transactions, or the prover's memory requirement"
        )]
        bootstrap: bool,
    },

    /// Print the config env
    PrintEnv {
        /// Display vite addresses
        #[arg(long)]
        vite: bool,

        /// Chain name
        #[arg(long)]
        chain: String,
    },

    /// Initialize an interfold project
    Init {
        /// Path to the location where the project should be initialized
        path: Option<PathBuf>,

        /// Template repository to use. Expecting the form `git+https://github.com/theinterfold/interfold.git#main:templates/default`
        #[arg(long)]
        template: Option<String>,

        /// Do not clean up on errors leaving the working folder intact. This option is mainly used
        /// for testing the installer.
        #[arg(long)]
        skip_cleanup: bool,

        /// Do not install JavaScript packages. Use this option for offline setup or unpublished
        /// release candidates.
        #[arg(long)]
        skip_install: bool,
    },

    /// Compile an Interfold project
    Compile {
        /// Compile the program in Dev Mode.
        #[arg(long)]
        dev: Option<bool>,
    },

    /// Return the git_sha rev that the cli was compiled against
    Rev {
        /// List the optional Cargo features compiled into this binary instead
        /// of the git sha. Prints nothing for a release build.
        #[arg(long)]
        features: bool,
    },

    /// Program management commands
    Program {
        #[command(subcommand)]
        command: ProgramCommands,
    },

    /// Run `nodes purge`, then delete the local program cache. Deletes each node's operator key
    /// and libp2p key.
    PurgeAll {
        /// Confirm the deletion.
        #[arg(long)]
        yes: bool,

        /// Override the refusal for an active key share and for a node that the command cannot
        /// check. The node permanently loses its key share. Check first that each listed E3 is
        /// complete or failed on chain, and that one day has passed after its lifecycle deadline.
        /// The command cannot see a node that runs with another E3_DATA_DIR, data_dir, or working
        /// directory. Check that no such node runs.
        #[arg(long)]
        allow_active_e3s: bool,
    },

    /// Password management commands
    Password {
        #[command(subcommand)]
        command: PasswordCommands,
    },

    /// Wallet management commands
    Wallet {
        #[command(subcommand)]
        command: WalletCommands,
    },

    /// Noir prover management and proof generation
    Noir {
        #[command(subcommand)]
        command: NoirCommands,
    },

    /// On-chain ciphernode lifecycle management
    Ciphernode {
        #[command(subcommand)]
        command: CiphernodeCommands,
    },

    /// Manage multiple node processes together as a set
    Nodes {
        #[command(subcommand)]
        command: NodeCommands,
    },

    /// Single-node maintenance commands (validate on-disk state, etc.)
    Node {
        #[command(subcommand)]
        command: NodeStateCommands,
    },

    /// Manage net configuration
    Net {
        #[command(subcommand)]
        command: NetCommands,
    },

    /// Query events
    Events {
        #[command(subcommand)]
        command: EventsCommands,
    },

    /// Get config values
    Config {
        #[command(subcommand)]
        command: ConfigCommands,
    },

    /// Request testnet tokens (FOLD + fee token) from the configured faucet
    Faucet {
        #[command(flatten)]
        chain: ChainArgs,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RemoteCli {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    otel: Option<String>,
    #[serde(default)]
    quiet: bool,
    #[serde(default)]
    config: Option<String>,
    #[serde(default)]
    verbose: u8,
    command: RemoteCommand,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum RemoteCommand {
    NetGetPeerId,
    CiphernodeStatus {
        chain: ChainArgs,
        operator: Option<String>,
    },
    NoirStatus,
    WalletGet,
    EventsQuery {
        agg: Option<usize>,
        since: Option<u64>,
        limit: Option<u64>,
    },
    Rev,
    PrintEnv {
        vite: bool,
        chain: String,
    },
    /// The client runs `config get` locally with its own environment. The daemon accepts this
    /// command only from older clients.
    ConfigGet {
        param: Option<String>,
    },
}

impl TryFrom<Commands> for RemoteCommand {
    type Error = anyhow::Error;

    fn try_from(value: Commands) -> std::result::Result<Self, Self::Error> {
        match value {
            Commands::Rev { features: true } => bail!(
                "`rev --features` reports the features of the local binary, so it cannot run remotely"
            ),
            Commands::Rev { features: false } => Ok(RemoteCommand::Rev),
            Commands::Net {
                command: NetCommands::GetPeerId,
            } => Ok(RemoteCommand::NetGetPeerId),
            Commands::Noir {
                command: NoirCommands::Status,
            } => Ok(RemoteCommand::NoirStatus),
            Commands::Ciphernode {
                command: CiphernodeCommands::Status { chain, operator },
            } => Ok(RemoteCommand::CiphernodeStatus { chain, operator }),
            Commands::PrintEnv { chain, vite } => Ok(RemoteCommand::PrintEnv { vite, chain }),
            Commands::Events {
                command: EventsCommands::Query { agg, since, limit },
            } => Ok(RemoteCommand::EventsQuery { agg, since, limit }),
            Commands::Wallet {
                command: WalletCommands::Get,
            } => Ok(RemoteCommand::WalletGet),
            _ => bail!("Command not allowed while node is running."),
        }
    }
}

impl TryFrom<Cli> for RemoteCli {
    type Error = anyhow::Error;
    fn try_from(value: Cli) -> Result<Self> {
        Ok(RemoteCli {
            otel: value.otel.map(|o| o.to_string()),
            verbose: value.verbose,
            config: value.config,
            name: value.name,
            quiet: value.quiet,
            command: value.command.try_into()?,
        })
    }
}

impl TryFrom<RemoteCli> for Cli {
    type Error = anyhow::Error;
    fn try_from(value: RemoteCli) -> std::result::Result<Self, Self::Error> {
        Ok(Cli {
            verbose: value.verbose,
            config: value.config,
            quiet: value.quiet,
            otel: value.otel.and_then(|o| ValidUrl::from_str(&o).ok()),
            command: value.command.try_into()?,
            name: value.name,
        })
    }
}

impl TryFrom<RemoteCommand> for Commands {
    type Error = anyhow::Error;
    fn try_from(value: RemoteCommand) -> std::result::Result<Self, Self::Error> {
        let command = match value {
            RemoteCommand::Rev => Commands::Rev { features: false },
            RemoteCommand::WalletGet => Commands::Wallet {
                command: WalletCommands::Get,
            },
            RemoteCommand::PrintEnv { vite, chain } => Commands::PrintEnv { vite, chain },
            RemoteCommand::CiphernodeStatus { chain, operator } => Commands::Ciphernode {
                command: CiphernodeCommands::Status { chain, operator },
            },
            RemoteCommand::NoirStatus => Commands::Noir {
                command: NoirCommands::Status,
            },
            RemoteCommand::NetGetPeerId => Commands::Net {
                command: NetCommands::GetPeerId,
            },
            RemoteCommand::EventsQuery { agg, since, limit } => Commands::Events {
                command: EventsCommands::Query { agg, since, limit },
            },
            RemoteCommand::ConfigGet { param } => Commands::Config {
                command: ConfigCommands::Get { param },
            },
        };
        // We might have to hold this stuff on RemoteCommand
        Ok(command)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn config_get_does_not_create_secrets() -> Result<()> {
        let dir = std::env::temp_dir().join(format!("e3-cli-config-get-{}", std::process::id()));
        std::fs::create_dir_all(&dir)?;
        let config_file = dir.join("config.yaml");
        std::fs::write(
            &config_file,
            format!(
                "node:\n  network: local\n  autopassword: true\n  autowallet: true\n  config_dir: {}\n  data_dir: {}\n",
                dir.join("config").display(),
                dir.join("data").display()
            ),
        )?;
        let config_arg = config_file.to_string_lossy().into_owned();
        let cli = Cli::parse_from(["interfold", "config", "get", "key_file", "-c", &config_arg]);
        let config = cli.load_config()?;
        let key_file = config.key_file();
        let db_file = config.db_file();
        assert!(key_file.starts_with(&dir) && db_file.starts_with(&dir));

        let (out, _rx) = Console::channel();
        let result = cli.execute(out, Ok(config)).await;
        let created = (key_file.exists(), db_file.exists());
        std::fs::remove_dir_all(&dir)?;

        result?;
        assert_eq!(
            created,
            (false, false),
            "config get created the key file or the database"
        );
        Ok(())
    }

    /// Without `--yes`, the purge commands refuse before they touch any node state, and they
    /// create no password or wallet.
    #[actix::test]
    async fn purge_without_confirmation_changes_nothing() -> Result<()> {
        // The purge works on the current directory. It must hold no state, so a regression of the
        // confirmation cannot delete real state.
        assert!(!std::path::Path::new(".interfold").exists());
        let dir = tempfile::tempdir()?;
        let config_file = dir.path().join("config.yaml");
        std::fs::write(
            &config_file,
            format!(
                "node:\n  network: local\n  autopassword: true\n  autowallet: true\n  config_dir: {}\n  data_dir: {}\n",
                dir.path().join("config").display(),
                dir.path().join("data").display()
            ),
        )?;
        let config_arg = config_file.to_string_lossy().into_owned();
        for command in [&["nodes", "purge"][..], &["purge-all"][..]] {
            let args = [&["interfold"][..], command, &["-c", &config_arg][..]].concat();
            let cli = Cli::parse_from(args);
            let config = cli.load_config()?;
            let (key_file, db_file) = (config.key_file(), config.db_file());

            let (out, _rx) = Console::channel();
            let error = cli
                .execute(out, Ok(config))
                .await
                .expect_err("the purge must require --yes");
            assert!(error.to_string().contains("--yes"), "{command:?}: {error}");
            assert_eq!(
                (key_file.exists(), db_file.exists()),
                (false, false),
                "{command:?} created the key file or the database"
            );
        }
        Ok(())
    }

    #[test]
    fn config_get_runs_locally_and_the_daemon_accepts_older_clients() -> Result<()> {
        let cli = Cli::parse_from(["interfold", "config", "get", "key_file"]);
        assert!(RemoteCli::try_from(cli).is_err());

        let remote: RemoteCli =
            serde_json::from_str(r#"{"command":{"ConfigGet":{"param":"key_file"}}}"#)?;
        let cli = Cli::try_from(remote)?;
        assert!(matches!(
            cli.command,
            Commands::Config {
                command: ConfigCommands::Get { param: Some(param) },
            } if param == "key_file"
        ));
        Ok(())
    }

    #[test]
    fn start_runs_a_full_node_unless_bootstrap_is_set() {
        let cli = Cli::parse_from(["interfold", "start"]);
        assert!(matches!(
            cli.command,
            Commands::Start {
                bootstrap: false,
                ..
            }
        ));

        let cli = Cli::parse_from([
            "interfold",
            "start",
            "--bootstrap",
            "--peer",
            "/ip4/127.0.0.1/udp/9091/quic-v1",
        ]);
        assert!(matches!(
            cli.command,
            Commands::Start {
                bootstrap: true,
                ref peers,
            } if peers.len() == 1
        ));
    }
}
