// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::chain_config::ChainConfig;
use crate::load_config::find_in_parent;
use crate::load_config::resolve_config_path;
use crate::network::{NetworkId, NetworkProfile};
use crate::paths_engine::PathsEngine;
use crate::paths_engine::DEFAULT_CONFIG_NAME;
use crate::program_config::ProgramConfig;
use crate::yaml::load_yaml_with_env;
use alloy_primitives::Address;
use anyhow::bail;
use anyhow::Context;
use anyhow::Result;
use figment::{
    providers::{Env, Format, Serialized, Yaml},
    Figment,
};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::{collections::HashMap, env, path::PathBuf};

/// The structure within the app configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
#[serde(deny_unknown_fields)]
pub struct NodeDefinition {
    /// Ethereum Address for the node
    pub address: Option<Address>,
    /// A list of libp2p multiaddrs to dial to as peers when joining the network
    pub peers: Vec<String>,
    /// Stable P2P network name. Built-in profiles are mainnet, sepolia, and local.
    pub network: Option<String>,
    /// Stable 32-byte identity for a custom P2P network.
    pub network_id: Option<NetworkId>,
    /// The port to use for the quic listener
    pub quic_port: u16,
    /// The port to use for the ctrl socket listener
    pub ctrl_port: u16,
    /// The name for the database
    pub db_file: PathBuf,
    /// The name for the keyfile
    pub key_file: PathBuf,
    /// The name for the logfile
    pub log_file: PathBuf,
    /// The data dir for interfold defaults to `~/.local/share/interfold/{name}`
    pub data_dir: PathBuf,
    /// Override the base folder for interfold configuration defaults to `~/.config/interfold/{name}` on linux
    pub config_dir: PathBuf,
    /// If a net key has not been set autogenerate one on start
    pub autonetkey: bool,
    /// If a password has not been set autogenerate one on start
    pub autopassword: bool,
    /// If a wallet has not been set autogenerate one on start
    pub autowallet: bool,
    /// Optional dashboard port. When set, serves a monitoring web UI on this port.
    pub dashboard_port: Option<u16>,
    /// Logical CPUs reserved for Actix, libp2p, and RPC (not used by the Rayon compute pool).
    #[serde(default = "default_multithread_reserve_threads")]
    pub multithread_reserve_threads: usize,
    /// Max concurrent CPU-bound jobs (ZK proofs + TrBFV). When unset, defaults to all CPUs minus
    /// `multithread_reserve_threads`. Override the default profile with env
    /// `E3_NODE__MULTITHREAD_CONCURRENT_JOBS`, or a named profile with
    /// `E3_NODES__<NAME>__MULTITHREAD_CONCURRENT_JOBS`.
    pub multithread_concurrent_jobs: Option<usize>,
    /// Hard deadline for construction and initial synchronization. A node that cannot reach live
    /// protocol operation before this deadline exits non-zero instead of remaining falsely alive.
    #[serde(default = "default_startup_timeout_secs")]
    pub startup_timeout_secs: u64,
    /// Maximum decoded EVM events retained per chain while initial sync is ordering historical
    /// and live data. Exceeding the bound fails startup; events are never silently discarded.
    #[serde(default = "default_max_buffered_evm_events")]
    pub max_buffered_evm_events: usize,
    /// Maximum network events retained while startup synchronization is in progress.
    #[serde(default = "default_max_buffered_net_events")]
    pub max_buffered_net_events: usize,
    /// Maximum estimated bytes retained by the network startup buffer.
    #[serde(default = "default_max_buffered_net_bytes")]
    pub max_buffered_net_bytes: usize,
    /// Test/CI-only escape hatch that skips recursive DKG and decryption proof aggregation.
    /// On-chain verification remains mandatory, so this requires mock verifiers and a binary
    /// compiled with the `test-only-skip-proof-aggregation` Cargo feature.
    pub skip_proof_aggregation: bool,
}

fn default_multithread_reserve_threads() -> usize {
    1
}

fn default_startup_timeout_secs() -> u64 {
    30 * 60
}

fn default_max_buffered_evm_events() -> usize {
    100_000
}

fn default_max_buffered_net_events() -> usize {
    1_024
}

fn default_max_buffered_net_bytes() -> usize {
    256 * 1024 * 1024
}

impl Default for NodeDefinition {
    fn default() -> Self {
        Self {
            // The resolved network profile supplies its DNS bootstrap when this list is empty.
            peers: vec![],
            network: None,
            network_id: None,
            address: None,
            quic_port: 9091,
            ctrl_port: 50505,
            key_file: PathBuf::from("key"), // ~/.config/interfold/key
            db_file: PathBuf::from("db"),   // ~/.config/interfold/db
            log_file: PathBuf::from("log"), // ~/.config/interfold/log
            config_dir: std::path::PathBuf::new(), // ~/.config/interfold
            data_dir: std::path::PathBuf::new(), // ~/.config/interfold
            autonetkey: false,
            autopassword: false,
            autowallet: false,
            dashboard_port: None,
            multithread_reserve_threads: default_multithread_reserve_threads(),
            multithread_concurrent_jobs: None,
            startup_timeout_secs: default_startup_timeout_secs(),
            max_buffered_evm_events: default_max_buffered_evm_events(),
            max_buffered_net_events: default_max_buffered_net_events(),
            max_buffered_net_bytes: default_max_buffered_net_bytes(),
            skip_proof_aggregation: false,
        }
    }
}

/// The config actually used throughout the app
#[derive(Debug, Serialize)]
pub struct AppConfig {
    /// The name of the node
    name: String,
    /// All the node definitions in the unscoped config
    nodes: HashMap<String, NodeDefinition>,
    /// The chains config
    chains: Vec<ChainConfig>,
    /// Non config peers probably from the CLI
    peers: Vec<String>,
    /// Store all paths in the paths engine
    paths: PathsEngine,
    /// The config yaml path
    config_yaml: PathBuf,
    /// Set the Open Telemetry collector grpc endpoint. Eg. 127.0.0.1:4317
    otel: Option<String>,
    /// If a net key has not been set autogenerate one on start
    autonetkey: bool,
    /// If a password has not been set autogenerate one on start
    autopassword: bool,
    /// If a wallet has not been set autogenerate one on start
    autowallet: bool,
    /// Program config
    program: ProgramConfig,
    /// A custom bb implementation has been provided do not download and checksum a binary
    using_custom_bb: bool,
    /// Resolved P2P network identity. This value is derived from user configuration.
    #[serde(skip)]
    network: NetworkProfile,
}

#[derive(Debug, Clone)]
pub enum BBPath {
    Custom(PathBuf),
    Default(PathBuf),
}

impl BBPath {
    pub fn is_custom(&self) -> bool {
        matches!(self, BBPath::Custom(_))
    }

    pub fn path(&self) -> PathBuf {
        match self {
            BBPath::Custom(p) => p.clone(),
            BBPath::Default(p) => p.clone(),
        }
    }

    /// Check the environment variable and if found use that otherwise use the given path
    pub fn check(default_path: PathBuf) -> Result<Self> {
        let bb_path = if let Ok(bb_path) = env::var("E3_CUSTOM_BB") {
            BBPath::Custom(bb_path.into())
        } else {
            BBPath::Default(default_path)
        };
        Ok(bb_path)
    }
}

impl AppConfig {
    pub fn try_from_unscoped(
        name: &str,
        config: UnscopedAppConfig,
        default_data_dir: &PathBuf,
        default_config_dir: &PathBuf,
        cwd: &PathBuf,
    ) -> Result<Self> {
        let mut config = config;

        if config.nodes.contains_key("_default") {
            bail!("Cannot use the `_default` node profile name as it is a reserved node name. In order to configure the _default profile use the `node` key in your yaml configuration.");
        }

        // Deliberately clobber default
        config.nodes.insert("_default".to_string(), config.node);

        let Some(node) = config.nodes.get(name) else {
            bail!("Could not find node definition for node '{}'. Did you forget to include it in your configuration?", name);
        };

        let mut node = node.clone();
        if node.startup_timeout_secs == 0 {
            bail!("node.startup_timeout_secs must be greater than zero");
        }
        if node.max_buffered_evm_events == 0 {
            bail!("node.max_buffered_evm_events must be greater than zero");
        }
        if node.max_buffered_net_events == 0 {
            bail!("node.max_buffered_net_events must be greater than zero");
        }
        if node.max_buffered_net_bytes == 0 {
            bail!("node.max_buffered_net_bytes must be greater than zero");
        }

        let network =
            NetworkProfile::resolve(node.network.as_deref(), node.network_id, &config.chains)?;
        node.network = Some(network.name().to_string());
        node.network_id = Some(network.id());
        node.peers = network.normalize_explicit_peers(node.peers)?;
        config.nodes.insert(name.to_string(), node.clone());

        let config_dir_override = (node.config_dir != PathBuf::new())
            .then_some(&node.config_dir)
            .or(config.config_dir.as_ref());

        let data_dir_override = (node.data_dir != PathBuf::new())
            .then_some(&node.data_dir)
            .or(config.data_dir.as_ref());

        let paths = PathsEngine::new(
            name,
            cwd,
            default_data_dir,
            default_config_dir,
            config.found_config_file.as_ref(),
            config_dir_override,
            data_dir_override,
            Some(&node.db_file),
            Some(&node.key_file),
            Some(&node.log_file),
            config.custom_bb.as_ref(),
        );
        let found_config_file = config.found_config_file.clone();
        Ok(AppConfig {
            name: name.to_owned(),
            nodes: config.nodes,
            chains: config.chains,
            peers: vec![],
            paths,
            config_yaml: found_config_file.clone().unwrap_or_default(),
            otel: config.otel,
            autopassword: node.autopassword,
            autowallet: node.autowallet,
            autonetkey: node.autonetkey,
            program: config.program.unwrap_or_default(),
            using_custom_bb: config.custom_bb.is_some(),
            network,
        })
    }

    /// Add the given peers to the peers vector
    pub fn add_peers(&mut self, peers: Vec<String>) -> Result<()> {
        let peers = self.network.normalize_explicit_peers(peers)?;
        self.peers = combine_unique(&self.peers, &peers);
        Ok(())
    }

    /// Get the key_file
    pub fn key_file(&self) -> PathBuf {
        self.paths.key_file()
    }

    /// Get the database file
    pub fn db_file(&self) -> PathBuf {
        self.paths.db_file()
    }

    /// Get the log file
    pub fn log_file(&self) -> PathBuf {
        self.paths.log_file()
    }

    /// Get the bb binary path
    pub fn bb_binary(&self) -> BBPath {
        let bb = self.paths.bb_binary();
        if self.using_custom_bb {
            BBPath::Custom(bb)
        } else {
            BBPath::Default(bb)
        }
    }

    /// Whether the config is changed from the default
    pub fn using_custom_config(&self) -> bool {
        !self.paths.is_default_config_file()
    }

    /// Get the circuits directory
    pub fn circuits_dir(&self) -> PathBuf {
        self.paths.circuits_dir()
    }

    /// Get the work directory for this node
    pub fn work_dir(&self) -> PathBuf {
        self.paths.work_dir(&self.name)
    }

    fn node_def(&self) -> &NodeDefinition {
        // NOTE: on creation an invariant we have is that our node name is an extant key in our
        // nodes datastructure so expect here is ok and we dont have to clone the NodeDefinition
        self.nodes
            .get(&self.name)
            .unwrap_or_else(|| panic!("Could not find node definition for node '{}'.", &self.name))
    }

    /// Use the in-memory store
    pub fn use_in_mem_store(&self) -> bool {
        // Currently hardcoded to true. In the future we can allow this to be set within the
        // configuration for testing
        false
    }

    /// Get the peers list
    pub fn peers(&self) -> Vec<String> {
        let config_peers = self.node_def().peers.clone();
        let cli_peers = self.peers.clone();
        self.network
            .resolve_peers(combine_unique(&config_peers, &cli_peers))
            .expect("active node peers were validated during configuration load")
    }

    /// Get the immutable P2P network profile for this node.
    pub fn network(&self) -> &NetworkProfile {
        &self.network
    }

    /// get the quic port
    pub fn quic_port(&self) -> u16 {
        self.node_def().quic_port
    }

    /// get the ctrl port
    pub fn ctrl_port(&self) -> u16 {
        self.node_def().ctrl_port
    }

    /// Get the config file path
    pub fn config_file(&self) -> PathBuf {
        self.paths.config_file()
    }

    /// Get the config yaml path
    pub fn config_yaml(&self) -> PathBuf {
        self.config_yaml.clone()
    }

    /// Get the chains config
    pub fn chains(&self) -> &Vec<ChainConfig> {
        &self.chains
    }

    pub fn name(&self) -> String {
        self.name.clone()
    }

    /// Get the open telemetry collector url
    pub fn otel(&self) -> Option<String> {
        self.otel.clone()
    }

    /// Get the node's address
    pub fn address(&self) -> Option<Address> {
        self.node_def().address
    }

    /// Get a collection containing all the node definitions from the configuration
    pub fn nodes(&self) -> &HashMap<String, NodeDefinition> {
        &self.nodes
    }

    /// Get the value of autonetkey
    pub fn autonetkey(&self) -> bool {
        self.autonetkey
    }

    /// Get the value of autowallet
    pub fn autowallet(&self) -> bool {
        self.autowallet
    }

    /// Get the value of autopassword
    pub fn autopassword(&self) -> bool {
        self.autopassword
    }

    pub fn program(&self) -> &ProgramConfig {
        &self.program
    }

    /// Get the optional dashboard port
    pub fn dashboard_port(&self) -> Option<u16> {
        self.node_def().dashboard_port
    }

    /// CPUs reserved for non-compute work (Actix, networking, RPC).
    pub fn multithread_reserve_threads(&self) -> usize {
        self.node_def().multithread_reserve_threads
    }

    /// Optional cap on concurrent ZK / TrBFV pool jobs. When `None`, the node uses all CPUs minus
    /// [`Self::multithread_reserve_threads`].
    pub fn multithread_concurrent_jobs(&self) -> Option<usize> {
        self.node_def().multithread_concurrent_jobs
    }

    /// Maximum time allowed for construction and initial synchronization.
    pub fn startup_timeout_secs(&self) -> u64 {
        self.node_def().startup_timeout_secs
    }

    /// Maximum per-chain decoded-event buffer used before EVM gateways become live.
    pub fn max_buffered_evm_events(&self) -> usize {
        self.node_def().max_buffered_evm_events
    }

    /// Maximum count retained by the network startup buffer.
    pub fn max_buffered_net_events(&self) -> usize {
        self.node_def().max_buffered_net_events
    }

    /// Maximum estimated bytes retained by the network startup buffer.
    pub fn max_buffered_net_bytes(&self) -> usize {
        self.node_def().max_buffered_net_bytes
    }

    /// Whether this node requests the compile-time-gated proof aggregation skip for test/CI runs.
    pub fn skip_proof_aggregation(&self) -> bool {
        self.node_def().skip_proof_aggregation
    }
}

#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct UnscopedAppConfig {
    /// The chains config
    chains: Vec<ChainConfig>,
    /// The base folder for interfold configuration defaults to `~/.config/interfold` on linux
    config_dir: Option<PathBuf>,
    /// The data dir for interfold defaults to `~/.local/share/interfold`
    data_dir: Option<PathBuf>,
    /// The config file as found before initialization this is for testing purposes and you should
    /// not use this in your configurations
    found_config_file: Option<PathBuf>, // This is set regardless as the file is resolved
    /// The default node that runs during commands like `interfold start` without supplying the
    /// `--name` argument.
    node: NodeDefinition,
    /// The `nodes` key in configuration
    nodes: HashMap<String, NodeDefinition>,
    /// Set the Open Telemetry collector grpc endpoint. Eg. 127.0.0.1:4317
    otel: Option<String>,
    /// Program config
    program: Option<ProgramConfig>,
    /// Path to custom bb binary. When this is set the bb binary is used will not be checksummed it
    /// is up to the node operator to ensure bb matches the version that exactly matches the
    /// application.
    custom_bb: Option<PathBuf>,
}

impl UnscopedAppConfig {
    /// Convert to a scoped configuration using local OS based default configuration
    pub fn into_scoped(self, name: &str) -> Result<AppConfig> {
        AppConfig::try_from_unscoped(
            name,
            self,
            &OsDirs::data_dir(),
            &OsDirs::config_dir(),
            &env::current_dir()?,
        )
    }

    /// Convert to a scoped configuration passing in some injected configuration
    pub fn into_scoped_with_defaults(
        self,
        name: &str,
        default_data_dir: &PathBuf,
        default_config_dir: &PathBuf,
        cwd: &PathBuf,
    ) -> Result<AppConfig> {
        AppConfig::try_from_unscoped(name, self, default_data_dir, default_config_dir, cwd)
    }
}

/// Value struct for passing configuration from the cli to the configuration
#[derive(Default, Serialize, Deserialize, Clone, Debug)]
struct CliOverrides {
    pub otel: Option<String>,
    pub found_config_file: Option<PathBuf>,
    pub using_custom_config: bool,
}

/// Load the config at the config_file or the default location if not provided
pub fn load_config(
    name: &str,
    found_config_file: Option<String>,
    otel: Option<String>,
) -> Result<AppConfig> {
    let found_config_file = found_config_file.map(PathBuf::from);
    let resolved_config_path = resolve_config_path(
        find_in_parent,            // finding strategy
        env::current_dir()?,       // cwd
        OsDirs::config_dir(),      // default config folder
        DEFAULT_CONFIG_NAME,       // hardcoded now to interfold.config.yaml
        found_config_file.clone(), // config file we have found to exist
    );

    let loaded_yaml =
        load_yaml_with_env(&resolved_config_path).context("Configuration file not found")?;

    let config: UnscopedAppConfig =
        Figment::from(Serialized::defaults(&UnscopedAppConfig::default()))
            .merge(Yaml::string(&loaded_yaml))
            .merge(Env::prefixed("E3_").split("__"))
            .merge(Serialized::defaults(&CliOverrides {
                otel,
                found_config_file: Some(resolved_config_path),
                using_custom_config: found_config_file.is_some(),
            }))
            .extract()
            .context("Could not parse configuration")?;

    config.into_scoped(name).context(format!(
        "Could not apply scope '{}' to configuration.",
        name
    ))
}

pub struct OsDirs;
impl OsDirs {
    pub fn config_dir() -> PathBuf {
        dirs::config_dir()
            .expect("Interfold may only be run on an OS that can provide a config dir. See https://docs.rs/dirs for more information.")
            .join("interfold")
    }

    pub fn data_dir() -> PathBuf {
        dirs::data_local_dir()
            .expect("Interfold may only be run on an OS that can provide a data dir. See https://docs.rs/dirs for more information.")
            .join("interfold")
    }
}

// TODO: Put this in a universal utils lib
pub fn combine_unique<T: Eq + std::hash::Hash + Clone + Ord>(a: &[T], b: &[T]) -> Vec<T> {
    let mut combined_set: HashSet<_> = a.iter().cloned().collect();
    combined_set.extend(b.iter().cloned());
    let mut result: Vec<_> = combined_set.into_iter().collect();
    result.sort();
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program_config::OpenVmConfig;
    use crate::rpc::RpcAuth;
    use figment::Jail;

    #[test]
    fn test_deserialization() -> Result<()> {
        let config_str = r#"
data_dir: "/mydata/interfold"
config_dir: "/myconfig/interfold"
chains:
  - name: "hardhat"
    rpc_url: "ws://localhost:8545"
    rpc_auth:
      type: "Basic"
      credentials:
        username: "testUser"
        password: "testPassword"
    contracts:
      interfold: "0x9fE46736679d2D9a65F0992F2272dE9f3c7fa6e0"
      ciphernode_registry:
        address: "0xCf7Ed3AccA5a467e9e704C703E8D87F634fB0Fc9"
        deploy_block: 1764352873645
      bonding_registry: "0xDc64a140Aa3E981100a9becA4E685f962f0cF6C9"

node:
  config_dir: "/myconfig/override"
  db_file: "./foo"
  quic_port: 1234

program:
  openvm:
    repository: "/deployment/source"
    prover_bin: "/deployment/bin/interfold-openvm-prover"
    prover_config: "/deployment/prover.json"

nodes:
  ag:
    quic_port: 1235
    peers:
      - "one"
      - "two"

"#;
        {
            // investigate default serialization
            let unscoped: UnscopedAppConfig = serde_yaml::from_str(config_str).unwrap();
            let config = unscoped
                .into_scoped_with_defaults(
                    "_default",
                    &PathBuf::from("/default/data"),
                    &PathBuf::from("/default/config"),
                    &PathBuf::from("/my/cwd"),
                )
                .unwrap();
            assert_eq!(
                config.db_file(),
                PathBuf::from("/mydata/interfold/_default/foo")
            );
            assert_eq!(
                config.key_file(),
                PathBuf::from("/myconfig/override/_default/key")
            );
            assert_eq!(config.quic_port(), 1234);
            assert_eq!(
                config.program().openvm(),
                Some(&OpenVmConfig {
                    repository: PathBuf::from("/deployment/source"),
                    prover_bin: PathBuf::from("/deployment/bin/interfold-openvm-prover"),
                    prover_config: PathBuf::from("/deployment/prover.json"),
                })
            );
            assert!(config.peers().is_empty());
        };
        {
            // investigate ag serialization
            let unscoped: UnscopedAppConfig = serde_yaml::from_str(config_str).unwrap();
            let config = unscoped
                .into_scoped_with_defaults(
                    "ag",
                    &PathBuf::from("/default/data"),
                    &PathBuf::from("/default/config"),
                    &PathBuf::from("/my/cwd"),
                )
                .unwrap();
            let chain = config.chains().first().unwrap();
            assert_eq!(config.quic_port(), 1235);
            assert_eq!(
                chain.contracts.ciphernode_registry.address_str(),
                "0xCf7Ed3AccA5a467e9e704C703E8D87F634fB0Fc9"
            );
            assert_eq!(config.peers(), vec!["one", "two"]);
            assert_eq!(
                config.config_file(),
                PathBuf::from("/default/config/interfold.config.yaml")
            );
            assert_eq!(config.db_file(), PathBuf::from("/mydata/interfold/ag/db"));
            assert_eq!(
                config.key_file(),
                PathBuf::from("/myconfig/interfold/ag/key")
            );
        };
        Ok(())
    }

    #[test]
    fn crisp_local_config_selects_only_the_local_network() -> Result<()> {
        let yaml = include_str!("../../../examples/CRISP/interfold.config.yaml");

        for name in ["_default", "cn1"] {
            let config: UnscopedAppConfig = serde_yaml::from_str(yaml)?;
            let config = config.into_scoped_with_defaults(
                name,
                &PathBuf::from("/default/data"),
                &PathBuf::from("/default/config"),
                &PathBuf::from("/crisp"),
            )?;

            assert_eq!(config.network().name(), "local");
            assert_eq!(
                config
                    .chains()
                    .iter()
                    .filter(|chain| chain.enabled.unwrap_or(true))
                    .map(|chain| chain.name.as_str())
                    .collect::<Vec<_>>(),
                vec!["localhost"]
            );
        }

        Ok(())
    }

    #[test]
    fn test_defaults() {
        Jail::expect_with(|jail| {
            let home = std::env::var("HOME").unwrap_or_else(|_| "/home/testuser".to_string());
            jail.set_env("HOME", &home);

            let config = UnscopedAppConfig::default()
                .into_scoped("_default")
                .map_err(|e| e.to_string())?;

            // Use the actual platform directories instead of hardcoded paths.
            let expected_config_dir = OsDirs::config_dir();
            let expected_data_dir = OsDirs::data_dir();

            assert_eq!(
                config.key_file(),
                expected_config_dir.join("_default").join("key")
            );

            assert_eq!(
                config.db_file(),
                expected_data_dir.join("_default").join("db")
            );

            assert_eq!(
                config.config_file(),
                expected_config_dir.join("interfold.config.yaml")
            );

            Ok(())
        });
    }

    #[test]
    fn test_file_not_found() -> Result<()> {
        let Err(err) = load_config("_default", Some("/nope".to_string()), None) else {
            bail!("error expected");
        };
        let Some(e) = err.downcast_ref::<std::io::Error>() else {
            bail!("io error expected");
        };

        assert_eq!(e.kind(), std::io::ErrorKind::NotFound);

        Ok(())
    }

    #[test]
    fn test_config() {
        Jail::expect_with(|jail| {
            let home = format!("{}", jail.directory().to_string_lossy());
            jail.set_env("HOME", &home);
            jail.set_env("XDG_CONFIG_HOME", format!("{}/.config", home));

            let expected_config_dir = OsDirs::config_dir();
            let filename = expected_config_dir.join("interfold.config.yaml");
            jail.create_dir(&expected_config_dir)?;
            jail.create_file(
                filename.clone(),
                r#"
chains:
  - name: "hardhat"
    rpc_url: "ws://localhost:8545"
    rpc_auth:
      type: "Basic"
      credentials:
        username: "testUser"
        password: "testPassword"
    contracts:
      interfold: "0x9fE46736679d2D9a65F0992F2272dE9f3c7fa6e0"
      ciphernode_registry:
        address: "0xCf7Ed3AccA5a467e9e704C703E8D87F634fB0Fc9"
        deploy_block: 1764352873645
      bonding_registry: "0xDc64a140Aa3E981100a9becA4E685f962f0cF6C9"
"#,
            )?;

            let mut config = load_config("_default", None, None).map_err(|err| err.to_string())?;

            let mut chain = config.chains().first().unwrap();

            assert_eq!(chain.name, "hardhat");
            assert_eq!(chain.rpc_url, "ws://localhost:8545");
            assert_eq!(
                chain.contracts.interfold.address_str(),
                "0x9fE46736679d2D9a65F0992F2272dE9f3c7fa6e0"
            );
            assert_eq!(
                chain.contracts.ciphernode_registry.address_str(),
                "0xCf7Ed3AccA5a467e9e704C703E8D87F634fB0Fc9"
            );
            assert_eq!(
                chain.rpc_auth,
                RpcAuth::Basic {
                    username: "testUser".to_string(),
                    password: "testPassword".to_string(),
                }
            );
            assert_eq!(chain.contracts.interfold.deploy_block(), None);
            assert_eq!(
                chain.contracts.ciphernode_registry.deploy_block(),
                Some(1764352873645)
            );

            jail.create_file(
                filename.clone(),
                r#"
chains:
  - name: "hardhat"
    rpc_url: "ws://localhost:8545"
    contracts:
      interfold: "0x9fE46736679d2D9a65F0992F2272dE9f3c7fa6e0"
      ciphernode_registry:
        address: "0xCf7Ed3AccA5a467e9e704C703E8D87F634fB0Fc9"
        deploy_block: 1764352873645
      bonding_registry: "0xDc64a140Aa3E981100a9becA4E685f962f0cF6C9"
"#,
            )?;
            config = load_config("_default", None, None).map_err(|err| err.to_string())?;
            chain = config.chains().first().unwrap();

            assert_eq!(chain.rpc_auth, RpcAuth::None);

            jail.create_file(
                filename,
                r#"
chains:
  - name: "hardhat"
    rpc_url: "ws://localhost:8545"
    rpc_auth:
      type: "Bearer"
      credentials: "testToken"
    contracts:
      interfold: "0x9fE46736679d2D9a65F0992F2272dE9f3c7fa6e0"
      ciphernode_registry:
        address: "0xCf7Ed3AccA5a467e9e704C703E8D87F634fB0Fc9"
        deploy_block: 1764352873645
      bonding_registry: "0xDc64a140Aa3E981100a9becA4E685f962f0cF6C9"
"#,
            )?;

            config = load_config("_default", None, None).map_err(|err| err.to_string())?;
            chain = config.chains().first().unwrap();
            assert_eq!(chain.rpc_auth, RpcAuth::Bearer("testToken".to_string()));

            Ok(())
        });
    }

    #[test]
    fn test_multithread_config() -> Result<()> {
        let config_str = r#"
node:
  multithread_reserve_threads: 2
  multithread_concurrent_jobs: 4
"#;
        let unscoped: UnscopedAppConfig = serde_yaml::from_str(config_str)?;
        let config = unscoped.into_scoped_with_defaults(
            "_default",
            &PathBuf::from("/default/data"),
            &PathBuf::from("/default/config"),
            &PathBuf::from("/my/cwd"),
        )?;
        assert_eq!(config.multithread_reserve_threads(), 2);
        assert_eq!(config.multithread_concurrent_jobs(), Some(4));
        Ok(())
    }

    #[test]
    fn test_skip_proof_aggregation_defaults_off_and_can_be_enabled() -> Result<()> {
        let configured: UnscopedAppConfig = serde_yaml::from_str(
            r#"
node:
  skip_proof_aggregation: true
"#,
        )?;
        let configured = configured.into_scoped_with_defaults(
            "_default",
            &PathBuf::from("/default/data"),
            &PathBuf::from("/default/config"),
            &PathBuf::from("/my/cwd"),
        )?;
        assert!(configured.skip_proof_aggregation());

        let default = UnscopedAppConfig::default().into_scoped_with_defaults(
            "_default",
            &PathBuf::from("/default/data"),
            &PathBuf::from("/default/config"),
            &PathBuf::from("/my/cwd"),
        )?;
        assert!(!default.skip_proof_aggregation());
        Ok(())
    }

    #[test]
    fn test_skip_proof_aggregation_can_be_enabled_for_named_node_via_env() {
        Jail::expect_with(|jail| {
            jail.set_env("E3_NODES__CN1__SKIP_PROOF_AGGREGATION", "true");

            let config: UnscopedAppConfig =
                Figment::from(Serialized::defaults(&UnscopedAppConfig::default()))
                    .merge(Env::prefixed("E3_").split("__"))
                    .extract()
                    .map_err(|err| err.to_string())?;
            let config = config
                .into_scoped_with_defaults(
                    "cn1",
                    &PathBuf::from("/default/data"),
                    &PathBuf::from("/default/config"),
                    &PathBuf::from("/my/cwd"),
                )
                .map_err(|err| err.to_string())?;

            assert!(config.skip_proof_aggregation());
            Ok(())
        });
    }

    #[test]
    fn test_startup_timeout_config_and_default() -> Result<()> {
        let configured: UnscopedAppConfig = serde_yaml::from_str(
            r#"
node:
  startup_timeout_secs: 42
  max_buffered_evm_events: 12345
  max_buffered_net_events: 321
  max_buffered_net_bytes: 654321
"#,
        )?;
        let configured = configured.into_scoped_with_defaults(
            "_default",
            &PathBuf::from("/default/data"),
            &PathBuf::from("/default/config"),
            &PathBuf::from("/my/cwd"),
        )?;
        assert_eq!(configured.startup_timeout_secs(), 42);
        assert_eq!(configured.max_buffered_evm_events(), 12_345);
        assert_eq!(configured.max_buffered_net_events(), 321);
        assert_eq!(configured.max_buffered_net_bytes(), 654_321);

        let default = UnscopedAppConfig::default().into_scoped_with_defaults(
            "_default",
            &PathBuf::from("/default/data"),
            &PathBuf::from("/default/config"),
            &PathBuf::from("/my/cwd"),
        )?;
        assert_eq!(default.startup_timeout_secs(), 30 * 60);
        assert_eq!(default.max_buffered_evm_events(), 100_000);
        assert_eq!(default.max_buffered_net_events(), 1_024);
        assert_eq!(default.max_buffered_net_bytes(), 256 * 1024 * 1024);
        Ok(())
    }

    #[test]
    fn test_zero_startup_timeout_is_rejected() -> Result<()> {
        let unscoped: UnscopedAppConfig = serde_yaml::from_str(
            r#"
node:
  startup_timeout_secs: 0
"#,
        )?;
        let error = unscoped
            .into_scoped_with_defaults(
                "_default",
                &PathBuf::from("/default/data"),
                &PathBuf::from("/default/config"),
                &PathBuf::from("/my/cwd"),
            )
            .expect_err("zero startup timeout must fail configuration");
        assert!(error
            .to_string()
            .contains("startup_timeout_secs must be greater than zero"));
        Ok(())
    }

    #[test]
    fn test_zero_evm_buffer_limit_is_rejected() -> Result<()> {
        let unscoped: UnscopedAppConfig = serde_yaml::from_str(
            r#"
node:
  max_buffered_evm_events: 0
"#,
        )?;
        let error = unscoped
            .into_scoped_with_defaults(
                "_default",
                &PathBuf::from("/default/data"),
                &PathBuf::from("/default/config"),
                &PathBuf::from("/my/cwd"),
            )
            .expect_err("zero EVM buffer limit must fail configuration");
        assert!(error
            .to_string()
            .contains("max_buffered_evm_events must be greater than zero"));
        Ok(())
    }

    #[test]
    fn test_zero_network_buffer_limits_are_rejected() -> Result<()> {
        for field in ["max_buffered_net_events", "max_buffered_net_bytes"] {
            let yaml = format!("node:\n  {field}: 0\n");
            let unscoped: UnscopedAppConfig = serde_yaml::from_str(&yaml)?;
            let error = unscoped
                .into_scoped_with_defaults(
                    "_default",
                    &PathBuf::from("/default/data"),
                    &PathBuf::from("/default/config"),
                    &PathBuf::from("/my/cwd"),
                )
                .expect_err("zero network buffer limit must fail configuration");
            assert!(
                error.to_string().contains(field),
                "unexpected validation error for {field}: {error}"
            );
        }
        Ok(())
    }

    #[test]
    fn test_config_env_vars() {
        Jail::expect_with(|jail| {
            let home = format!("{}", jail.directory().to_string_lossy());
            jail.set_env("HOME", &home);
            jail.set_env("XDG_CONFIG_HOME", format!("{}/.config", home));
            jail.set_env("TEST_RPC_URL_PORT", "8545");
            jail.set_env("TEST_USERNAME", "envUser");
            jail.set_env("TEST_PASSWORD", "envPassword");
            jail.set_env(
                "TEST_CONTRACT_ADDRESS",
                "0x1234567890123456789012345678901234567890",
            );

            let expected_config_dir = OsDirs::config_dir();
            let filename = expected_config_dir.join("interfold.config.yaml");
            jail.create_dir(&expected_config_dir)?;
            jail.create_file(
                filename,
                r#"
chains:
  - name: "hardhat"
    rpc_url: "ws://test-endpoint:${TEST_RPC_URL_PORT}"
    rpc_auth:
      type: "Basic"
      credentials:
        username: "${TEST_USERNAME}"
        password: "${TEST_PASSWORD}"
    contracts:
      interfold: "${TEST_CONTRACT_ADDRESS}"
      ciphernode_registry:
        address: "0xCf7Ed3AccA5a467e9e704C703E8D87F634fB0Fc9"
        deploy_block: 1764352873645
      bonding_registry: "0xDc64a140Aa3E981100a9becA4E685f962f0cF6C9"
"#,
            )?;

            let config = load_config("_default", None, None).map_err(|err| err.to_string())?;
            let chain = config.chains().first().unwrap();

            // Test that environment variables are properly substituted
            assert_eq!(chain.rpc_url, "ws://test-endpoint:8545");
            assert_eq!(
                chain.rpc_auth,
                RpcAuth::Basic {
                    username: "envUser".to_string(),
                    password: "envPassword".to_string(),
                }
            );
            assert_eq!(
                chain.contracts.interfold.address_str(),
                "0x1234567890123456789012345678901234567890"
            );

            Ok(())
        });
    }
}
