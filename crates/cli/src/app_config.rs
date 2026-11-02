// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Application configuration discovery and precedence. Runtime owners receive only their settings.

use crate::program_config::ProgramConfig;
use anyhow::{Context, Result};
use e3_config::{paths_engine::DEFAULT_CONFIG_NAME, AppConfig, OsDirs, UnscopedAppConfig};
use figment::{
    providers::{Env, Format, Serialized, Yaml},
    Figment,
};
use path_clean::clean;
use serde::{Deserialize, Serialize};
use std::{env, fs, path::PathBuf};

#[derive(Debug)]
pub struct ApplicationConfig {
    pub node: AppConfig,
    pub program: ProgramConfig,
}

#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(default)]
struct UnscopedApplicationConfig {
    #[serde(flatten)]
    node: UnscopedAppConfig,
    program: Option<ProgramConfig>,
}

/// A flag that was not given leaves the file or environment value intact.
#[derive(Serialize)]
struct CliOverrides {
    #[serde(skip_serializing_if = "Option::is_none")]
    otel: Option<String>,
    found_config_file: Option<PathBuf>,
    using_custom_config: bool,
}

/// Load one file for node and program commands, then resolve the selected node profile.
pub fn load_config(
    name: &str,
    found_config_file: Option<String>,
    otel: Option<String>,
) -> Result<ApplicationConfig> {
    let found_config_file = found_config_file.map(PathBuf::from);
    let resolved_config_path = resolve_config_path(
        find_in_parent,
        env::current_dir()?,
        OsDirs::config_dir(),
        DEFAULT_CONFIG_NAME,
        found_config_file.clone(),
    );

    let loaded_yaml =
        load_yaml_with_env(&resolved_config_path).context("Configuration file not found")?;

    let config: UnscopedApplicationConfig =
        Figment::from(Serialized::defaults(&UnscopedApplicationConfig::default()))
            .merge(Yaml::string(&loaded_yaml))
            .merge(Env::prefixed("E3_").split("__"))
            .merge(Serialized::defaults(&CliOverrides {
                otel,
                found_config_file: Some(resolved_config_path),
                using_custom_config: found_config_file.is_some(),
            }))
            .extract()
            .context("Could not parse configuration")?;

    let node = config.node.into_scoped(name).context(format!(
        "Could not apply scope '{}' to configuration.",
        name
    ))?;
    Ok(ApplicationConfig {
        node,
        program: config.program.unwrap_or_default(),
    })
}

type FindInParent = fn(&PathBuf, &str) -> Option<PathBuf>;

fn find_in_parent(path: &PathBuf, filename: &str) -> Option<PathBuf> {
    let mut current = PathBuf::from(path);

    loop {
        let file_path = current.join(filename);
        if file_path.exists() {
            return Some(file_path);
        }

        if !current.pop() {
            break;
        }
    }

    None
}

fn resolve_config_path<P: Into<PathBuf>>(
    find_in_parent: FindInParent,
    cwd: P,
    default_config_dir: P,
    default_filename: &str,
    cli_file: Option<P>,
) -> PathBuf {
    let cli_file: Option<PathBuf> = cli_file.map(Into::into);
    let default_config_dir = default_config_dir.into();
    let cwd = cwd.into();

    if let Some(cli_file) = cli_file {
        // config is passed in and is absolute
        if cli_file.is_absolute() {
            return cli_file;
        }

        // config is passed in and is relative
        return clean(cwd.join(cli_file));
    }

    // search from cwd
    if let Some(found) = find_in_parent(&cwd, default_filename) {
        return found;
    }

    // return default
    clean(default_config_dir.join(default_filename))
}

fn load_yaml_with_env(file_path: &PathBuf) -> Result<String> {
    let content = fs::read_to_string(file_path)?;
    Ok(shellexpand::env(&content)?.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program_config::{OpenVmBackend, OpenVmConfig};
    use anyhow::bail;
    use e3_evm_config::RpcAuth;
    use figment::Jail;

    #[test]
    fn test_resolve_cli() -> Result<()> {
        fn not_found(_: &PathBuf, _: &str) -> Option<PathBuf> {
            None
        }
        fn found(_: &PathBuf, _: &str) -> Option<PathBuf> {
            Some(PathBuf::from("/foo/interfold.config.yaml"))
        }
        let path = resolve_config_path(
            not_found,
            PathBuf::from("/foo/bar"),
            PathBuf::from("/my/config"),
            "interfold.config.yaml",
            None,
        );

        assert_eq!(path, PathBuf::from("/my/config/interfold.config.yaml"));

        let path = resolve_config_path(
            found, // should be overridden by config attr
            PathBuf::from("/foo/bar"),
            PathBuf::from("/my/config"),
            "interfold.config.yaml",
            Some(PathBuf::from("/my/absolute/conf.yaml")),
        );

        assert_eq!(path, PathBuf::from("/my/absolute/conf.yaml"));

        let path = resolve_config_path(
            found, // should be overridden by config attr
            PathBuf::from("/foo/bar"),
            PathBuf::from("/my/config"),
            "interfold.config.yaml",
            None,
        );

        assert_eq!(path, PathBuf::from("/foo/interfold.config.yaml"));
        Ok(())
    }

    #[test]
    fn test_yaml_env_substitution() {
        // The jail holds the lock that the other tests that change the environment take, and
        // restores the environment afterwards.
        Jail::expect_with(|jail| {
            jail.create_file(
                "test.yaml",
                "database:\n  url: $MY_DATABASE_URL\n  password: ${MY_DB_PASSWORD}\n",
            )?;
            jail.set_env("MY_DATABASE_URL", "postgres://localhost:5432");
            jail.set_env("MY_DB_PASSWORD", "secret123");

            let processed = load_yaml_with_env(&jail.directory().join("test.yaml"))
                .map_err(|error| error.to_string())?;

            assert!(processed.contains("postgres://localhost:5432"));
            assert!(processed.contains("secret123"));
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

            let mut config = load_config("_default", None, None)
                .map_err(|err| err.to_string())?
                .node;

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
            config = load_config("_default", None, None)
                .map_err(|err| err.to_string())?
                .node;
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

            config = load_config("_default", None, None)
                .map_err(|err| err.to_string())?
                .node;
            chain = config.chains().first().unwrap();
            assert_eq!(chain.rpc_auth, RpcAuth::Bearer("testToken".to_string()));

            Ok(())
        });
    }

    /// `otel` comes from the `--otel` flag, else from `E3_OTEL`, else from the configuration file.
    /// A flag that was not given leaves the others.
    #[test]
    fn otel_comes_from_the_flag_the_environment_or_the_file() {
        Jail::expect_with(|jail| {
            // An `E3_OTEL` of the shell that runs the test must not decide the first case.
            jail.clear_env();
            let home = format!("{}", jail.directory().to_string_lossy());
            jail.set_env("HOME", &home);
            jail.set_env("XDG_CONFIG_HOME", format!("{home}/.config"));
            jail.create_file("interfold.config.yaml", "otel: \"http://from-yaml:4317\"\n")?;
            let otel = |flag: Option<&str>| {
                load_config(
                    "_default",
                    Some("interfold.config.yaml".to_string()),
                    flag.map(str::to_string),
                )
                .map(|config| config.node.otel())
                .map_err(|error| error.to_string())
            };

            assert_eq!(otel(None)?.as_deref(), Some("http://from-yaml:4317"));
            jail.set_env("E3_OTEL", "http://from-env:4317");
            assert_eq!(otel(None)?.as_deref(), Some("http://from-env:4317"));
            assert_eq!(
                otel(Some("http://from-flag:4317"))?.as_deref(),
                Some("http://from-flag:4317")
            );
            Ok(())
        });
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

            let config = load_config("_default", None, None)
                .map_err(|err| err.to_string())?
                .node;
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

    #[test]
    fn test_skip_proof_aggregation_can_be_enabled_for_named_node_via_env() {
        Jail::expect_with(|jail| {
            jail.clear_env();
            jail.set_env("HOME", jail.directory().display().to_string());
            jail.create_file("interfold.config.yaml", "{}")?;
            jail.set_env("E3_NODES__CN1__SKIP_PROOF_AGGREGATION", "true");

            let config = load_config("cn1", None, None).map_err(|error| error.to_string())?;
            assert!(config.node.skip_proof_aggregation());
            Ok(())
        });
    }

    #[test]
    fn program_and_node_settings_use_the_same_file_and_environment() {
        Jail::expect_with(|jail| {
            jail.clear_env();
            jail.set_env("HOME", jail.directory().display().to_string());
            jail.create_file(
                "interfold.config.yaml",
                r#"
node:
  network: local
  quic_port: 1234
program:
  openvm:
    prover_bin: "/deployment/bin/interfold-openvm-prover"
    setup_dir: "/deployment/openvm"
"#,
            )?;
            let config = load_config("_default", None, None).map_err(|error| error.to_string())?;
            assert_eq!(config.node.quic_port(), 1234);
            assert_eq!(
                config.program.openvm(),
                Some(&OpenVmConfig {
                    prover_bin: Some(PathBuf::from("/deployment/bin/interfold-openvm-prover")),
                    setup_dir: Some(PathBuf::from("/deployment/openvm")),
                    ..OpenVmConfig::default()
                })
            );
            assert!(!config.program.dev());

            jail.set_env("E3_NODE__QUIC_PORT", "4321");
            jail.set_env("E3_PROGRAM__DEV", "true");
            jail.set_env("E3_PROGRAM__OPENVM__BACKEND", "cpu");
            let config = load_config("_default", None, None).map_err(|error| error.to_string())?;
            assert_eq!(config.node.quic_port(), 4321);
            assert!(config.program.dev());
            let openvm = config.program.openvm().unwrap();
            assert_eq!(openvm.backend, OpenVmBackend::Cpu);
            assert_eq!(openvm.setup_dir, Some(PathBuf::from("/deployment/openvm")));
            Ok(())
        });
    }
}
