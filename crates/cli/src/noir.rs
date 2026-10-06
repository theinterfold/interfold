// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use anyhow::*;
use clap::Subcommand;
use e3_config::AppConfig;
use e3_console::{log, Console};
use e3_zk_prover::{SetupStatus, ZkBackend};
use std::path::PathBuf;

#[derive(Subcommand, Clone, Debug)]
pub enum NoirCommands {
    /// Print the path, version, and install state of `bb` and the circuits, and what to do next
    Status,
    /// Install or update `bb` and the circuits. Does nothing when both are current
    Setup {
        /// Install `bb` and the circuits again, also when they are current
        #[arg(long, short)]
        force: bool,

        /// Install circuits from a local release archive instead of downloading them.
        #[arg(long, value_name = "PATH")]
        circuits_archive: Option<PathBuf>,

        /// Require a preset/committee pair from the local archive. Repeat to select more pairs.
        /// Without this option, require the full supported matrix.
        #[arg(long, value_name = "PRESET/COMMITTEE", requires = "circuits_archive")]
        circuits_configuration: Vec<String>,
    },
}

pub async fn execute(out: Console, command: NoirCommands, config: &AppConfig) -> Result<()> {
    let backend = ZkBackend::new(config.bb_binary(), config.circuits_dir(), config.work_dir());

    match command {
        NoirCommands::Status => {
            execute_status(out, &backend).await?;
        }
        NoirCommands::Setup {
            force,
            circuits_archive,
            circuits_configuration,
        } => {
            execute_setup(
                out,
                &backend,
                force,
                circuits_archive,
                circuits_configuration,
            )
            .await?;
        }
    }

    Ok(())
}

pub async fn execute_without_config(out: Console, command: NoirCommands) -> Result<()> {
    let backend = ZkBackend::with_default_dir("default")
        .map_err(|e| anyhow!("Failed to initialize ZK backend: {}", e))?;

    match command {
        NoirCommands::Status => {
            execute_status(out, &backend).await?;
        }
        NoirCommands::Setup {
            force,
            circuits_archive,
            circuits_configuration,
        } => {
            execute_setup(
                out,
                &backend,
                force,
                circuits_archive,
                circuits_configuration,
            )
            .await?;
        }
    }

    Ok(())
}

async fn execute_status(out: Console, backend: &ZkBackend) -> Result<()> {
    let status = backend.check_status().await;
    let version_info = backend.load_version_info().await;

    log!(out, "=== ZK Prover Status ===\n");

    log!(out, "Barretenberg (bb):");
    log!(out, "  Path: {}", backend.bb_binary.display());
    if let Some(ref v) = version_info.bb_version {
        log!(out, "  Version: {}", v);
    }
    if backend.bb_binary.exists() {
        log!(out, "  Installed");
    } else {
        log!(out, "  Not installed");
    }

    log!(out, "");

    log!(out, "Circuits:");
    log!(out, "  Path: {}", backend.circuits_dir.display());
    log!(
        out,
        "  Required version: {}",
        backend.config.required_circuits_version
    );
    log!(
        out,
        "  Archive SHA-256: {}",
        backend
            .config
            .circuits_checksums
            .get(&backend.config.required_circuits_version)
            .map(String::as_str)
            .unwrap_or("not pinned")
    );
    if let Some(ref v) = version_info.circuits_version {
        log!(out, "  Version: {}", v);
    }
    if backend.circuits_dir.exists() {
        log!(out, "  Installed");
    } else {
        log!(out, "  Not installed");
    }

    log!(out, "");

    match status {
        SetupStatus::Ready => {
            log!(out, "Status: Ready");
        }
        SetupStatus::BbNeedsUpdate {
            installed,
            required,
        } => {
            log!(out, "Status: Barretenberg needs update");
            log!(
                out,
                "  Installed: {}",
                installed.as_deref().unwrap_or("not installed")
            );
            log!(out, "  Required: {}", required);
            log!(out, "\nRun `interfold noir setup` to update");
        }
        SetupStatus::CircuitsNeedUpdate {
            installed,
            required,
        } => {
            log!(out, "Status: Circuits need update");
            log!(
                out,
                "  Installed: {}",
                installed.as_deref().unwrap_or("not installed")
            );
            log!(out, "  Required: {}", required);
            log!(out, "\nRun `interfold noir setup` to update");
        }
        SetupStatus::FullSetupNeeded => {
            log!(out, "Status: Setup required");
            log!(out, "\nRun `interfold noir setup` to install");
        }
    }

    Ok(())
}

async fn execute_setup(
    out: Console,
    backend: &ZkBackend,
    force: bool,
    circuits_archive: Option<PathBuf>,
    circuits_configuration: Vec<String>,
) -> Result<()> {
    log!(out, "Setting up ZK prover...\n");
    log!(
        out,
        "  target bb version:       {}",
        backend.config.required_bb_version
    );
    log!(
        out,
        "  target circuits version: {}\n",
        backend.config.required_circuits_version
    );

    if let Some(archive) = circuits_archive.as_deref() {
        log!(out, "  circuits archive:      {}\n", archive.display());
        let result = if circuits_configuration.is_empty() {
            backend.install_circuits_archive(archive).await
        } else {
            let configurations = circuits_configuration
                .iter()
                .map(|configuration| {
                    configuration.split_once('/').ok_or_else(|| {
                        anyhow!(
                            "Circuit configuration must have the form PRESET/COMMITTEE: {}",
                            configuration
                        )
                    })
                })
                .collect::<Result<Vec<_>>>()?;
            backend
                .install_circuits_archive_for_configurations(archive, &configurations)
                .await
        };
        result.map_err(|e| anyhow!("Failed to install circuits archive: {}", e))?;
    }

    if force {
        log!(out, "Force reinstalling ZK prover components...\n");

        // Force reinstall by directly downloading components
        backend
            .download_bb()
            .await
            .map_err(|e| anyhow!("Failed to download bb: {}", e))?;
        if circuits_archive.is_none() {
            backend
                .download_circuits()
                .await
                .map_err(|e| anyhow!("Failed to download circuits: {}", e))?;
        }
    } else {
        let status = backend.check_status().await;
        if matches!(status, SetupStatus::Ready) {
            let version_info = backend.load_version_info().await;
            log!(out, "ZK prover is already set up and up to date.");
            log!(
                out,
                "  bb version:         {}",
                version_info.bb_version.as_deref().unwrap_or("unknown")
            );
            log!(
                out,
                "  circuits version:   {}",
                version_info
                    .circuits_version
                    .as_deref()
                    .unwrap_or("unknown")
            );
            log!(out, "  Use --force to reinstall.");
            return Ok(());
        }

        backend
            .ensure_installed()
            .await
            .map_err(|e| anyhow!("Setup failed: {}", e))?;
    }

    let version_info = backend.load_version_info().await;

    log!(out, "\nZK prover setup complete!");
    log!(out, "");
    log!(out, "  bb binary:          {}", backend.bb_binary.display());
    log!(
        out,
        "  bb version:         {}",
        version_info.bb_version.as_deref().unwrap_or("unknown")
    );
    log!(
        out,
        "  circuits dir:       {}",
        backend.circuits_dir.display()
    );
    log!(
        out,
        "  circuits version:   {}",
        version_info
            .circuits_version
            .as_deref()
            .unwrap_or("unknown")
    );
    if let Some(ref ts) = version_info.last_updated {
        log!(out, "  last updated:       {}", ts);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use e3_config::BBPath;
    use e3_zk_prover::ZkConfig;

    #[cfg(unix)]
    #[actix::test]
    async fn setup_requires_explicit_archive_subset() {
        use crate::cli::Cli;
        use clap::Parser;
        use e3_zk_prover::VersionInfo;
        use std::{collections::BTreeMap, fs, os::unix::fs::PermissionsExt, process::Command};

        assert!(Cli::try_parse_from([
            "interfold",
            "noir",
            "setup",
            "--circuits-configuration",
            "insecure-512/minimum",
        ])
        .is_err());
        let temp = tempfile::tempdir().unwrap();
        let payload = temp.path().join("payload");
        let artifacts: Vec<&str> =
            serde_json::from_str(include_str!("../../zk-prover/required-artifacts.json")).unwrap();
        let mut files = BTreeMap::new();
        for artifact in &artifacts {
            let relative = format!("insecure-512/minimum/{artifact}");
            let path = payload.join("circuits").join(&relative);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, b"{}").unwrap();
            files.insert(
                relative,
                "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a",
            );
        }
        fs::write(
            payload.join("circuits/checksums.json"),
            serde_json::to_vec(&serde_json::json!({
                "algorithm": "sha256", "generated": "test", "files": files,
            }))
            .unwrap(),
        )
        .unwrap();
        let archive = temp.path().join("circuits.tar.gz");
        assert!(Command::new("tar")
            .arg("-czf")
            .arg(&archive)
            .arg("-C")
            .arg(&payload)
            .arg("circuits")
            .status()
            .unwrap()
            .success());

        let bb = temp.path().join("bb");
        let versions = ZkConfig::default();
        fs::write(
            &bb,
            format!("#!/bin/sh\necho '{}'\n", versions.required_bb_version),
        )
        .unwrap();
        fs::set_permissions(&bb, fs::Permissions::from_mode(0o755)).unwrap();
        let config_file = temp.path().join("config.yaml");
        fs::write(
            &config_file,
            format!(
                "custom_bb: {}\nnode:\n  network: local\n  config_dir: {}\n  data_dir: {}\n",
                bb.display(),
                temp.path().join("config").display(),
                temp.path().join("data").display(),
            ),
        )
        .unwrap();
        let args = [
            "interfold",
            "noir",
            "setup",
            "--circuits-archive",
            archive.to_str().unwrap(),
            "--config",
            config_file.to_str().unwrap(),
        ];
        let cli = Cli::try_parse_from(args).unwrap();
        let config = cli.load_config().unwrap();
        let circuits = config.circuits_dir();
        assert!(circuits.starts_with(temp.path()));
        fs::create_dir_all(&circuits).unwrap();
        fs::write(circuits.join("retained"), b"previous").unwrap();
        let version_file = circuits.parent().unwrap().join("version.json");
        VersionInfo {
            circuits_version: Some("previous".into()),
            ..Default::default()
        }
        .save(&version_file)
        .await
        .unwrap();
        let previous_version = fs::read(&version_file).unwrap();
        let (out, _messages) = Console::channel();
        assert!(cli.execute(out, Ok(config)).await.is_err());
        assert_eq!(fs::read(&version_file).unwrap(), previous_version);
        assert_eq!(fs::read(circuits.join("retained")).unwrap(), b"previous");

        let args = [
            args.as_slice(),
            &["--circuits-configuration", "insecure-512/minimum"],
        ]
        .concat();
        let cli = Cli::try_parse_from(args).unwrap();
        let config = cli.load_config().unwrap();
        let (out, _messages) = Console::channel();
        cli.execute(out, Ok(config)).await.unwrap();
        assert!(!circuits.join("retained").exists());
        let version = VersionInfo::load(&version_file).await.unwrap();
        assert_eq!(
            version.circuits_version,
            Some(versions.required_circuits_version)
        );
        assert_eq!(version.circuits.len(), artifacts.len());
    }

    #[tokio::test]
    async fn status_reports_required_archive_pin() {
        let temp = tempfile::tempdir().unwrap();
        let digest = "a1".repeat(32);
        let mut config = ZkConfig {
            required_circuits_version: "candidate".into(),
            ..Default::default()
        };
        config
            .circuits_checksums
            .insert("candidate".into(), digest.clone());
        let backend = ZkBackend::with_config(
            BBPath::Default(temp.path().join("bb")),
            temp.path().join("circuits"),
            temp.path().join("work"),
            config,
        );
        let (out, mut messages) = Console::channel();
        execute_status(out, &backend).await.unwrap();
        let mut output = Vec::new();
        while let Some(message) = messages.recv().await {
            output.push(message);
        }
        assert!(output.contains(&"  Required version: candidate".to_string()));
        assert!(output.contains(&format!("  Archive SHA-256: {digest}")));
    }
}
