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

#[derive(Subcommand, Clone, Debug)]
pub enum NoirCommands {
    Status,
    Setup {
        #[arg(long, short)]
        force: bool,
    },
}

pub async fn execute(out: Console, command: NoirCommands, config: &AppConfig) -> Result<()> {
    let backend = ZkBackend::new(config.bb_binary(), config.circuits_dir(), config.work_dir());

    match command {
        NoirCommands::Status => {
            execute_status(out, &backend).await?;
        }
        NoirCommands::Setup { force } => {
            execute_setup(out, &backend, force).await?;
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
        NoirCommands::Setup { force } => {
            execute_setup(out, &backend, force).await?;
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

async fn execute_setup(out: Console, backend: &ZkBackend, force: bool) -> Result<()> {
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

    if force {
        log!(out, "Force reinstalling ZK prover components...\n");

        // Force reinstall by directly downloading components
        backend
            .download_bb()
            .await
            .map_err(|e| anyhow!("Failed to download bb: {}", e))?;
        backend
            .download_circuits()
            .await
            .map_err(|e| anyhow!("Failed to download circuits: {}", e))?;
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
