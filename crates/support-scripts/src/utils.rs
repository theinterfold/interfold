// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use anyhow::{bail, Result};
use duct::cmd;
use std::path::{Path, PathBuf};
use tokio::fs;
use tokio::signal;

pub async fn run_bash_script(cwd: &PathBuf, script: &Path, args: &[&str]) -> Result<()> {
    let mut cmd_args = vec!["bash".to_string(), script.to_string_lossy().to_string()];
    cmd_args.extend(args.iter().map(|s| s.to_string()));

    // Note this will not end up on shell history
    let expression = cmd("bash", &cmd_args[1..]).dir(cwd);

    let handle = expression.start()?;

    tokio::select! {
        result = async { handle.wait() } => {
            match result {
                Ok(output) => {
                    if output.status.success() {
                        Ok(())
                    } else {
                        bail!("{} failed with exit code: {:?}", script.display(), output.status.code());
                    }
                }
                Err(e) => Err(e.into()),
            }
        }
        _ = signal::ctrl_c() => {
            let _ = handle.kill();
            bail!("Script interrupted by user");
        }
    }
}

pub async fn ensure_script_exists(script_path: &PathBuf) -> Result<()> {
    if !fs::try_exists(script_path).await? {
        bail!("Invalid or corrupted project. This command can only be run from within a valid Interfold project.");
    }
    Ok(())
}
