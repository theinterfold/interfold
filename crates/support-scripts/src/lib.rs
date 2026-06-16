// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

mod program;
mod program_dev;
mod program_risc0;
mod traits;
mod utils;

use anyhow::Result;
use e3_config::ProgramConfig;
use program::ProgramSupport;
use std::env;
use tokio::fs;
use traits::ProgramSupportApi;
use utils::{ensure_script_exists, run_bash_script};

pub async fn program_compile(program_config: ProgramConfig, is_dev: Option<bool>) -> Result<()> {
    ProgramSupport::new(program_config, is_dev).compile().await
}

pub async fn program_start(program_config: ProgramConfig, is_dev: Option<bool>) -> Result<()> {
    ProgramSupport::new(program_config, is_dev).start().await
}

/// Upload the compiled program to Pinata IPFS
pub async fn program_upload(program_config: ProgramConfig, is_dev: Option<bool>) -> Result<()> {
    ProgramSupport::new(program_config, is_dev).upload().await
}

/// Open up a shell in the docker container
pub async fn program_shell() -> Result<()> {
    let cwd = env::current_dir()?;
    let script = cwd.join(".interfold/support/ctl/shell");
    ensure_script_exists(&script).await?;
    run_bash_script(&cwd, &script, &[]).await?;
    Ok(())
}

/// Purge all build caches from support
pub async fn program_cache_purge() -> Result<()> {
    let cwd = env::current_dir()?;
    let caches = cwd.join(".interfold/caches");
    fs::remove_dir_all(caches).await?;
    Ok(())
}
