// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

mod program;
mod program_dev;
mod program_openvm;
mod traits;
mod utils;

use anyhow::Result;
use e3_config::ProgramConfig;
use program::ProgramSupport;
use std::env;
use tokio::fs;
use traits::ProgramSupportApi;

pub async fn program_compile(program_config: ProgramConfig, is_dev: Option<bool>) -> Result<()> {
    ProgramSupport::new(program_config, is_dev).compile().await
}

pub async fn program_start(program_config: ProgramConfig, is_dev: Option<bool>) -> Result<()> {
    ProgramSupport::new(program_config, is_dev).start().await
}

/// Purge all build caches from support
pub async fn program_cache_purge() -> Result<()> {
    let cwd = env::current_dir()?;
    let caches = cwd.join(".interfold/caches");
    fs::remove_dir_all(caches).await?;
    Ok(())
}
