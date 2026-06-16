// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use std::env;

use crate::{
    traits::ProgramSupportApi,
    utils::{ensure_script_exists, run_bash_script},
};
use anyhow::Result;
use async_trait::async_trait;
use e3_config::ProgramConfig;

#[allow(dead_code)]
pub struct ProgramSupportDev(pub ProgramConfig);

#[async_trait]
impl ProgramSupportApi for ProgramSupportDev {
    async fn compile(&self) -> Result<()> {
        let cwd = env::current_dir()?;
        let script = cwd.join(".interfold/support/dev/compile");
        ensure_script_exists(&script).await?;
        run_bash_script(&cwd, &script, &[]).await?;
        Ok(())
    }
    async fn start(&self) -> Result<()> {
        let cwd = env::current_dir()?;
        let script = cwd.join(".interfold/support/dev/start");
        ensure_script_exists(&script).await?;
        run_bash_script(&cwd, &script, &[]).await?;
        Ok(())
    }

    async fn upload(&self) -> Result<()> {
        let cwd = env::current_dir()?;
        let script = cwd.join(".interfold/support/ctl/upload");
        ensure_script_exists(&script).await?;
        run_bash_script(&cwd, &script, &[]).await?;
        Ok(())
    }
}
