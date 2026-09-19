// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::{traits::ProgramSupportApi, utils::run_bash_script_with_env};
use anyhow::{ensure, Context, Result};
use async_trait::async_trait;
use e3_config::ProgramConfig;

pub struct ProgramSupportOpenVm(pub ProgramConfig);

impl ProgramSupportOpenVm {
    async fn run(&self, action: &str) -> Result<()> {
        let config = self.0.openvm().context(
            "Set program.openvm with the repository, prover_bin, and prover_config paths",
        )?;
        ensure!(
            config.repository.is_absolute(),
            "program.openvm.repository must be an absolute path"
        );
        let script = config.repository.join("scripts/run-openvm.sh");
        ensure!(
            script.is_file(),
            "The OpenVM build script is missing from the configured repository"
        );
        let environment = vec![
            (
                "OPENVM_PROVER_BIN".to_owned(),
                config.prover_bin.to_string_lossy().into_owned(),
            ),
            (
                "OPENVM_PROVER_CONFIG".to_owned(),
                config.prover_config.to_string_lossy().into_owned(),
            ),
        ];
        run_bash_script_with_env(&config.repository, &script, &[action], &environment).await?;
        Ok(())
    }
}

#[async_trait]
impl ProgramSupportApi for ProgramSupportOpenVm {
    async fn compile(&self) -> Result<()> {
        self.run("service-build").await
    }
    async fn start(&self) -> Result<()> {
        self.run("service-start").await
    }
}
