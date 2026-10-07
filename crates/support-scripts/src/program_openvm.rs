// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::{
    traits::ProgramSupportApi,
    utils::{ensure_script_exists, run_bash_script_with_env},
};
use anyhow::{ensure, Context, Result};
use async_trait::async_trait;
use e3_config::ProgramConfig;
use std::env;

/// Proves the project's E3 program with OpenVM, through the project's
/// `.interfold/support/openvm` scripts.
pub struct ProgramSupportOpenVm(pub ProgramConfig);

impl ProgramSupportOpenVm {
    async fn run(&self, script: &str) -> Result<()> {
        let config = self.0.openvm().context(
            "Set program.openvm.prover_bin to the CPU worker, program.openvm.prover_bin_cuda to \
             the CUDA worker, or both",
        )?;
        ensure!(
            config.prover_bin.is_some() || config.prover_bin_cuda.is_some(),
            "Set program.openvm.prover_bin to the CPU worker, program.openvm.prover_bin_cuda to \
             the CUDA worker, or both"
        );

        let mut environment = vec![(
            "OPENVM_BACKEND".to_owned(),
            config.backend.as_str().to_owned(),
        )];
        for (name, path) in [
            ("OPENVM_PROVER_BIN", &config.prover_bin),
            ("OPENVM_PROVER_BIN_CUDA", &config.prover_bin_cuda),
            ("OPENVM_SETUP_DIR", &config.setup_dir),
        ] {
            if let Some(path) = path {
                ensure!(
                    path.is_absolute(),
                    "program.openvm paths must be absolute: {}",
                    path.display()
                );
                environment.push((name.to_owned(), path.to_string_lossy().into_owned()));
            }
        }

        let cwd = env::current_dir()?;
        let script = cwd.join(".interfold/support/openvm").join(script);
        ensure_script_exists(&script).await?;
        run_bash_script_with_env(&cwd, &script, &[], &environment).await
    }
}

#[async_trait]
impl ProgramSupportApi for ProgramSupportOpenVm {
    async fn compile(&self) -> Result<()> {
        self.run("compile").await
    }
    async fn start(&self) -> Result<()> {
        self.run("start").await
    }
}
