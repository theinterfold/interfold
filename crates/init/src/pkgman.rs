// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use anyhow::{bail, Result};
use std::{env, path::PathBuf};
use tokio::process::Command as TokioCommand;

#[async_trait::async_trait]
pub trait PkgStrategy {
    fn cmd(&self) -> &'static str;

    async fn available(&self) -> bool {
        TokioCommand::new(self.cmd())
            .arg("--version")
            .output()
            .await
            .map(|output| output.status.success())
            .unwrap_or(false)
    }

    async fn run(&self, cwd: &PathBuf, args: &[&str]) -> Result<()> {
        if !self.available().await {
            bail!("{} is not installed or not available in PATH", self.cmd());
        }

        let status = TokioCommand::new(self.cmd())
            .args(args)
            .current_dir(cwd)
            .status()
            .await?;

        if status.success() {
            Ok(())
        } else {
            bail!(
                "{} command failed with exit code: {:?}",
                self.cmd(),
                status.code()
            );
        }
    }
}

struct Npm;

#[async_trait::async_trait]
impl PkgStrategy for Npm {
    fn cmd(&self) -> &'static str {
        "npm"
    }
}

struct Pnpm;

#[async_trait::async_trait]
impl PkgStrategy for Pnpm {
    fn cmd(&self) -> &'static str {
        "pnpm"
    }
}

type PkgType = dyn PkgStrategy + Send + Sync;

pub struct PkgMan {
    strategy: Box<PkgType>,
    cwd: PathBuf,
}

#[allow(dead_code)]
#[allow(clippy::upper_case_acronyms)]
pub enum PkgManKind {
    NPM,
    PNPM,
}

impl PkgMan {
    pub fn new(kind: PkgManKind) -> Result<Self> {
        let strategy: Box<PkgType> = match kind {
            PkgManKind::NPM => Box::new(Npm),
            PkgManKind::PNPM => Box::new(Pnpm),
            // TODO: yarn
        };

        Ok(Self {
            strategy,
            cwd: env::current_dir()?,
        })
    }

    pub fn with_cwd(mut self, cwd: impl Into<PathBuf>) -> Self {
        self.cwd = cwd.into();
        self
    }

    #[allow(dead_code)]
    pub async fn available(&self) -> bool {
        self.strategy.available().await
    }

    pub async fn run(&self, args: &[&str]) -> Result<()> {
        self.strategy.run(&self.cwd, args).await
    }
}
