// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use anyhow::Result;
use async_trait::async_trait;
use e3_config::ProgramConfig;

use crate::{
    program_dev::ProgramSupportDev, program_risc0::ProgramSupportRisc0, traits::ProgramSupportApi,
};

fn get_mode(config: ProgramConfig, mode: Option<bool>) -> bool {
    if let Some(m) = mode {
        return m;
    };
    config.dev()
}

pub enum ProgramSupport {
    Dev(ProgramSupportDev),
    Risc0(ProgramSupportRisc0),
}

impl ProgramSupport {
    pub fn new(config: ProgramConfig, mode: Option<bool>) -> ProgramSupport {
        if get_mode(config.clone(), mode) {
            ProgramSupport::Dev(ProgramSupportDev(config))
        } else {
            ProgramSupport::Risc0(ProgramSupportRisc0(config))
        }
    }
}

#[async_trait]
impl ProgramSupportApi for ProgramSupport {
    async fn compile(&self) -> Result<()> {
        match self {
            ProgramSupport::Dev(s) => s.compile().await,
            ProgramSupport::Risc0(s) => s.compile().await,
        }
    }
    async fn start(&self, linux_network_host_mode: bool) -> Result<()> {
        match self {
            ProgramSupport::Dev(s) => s.start(linux_network_host_mode).await,
            ProgramSupport::Risc0(s) => s.start(linux_network_host_mode).await,
        }
    }

    async fn upload(&self) -> Result<()> {
        match self {
            ProgramSupport::Dev(s) => s.upload().await,
            ProgramSupport::Risc0(s) => s.upload().await,
        }
    }
}
