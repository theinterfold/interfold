// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use anyhow::Result;
use async_trait::async_trait;
use e3_config::ProgramConfig;

use crate::{
    program_dev::ProgramSupportDev, program_openvm::ProgramSupportOpenVm, traits::ProgramSupportApi,
};

fn get_mode(config: ProgramConfig, mode: Option<bool>) -> bool {
    if let Some(m) = mode {
        return m;
    };
    config.dev()
}

pub enum ProgramSupport {
    Dev(ProgramSupportDev),
    OpenVm(ProgramSupportOpenVm),
}

impl ProgramSupport {
    pub fn new(config: ProgramConfig, mode: Option<bool>) -> ProgramSupport {
        if get_mode(config.clone(), mode) {
            ProgramSupport::Dev(ProgramSupportDev(config))
        } else {
            ProgramSupport::OpenVm(ProgramSupportOpenVm(config))
        }
    }
}

#[async_trait]
impl ProgramSupportApi for ProgramSupport {
    async fn compile(&self) -> Result<()> {
        match self {
            ProgramSupport::Dev(s) => s.compile().await,
            ProgramSupport::OpenVm(s) => s.compile().await,
        }
    }
    async fn start(&self) -> Result<()> {
        match self {
            ProgramSupport::Dev(s) => s.start().await,
            ProgramSupport::OpenVm(s) => s.start().await,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_backend_is_openvm() {
        assert!(matches!(
            ProgramSupport::new(ProgramConfig::default(), None),
            ProgramSupport::OpenVm(_)
        ));
    }

    #[test]
    fn unproved_execution_requires_an_explicit_flag() {
        assert!(matches!(
            ProgramSupport::new(ProgramConfig::default(), Some(true)),
            ProgramSupport::Dev(_)
        ));
        assert!(matches!(
            ProgramSupport::new(ProgramConfig::default(), Some(false)),
            ProgramSupport::OpenVm(_)
        ));
    }
}
