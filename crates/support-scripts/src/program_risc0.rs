// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use std::env;

use crate::utils::run_bash_script_with_env;
use crate::{ensure_script_exists, run_bash_script, traits::ProgramSupportApi};
use anyhow::{bail, Result};
use async_trait::async_trait;
use e3_config::ProgramConfig;

pub struct ProgramSupportRisc0(pub ProgramConfig);

#[async_trait]
impl ProgramSupportApi for ProgramSupportRisc0 {
    /// Run the docker container compile script
    async fn compile(&self) -> Result<()> {
        let cwd = env::current_dir()?;
        let script = cwd.join(".interfold/support/ctl/compile");
        ensure_script_exists(&script).await?;
        run_bash_script(&cwd, &script, &[]).await?;
        Ok(())
    }

    /// Run the docker container start script
    async fn start(&self) -> Result<()> {
        let cwd = env::current_dir()?;
        let script = cwd.join(".interfold/support/ctl/start");
        ensure_script_exists(&script).await?;

        let Some(risc0_config) = self.0.risc0() else {
            bail!("start must be run with risc0 config available");
        };

        let mut environment = vec![(
            "RISC0_DEV_MODE".to_owned(),
            risc0_config.risc0_dev_mode.to_string(),
        )];

        // Boundless support
        if let Some(boundless) = &risc0_config.boundless {
            environment.extend([
                ("RPC_URL".to_owned(), boundless.rpc_url.clone()),
                ("PRIVATE_KEY".to_owned(), boundless.private_key.clone()),
            ]);

            if let Some(jwt) = &boundless.pinata_jwt {
                environment.push(("PINATA_JWT".to_owned(), jwt.clone()));
            }

            if let Some(url) = &boundless.ipfs_gateway_url {
                environment.push(("IPFS_GATEWAY_URL".to_owned(), url.clone()));
            }

            if let Some(url) = &boundless.program_url {
                environment.push(("PROGRAM_URL".to_owned(), url.clone()));
            }

            let onchain = if boundless.onchain { "true" } else { "false" };
            environment.push(("BOUNDLESS_ONCHAIN".to_owned(), onchain.to_owned()));

            if let Some(v) = boundless.min_price_eth {
                environment.push(("BOUNDLESS_MIN_PRICE_ETH".to_owned(), v.to_string()));
            }
            if let Some(v) = boundless.max_price_eth {
                environment.push(("BOUNDLESS_MAX_PRICE_ETH".to_owned(), v.to_string()));
            }
            if let Some(v) = boundless.timeout_secs {
                environment.push(("BOUNDLESS_TIMEOUT_SECS".to_owned(), v.to_string()));
            }
            if let Some(v) = boundless.lock_timeout_secs {
                environment.push(("BOUNDLESS_LOCK_TIMEOUT_SECS".to_owned(), v.to_string()));
            }
            if let Some(v) = boundless.ramp_up_secs {
                environment.push(("BOUNDLESS_RAMP_UP_SECS".to_owned(), v.to_string()));
            }
            if let Some(v) = boundless.lock_collateral_zkc {
                environment.push(("BOUNDLESS_LOCK_COLLATERAL_ZKC".to_owned(), v.to_string()));
            }
        }

        run_bash_script_with_env(&cwd, &script, &[], &environment).await?;
        Ok(())
    }

    /// Upload the compiled program to Pinata IPFS
    async fn upload(&self) -> Result<()> {
        let cwd = env::current_dir()?;
        let script = cwd.join(".interfold/support/ctl/upload");
        ensure_script_exists(&script).await?;

        let mut environment = vec![];

        if let Some(risc0_config) = self.0.risc0() {
            if let Some(boundless) = &risc0_config.boundless {
                if let Some(jwt) = &boundless.pinata_jwt {
                    environment.push(("PINATA_JWT".to_owned(), jwt.clone()));
                }
                if let Some(url) = &boundless.ipfs_gateway_url {
                    environment.push(("IPFS_GATEWAY_URL".to_owned(), url.clone()));
                }
            }
        }

        run_bash_script_with_env(&cwd, &script, &[], &environment).await?;
        Ok(())
    }
}
