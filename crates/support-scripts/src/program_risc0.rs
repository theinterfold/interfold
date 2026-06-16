// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use std::env;

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

        let mut args: Vec<String> = vec![
            "--risc0-dev-mode".into(),
            risc0_config.risc0_dev_mode.to_string(),
        ];

        // Boundless support
        if let Some(boundless) = &risc0_config.boundless {
            args.extend_from_slice(&[
                "--rpc-url".into(),
                boundless.rpc_url.clone(),
                "--private-key".into(),
                boundless.private_key.clone(),
            ]);

            if let Some(jwt) = &boundless.pinata_jwt {
                args.extend_from_slice(&["--pinata-jwt".into(), jwt.clone()]);
            }

            if let Some(url) = &boundless.program_url {
                args.extend_from_slice(&["--program-url".into(), url.clone()]);
            }

            let onchain = if boundless.onchain { "true" } else { "false" };
            args.extend_from_slice(&["--boundless-onchain".into(), onchain.into()]);

            // Offer params — push flag + value as owned Strings
            if let Some(v) = boundless.min_price_eth {
                args.extend_from_slice(&["--boundless-min-price-eth".into(), v.to_string()]);
            }
            if let Some(v) = boundless.max_price_eth {
                args.extend_from_slice(&["--boundless-max-price-eth".into(), v.to_string()]);
            }
            if let Some(v) = boundless.timeout_secs {
                args.extend_from_slice(&["--boundless-timeout-secs".into(), v.to_string()]);
            }
            if let Some(v) = boundless.lock_timeout_secs {
                args.extend_from_slice(&["--boundless-lock-timeout-secs".into(), v.to_string()]);
            }
            if let Some(v) = boundless.ramp_up_secs {
                args.extend_from_slice(&["--boundless-ramp-up-secs".into(), v.to_string()]);
            }
            if let Some(v) = boundless.lock_collateral_zkc {
                args.extend_from_slice(&["--boundless-lock-collateral-zkc".into(), v.to_string()]);
            }
        }

        let arg_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
        run_bash_script(&cwd, &script, &arg_refs).await?;
        Ok(())
    }

    /// Upload the compiled program to Pinata IPFS
    async fn upload(&self) -> Result<()> {
        let cwd = env::current_dir()?;
        let script = cwd.join(".interfold/support/ctl/upload");
        ensure_script_exists(&script).await?;

        let mut args = vec![];

        if let Some(risc0_config) = self.0.risc0() {
            if let Some(boundless) = &risc0_config.boundless {
                if let Some(jwt) = &boundless.pinata_jwt {
                    args.extend(["--pinata-jwt", jwt.as_str()]);
                }
            }
        }

        run_bash_script(&cwd, &script, &args).await?;
        Ok(())
    }
}
