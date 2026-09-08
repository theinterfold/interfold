// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use anyhow::{anyhow, bail, Result};
use duct::cmd;
use std::path::{Path, PathBuf};
use tokio::fs;
use tokio::signal;

pub async fn run_bash_script(cwd: &PathBuf, script: &Path, args: &[&str]) -> Result<()> {
    run_bash_script_with_env(cwd, script, args, &[]).await
}

pub async fn run_bash_script_with_env(
    cwd: &PathBuf,
    script: &Path,
    args: &[&str],
    environment: &[(String, String)],
) -> Result<()> {
    let mut cmd_args = vec!["bash".to_string(), script.to_string_lossy().to_string()];
    cmd_args.extend(args.iter().map(|s| s.to_string()));

    // Note this will not end up on shell history
    // `duct` includes every command argument in its checked-process error. Some support-script
    // arguments contain credentials, so inspect the exit status ourselves and keep arguments out
    // of every error path.
    let mut expression = cmd("bash", &cmd_args[1..]).dir(cwd).unchecked();
    for (name, value) in environment {
        expression = expression.env(name, value);
    }

    let handle = expression
        .start()
        .map_err(|_| anyhow!("failed to start {}", script.display()))?;

    tokio::select! {
        result = async { handle.wait() } => {
            match result {
                Ok(output) => {
                    if output.status.success() {
                        Ok(())
                    } else {
                        bail!("{} failed with exit code: {:?}", script.display(), output.status.code());
                    }
                }
                Err(_) => Err(anyhow!("failed while waiting for {}", script.display())),
            }
        }
        _ = signal::ctrl_c() => {
            let _ = handle.kill();
            bail!("Script interrupted by user");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[tokio::test]
    async fn failed_script_does_not_expose_arguments() -> Result<()> {
        let unique = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "interfold-support-script-test-{}-{unique}",
            std::process::id()
        ));
        fs::create_dir_all(&directory).await?;
        let script = directory.join("fail.sh");
        fs::write(&script, "exit 17\n").await?;

        let secret = "credential-that-must-not-appear";
        let error = run_bash_script(&directory, &script, &["--private-key", secret])
            .await
            .expect_err("the script must fail");
        let message = error.to_string();

        assert!(message.contains("failed with exit code: Some(17)"));
        assert!(!message.contains(secret));
        fs::remove_dir_all(directory).await?;
        Ok(())
    }

    #[tokio::test]
    async fn passes_configuration_through_the_child_environment() -> Result<()> {
        let unique = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "interfold-support-script-test-{}-{unique}",
            std::process::id()
        ));
        fs::create_dir_all(&directory).await?;
        let script = directory.join("check-env.sh");
        fs::write(
            &script,
            "test \"$PRIVATE_KEY\" = \"credential-from-environment\"\n",
        )
        .await?;

        run_bash_script_with_env(
            &directory,
            &script,
            &[],
            &[(
                "PRIVATE_KEY".to_owned(),
                "credential-from-environment".to_owned(),
            )],
        )
        .await?;
        fs::remove_dir_all(directory).await?;
        Ok(())
    }
}

pub async fn ensure_script_exists(script_path: &PathBuf) -> Result<()> {
    if !fs::try_exists(script_path).await? {
        bail!("Invalid or corrupted project. This command can only be run from within a valid Interfold project.");
    }
    Ok(())
}
