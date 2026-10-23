// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! `interfold program compile`, `start` and `cache purge`. They build and run the program runner:
//! the `program-runner` binary of the project's `runner/` crate, which serves the project's program
//! through `e3_program_runner::run`. Every command runs in the current directory, the project root.

use anyhow::{anyhow, bail, ensure, Context, Result};
use e3_config::ProgramConfig;
use std::{env, io::Write, path::Path};
use tokio::{fs, process::Command, signal};

/// The binary of the project's `runner/` crate.
const RUNNER_BIN: &str = "program-runner";

/// Builds the OpenVM guest, its keys and receipt identity, the worker configuration and the program
/// runner.
const OPENVM_COMPILE: &str = include_str!("../scripts/openvm-compile.sh");

/// Where `openvm-compile.sh` writes the worker configuration unless OPENVM_PROVER_CONFIG names
/// another path.
const OPENVM_PROVER_CONFIG: &str = ".interfold/caches/openvm/prover.json";

const OPENVM_WORKER_REQUIRED: &str = "Set program.openvm.prover_bin to the CPU worker, \
     program.openvm.prover_bin_cuda to the CUDA worker, or both";

/// The unproved development runner when `--dev` says so, or `program.dev` when `--dev` is absent.
/// Otherwise the OpenVM proving service.
fn is_dev(config: &ProgramConfig, dev: Option<bool>) -> bool {
    dev.unwrap_or_else(|| config.dev())
}

/// The `OPENVM_*` environment that `program.openvm` gives the compile script and the runner.
fn openvm_environment(config: &ProgramConfig) -> Result<Vec<(String, String)>> {
    let config = config.openvm().context(OPENVM_WORKER_REQUIRED)?;
    ensure!(
        config.prover_bin.is_some() || config.prover_bin_cuda.is_some(),
        OPENVM_WORKER_REQUIRED
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
    Ok(environment)
}

pub async fn compile(config: &ProgramConfig, dev: Option<bool>) -> Result<()> {
    config.ensure_supported()?;
    let cwd = project_dir().await?;
    if is_dev(config, dev) {
        // Not --locked: `interfold init` points the project's Interfold crates at git, so the lock
        // file a new project copies is out of date until cargo updates it.
        return run(&cwd, "cargo", &["build", "--bin", RUNNER_BIN], &[]).await;
    }
    let environment = openvm_environment(config)?;
    // The script reaches bash as a file, not as an argument, so its text stays out of the process
    // list.
    let mut script = tempfile::Builder::new()
        .prefix("openvm-compile")
        .suffix(".sh")
        .tempfile()
        .context("failed to create the OpenVM compile script")?;
    script
        .write_all(OPENVM_COMPILE.as_bytes())
        .and_then(|()| script.flush())
        .context("failed to write the OpenVM compile script")?;
    let script_path = script.path().to_string_lossy().into_owned();
    run(&cwd, "bash", &[&script_path], &environment).await
}

pub async fn start(config: &ProgramConfig, dev: Option<bool>) -> Result<()> {
    config.ensure_supported()?;
    let cwd = project_dir().await?;
    if is_dev(config, dev) {
        return run(
            &cwd,
            "cargo",
            &["run", "--bin", RUNNER_BIN, "--", "dev"],
            &[],
        )
        .await;
    }
    let mut environment = openvm_environment(config)?;
    if env::var_os("OPENVM_PROVER_CONFIG").is_none_or(|path| path.is_empty()) {
        environment.push((
            "OPENVM_PROVER_CONFIG".to_owned(),
            cwd.join(OPENVM_PROVER_CONFIG)
                .to_string_lossy()
                .into_owned(),
        ));
    }
    run(
        &cwd,
        "cargo",
        &["run", "--release", "--bin", RUNNER_BIN, "--", "openvm"],
        &environment,
    )
    .await
}

/// Deletes the program build caches.
pub async fn cache_purge() -> Result<()> {
    let caches = env::current_dir()?.join(".interfold/caches");
    fs::remove_dir_all(caches).await?;
    Ok(())
}

/// The current directory, once it is a project that the program runner can build in.
async fn project_dir() -> Result<std::path::PathBuf> {
    let cwd = env::current_dir()?;
    ensure_project(&cwd).await?;
    Ok(cwd)
}

async fn ensure_project(cwd: &Path) -> Result<()> {
    if fs::try_exists(cwd.join(".interfold/support")).await? {
        bail!(
            "This project keeps its program server in .interfold/support, which the interfold CLI \
             no longer uses. Delete .interfold/support and its Cargo workspace members, then add \
             the runner crate from the project template (templates/default/runner)."
        );
    }
    if !fs::try_exists(cwd.join("Cargo.toml")).await? {
        bail!("Invalid or corrupted project. This command can only be run from within a valid Interfold project.");
    }
    Ok(())
}

/// Runs `program` in `cwd` and waits for it. Ctrl-C stops it.
///
/// Errors name only `program`, never `args`: an argument may hold a credential.
async fn run(
    cwd: &Path,
    program: &str,
    args: &[&str],
    environment: &[(String, String)],
) -> Result<()> {
    let mut child = Command::new(program)
        .args(args)
        .envs(environment.iter().map(|(name, value)| (name, value)))
        .current_dir(cwd)
        .kill_on_drop(true)
        .spawn()
        .map_err(|error| anyhow!("failed to start {program}: {error}"))?;

    tokio::select! {
        status = child.wait() => {
            let status = status.map_err(|_| anyhow!("failed while waiting for {program}"))?;
            ensure!(status.success(), "{program} failed with exit code: {:?}", status.code());
            Ok(())
        }
        _ = signal::ctrl_c() => {
            let _ = child.kill().await;
            bail!("Interrupted by user");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_dev_flag_overrides_the_configuration_and_openvm_is_the_default() {
        let config = ProgramConfig::default();
        assert!(!is_dev(&config, None));
        assert!(is_dev(&config, Some(true)));
        assert!(!is_dev(&config, Some(false)));
    }

    #[tokio::test]
    async fn passes_the_environment_and_keeps_arguments_out_of_errors() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let directory = directory.path();
        run(
            directory,
            "bash",
            &[
                "-c",
                "test \"$PRIVATE_KEY\" = \"credential-from-environment\"",
            ],
            &[(
                "PRIVATE_KEY".to_owned(),
                "credential-from-environment".to_owned(),
            )],
        )
        .await?;

        let secret = "credential-that-must-not-appear";
        let error = run(directory, "bash", &["-c", "exit 17", secret], &[])
            .await
            .expect_err("the command must fail");
        assert_eq!(error.to_string(), "bash failed with exit code: Some(17)");
        Ok(())
    }

    #[tokio::test]
    async fn refuses_a_project_with_the_removed_support_folder() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let directory = directory.path();
        fs::write(directory.join("Cargo.toml"), "").await?;
        ensure_project(directory).await?;

        fs::create_dir_all(directory.join(".interfold/support/dev")).await?;
        let error = ensure_project(directory)
            .await
            .expect_err("the old layout must be refused");
        assert!(error.to_string().contains("templates/default/runner"));
        Ok(())
    }
}
