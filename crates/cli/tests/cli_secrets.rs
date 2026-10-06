// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use anyhow::Result;
use std::io::Write;
use std::path::Path;
use std::process::{Command, Output, Stdio};
use tempfile::TempDir;

const PASSWORD: &str = "  cli stdin password  ";
const WALLET_KEY: &str = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

fn project() -> Result<TempDir> {
    let dir = tempfile::tempdir()?;
    std::fs::write(
        dir.path().join("interfold.config.yaml"),
        format!(
            "config_dir: {}\ndata_dir: {}\nnodes:\n  stdin-node:\n    network: local\n    autopassword: false\n    autowallet: false\n",
            dir.path().join("config").display(),
            dir.path().join("data").display(),
        ),
    )?;
    Ok(dir)
}

fn run(dir: &Path, args: &[&str], input: &str) -> Result<Output> {
    let mut child = Command::new(env!("CARGO_BIN_EXE_interfold"))
        .current_dir(dir)
        .env_remove("E3_CONFIG_DIR")
        .env_remove("E3_DATA_DIR")
        .args(["--config", "interfold.config.yaml", "--name", "stdin-node"])
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    child.stdin.take().unwrap().write_all(input.as_bytes())?;
    Ok(child.wait_with_output()?)
}

fn success(output: Output) -> String {
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "{stdout}\n{stderr}");
    assert!(!stdout.contains(PASSWORD) && !stderr.contains(PASSWORD));
    assert!(!stdout.contains(WALLET_KEY) && !stderr.contains(WALLET_KEY));
    stdout.into_owned()
}

fn rejects_argv(
    dir: &Path,
    command: &[&str],
    options: &[&str],
    secret: &str,
    alternative: &str,
) -> Result<()> {
    let mut failures = Vec::new();
    for option in options {
        let mut forms = vec![
            vec![option.to_string(), secret.to_string()],
            vec![format!("{option}={secret}")],
            vec![option.to_string()],
        ];
        if !option.starts_with("--") {
            forms.push(vec![format!("{option}{secret}")]);
            forms.push(vec![format!("-v{}{secret}", &option[1..])]);
        }
        for (form, args) in forms.iter().enumerate() {
            let args: Vec<_> = command
                .iter()
                .copied()
                .chain(args.iter().map(String::as_str))
                .collect();
            let output = run(dir, &args, "")?;
            let stderr = String::from_utf8_lossy(&output.stderr);
            let stdout = String::from_utf8_lossy(&output.stdout);
            if output.status.code() != Some(2)
                || !stderr.contains(alternative)
                || !stderr.contains("interactive prompt")
                || stderr.contains(secret)
                || stdout.contains(secret)
            {
                failures.push(format!(
                    "{} {option} (form {form}): expected an argument error with {alternative} and no secret, got {}: {stderr}",
                    command.join(" "), output.status,
                ));
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
    Ok(())
}

#[test]
fn password_set_rejects_argv_and_reads_stdin() -> Result<()> {
    let dir = project()?;
    success(run(
        dir.path(),
        &["password", "set", "--password-stdin"],
        &format!("{PASSWORD}\r\n"),
    )?);
    assert_eq!(
        std::fs::read(dir.path().join("config/stdin-node/key"))?,
        PASSWORD.as_bytes(),
    );
    rejects_argv(
        dir.path(),
        &["password", "set"],
        &["--password", "-p"],
        PASSWORD,
        "--password-stdin",
    )
}

#[test]
fn wallet_set_rejects_argv_and_reads_stdin() -> Result<()> {
    let dir = project()?;
    success(run(
        dir.path(),
        &["password", "set", "--password-stdin"],
        &format!("{PASSWORD}\n"),
    )?);
    success(run(
        dir.path(),
        &["wallet", "set", "--private-key-stdin"],
        &format!("{WALLET_KEY}\n"),
    )?);
    let address = success(run(dir.path(), &["wallet", "get"], "")?);
    assert!(address.contains("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"));
    let peer_id = success(run(dir.path(), &["net", "get-peer-id"], "")?);
    assert!(peer_id.contains("12D3KooWEZiPVmEZkwCFEWYxPL6xts6LnPHRFqsSEDGmt1vQ17By"));
    rejects_argv(
        dir.path(),
        &["wallet", "set"],
        &["--private-key"],
        WALLET_KEY,
        "--private-key-stdin",
    )
}

#[test]
fn ciphernode_setup_rejects_argv_secrets() -> Result<()> {
    let dir = project()?;
    rejects_argv(
        dir.path(),
        &["ciphernode", "setup"],
        &["--password", "-p"],
        PASSWORD,
        "--password-stdin",
    )?;
    rejects_argv(
        dir.path(),
        &["ciphernode", "setup"],
        &["--private-key", "-k"],
        WALLET_KEY,
        "--private-key-stdin",
    )
}

/// Without a terminal, setup takes every value from its flags and stdin, and writes a configuration
/// with a data-availability reader, which `start` needs. When a flag that replaces a prompt is
/// missing, it names the flag and reads and writes nothing, instead of failing at a prompt. It
/// refuses a local network, for which the binary has no deployment, before it reads anything, and
/// names the template.
#[test]
fn ciphernode_setup_runs_without_a_terminal() -> Result<()> {
    let home = tempfile::tempdir()?;
    let config_dir = home.path().join("node-config");
    let config_dir_arg = config_dir.to_str().unwrap().to_owned();
    let secrets = format!("{PASSWORD}\n{WALLET_KEY}\n");
    let setup = |args: &[&str], input: &str| -> Result<(bool, String)> {
        let mut child = Command::new(env!("CARGO_BIN_EXE_interfold"))
            .current_dir(home.path())
            .env("HOME", home.path())
            .env("XDG_CONFIG_HOME", home.path().join(".config"))
            .env("XDG_DATA_HOME", home.path().join(".local/share"))
            .env_remove("E3_CONFIG_DIR")
            .env_remove("E3_DATA_DIR")
            .args(["ciphernode", "setup"])
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        // The command may stop before it reads stdin.
        let _ = child.stdin.take().unwrap().write_all(input.as_bytes());
        let output = child.wait_with_output()?;
        let message = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(!message.contains(PASSWORD) && !message.contains(WALLET_KEY));
        Ok((output.status.success(), message))
    };
    let flags: [&[&str]; 4] = [
        &["--rpc-url", "ws://127.0.0.1:8545"],
        &["--config-dir", config_dir_arg.as_str()],
        &["--password-stdin"],
        &["--private-key-stdin"],
    ];

    for (omitted, flag) in flags.iter().enumerate() {
        let args: Vec<&str> = flags
            .iter()
            .enumerate()
            .filter(|(index, _)| *index != omitted)
            .flat_map(|(_, flag)| flag.iter().copied())
            .collect();
        let (succeeded, message) = setup(&args, &secrets)?;
        assert!(!succeeded, "{message}");
        assert!(
            message.contains("cannot prompt") && message.contains(flag[0]),
            "{message}"
        );
        assert!(!config_dir.exists());
    }

    let all: Vec<&str> = flags.iter().flat_map(|flag| flag.iter().copied()).collect();
    let local: Vec<&str> = ["--network", "local"]
        .into_iter()
        .chain(all.iter().copied())
        .collect();
    // With nothing on stdin, a read would fail first.
    let (succeeded, message) = setup(&local, "")?;
    assert!(!succeeded, "{message}");
    assert!(message.contains("project template"), "{message}");
    assert!(!config_dir.exists());

    let (succeeded, message) = setup(&all, &secrets)?;
    assert!(succeeded, "{message}");
    let config = std::fs::read_to_string(config_dir.join("interfold.config.yaml"))?;
    assert!(config.contains("data_availability:"), "{config}");
    Ok(())
}
