// SPDX-License-Identifier: LGPL-3.0-only

use anyhow::Result;
use std::path::Path;
use std::process::{Command, Output};

fn run(cwd: &Path, args: &[&str], environment: &[(&str, &str)]) -> Result<Output> {
    let mut command = Command::new(env!("CARGO_BIN_EXE_interfold"));
    for (key, _) in std::env::vars_os() {
        if key.to_string_lossy().starts_with("E3_") {
            command.env_remove(key);
        }
    }
    Ok(command
        .current_dir(cwd)
        .env("HOME", cwd.join("home"))
        .env("XDG_CONFIG_HOME", cwd.join("home/.config"))
        .env("XDG_DATA_HOME", cwd.join("home/.local/share"))
        .envs(environment.iter().copied())
        .arg("--quiet")
        .args(args)
        .output()?)
}

fn success(output: Output) -> String {
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "{stdout}\n{stderr}");
    stdout.trim().to_owned()
}

#[test]
fn discovery_preserves_project_and_named_node_locations() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let root = temp.path().canonicalize()?;
    let nested = root.join("nested");
    let alternate = root.join("alternate");
    std::fs::create_dir_all(&nested)?;
    std::fs::create_dir_all(&alternate)?;
    std::fs::write(
        root.join("interfold.config.yaml"),
        "node:\n  network: local\n  ctrl_port: 0\n",
    )?;
    std::fs::write(
        alternate.join("custom.yaml"),
        "found_config_file: /not-the-loaded-file\nnodes:\n  operator:\n    network: local\n    ctrl_port: 0\n    db_file: ../override-db\n",
    )?;

    for (param, path) in [
        ("config_yaml", root.join("interfold.config.yaml")),
        ("key_file", root.join(".interfold/config/_default/key")),
        ("db_file", root.join(".interfold/data/_default/db")),
    ] {
        assert_eq!(
            success(run(&nested, &["config", "get", param], &[])?),
            path.to_string_lossy()
        );
    }

    for (param, path) in [
        ("config_yaml", alternate.join("custom.yaml")),
        ("key_file", alternate.join(".interfold/config/operator/key")),
        ("db_file", alternate.join(".interfold/data/override-db")),
    ] {
        let output = run(
            &nested,
            &[
                "--config",
                "../alternate/custom.yaml",
                "--name",
                "operator",
                "config",
                "get",
                param,
            ],
            &[("E3_FOUND_CONFIG_FILE", "/also-not-the-loaded-file")],
        )?;
        assert_eq!(success(output), path.to_string_lossy());
    }
    assert!(!root.join(".interfold/config/_default/key").exists());
    assert!(!alternate.join(".interfold/data/override-db").exists());
    Ok(())
}

#[test]
fn config_get_keeps_program_output_and_nested_environment_overrides() -> Result<()> {
    let temp = tempfile::tempdir()?;
    std::fs::write(
        temp.path().join("interfold.config.yaml"),
        "node:\n  network: local\n  ctrl_port: 0\nprogram:\n  openvm:\n    prover_bin: /deployment/bin/worker\n    setup_dir: /deployment/setup\n",
    )?;
    let environment = [
        ("E3_PROGRAM__OPENVM__BACKEND", "cpu"),
        ("E3_PROGRAM__DEV", "true"),
    ];
    let program = success(run(
        temp.path(),
        &["config", "get", "program"],
        &environment,
    )?);
    assert!(program.contains("/deployment/bin/worker"), "{program}");
    assert!(program.contains("/deployment/setup"), "{program}");
    assert!(program.contains("backend: Cpu"), "{program}");
    assert!(program.contains("dev: Some(true)"), "{program}");

    let all = success(run(temp.path(), &["config", "get"], &environment)?);
    assert!(all
        .lines()
        .any(|line| line == format!("program: {program}")));
    Ok(())
}

#[test]
fn legacy_program_settings_load_for_nodes_but_cannot_select_a_backend() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let config = temp.path().join("interfold.config.yaml");
    std::fs::write(
        &config,
        "node:\n  network: local\n  ctrl_port: 0\nprogram:\n  risc0:\n    boundless:\n      rpc_url: https://example.invalid\n",
    )?;
    assert_eq!(
        success(run(temp.path(), &["config", "get", "name"], &[])?),
        "_default"
    );
    for command in [
        &["compile"][..],
        &["program", "compile", "--dev", "true"],
        &["program", "start", "--dev", "true"],
    ] {
        let output = run(temp.path(), command, &[])?;
        assert!(!output.status.success());
        let error = String::from_utf8_lossy(&output.stderr);
        assert!(
            error.contains("program.risc0 is no longer supported"),
            "{error}"
        );
    }

    for program in ["unknown_backend: {}", "openvm:\n    backend: gpu"] {
        std::fs::write(&config, format!("program:\n  {program}\n"))?;
        let output = run(temp.path(), &["config", "get", "name"], &[])?;
        assert!(!output.status.success());
        assert!(String::from_utf8_lossy(&output.stderr).contains("Could not parse configuration"));
    }
    assert!(!temp.path().join(".interfold/caches").exists());
    Ok(())
}

#[tokio::test]
async fn remote_reads_use_the_selected_nodes_control_port() -> Result<()> {
    use std::time::Duration;
    use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};

    let temp = tempfile::tempdir()?;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    std::fs::write(
        temp.path().join("config.yaml"),
        format!(
            "node:\n  network: local\n  ctrl_port: 0\nnodes:\n  operator:\n    network: local\n    ctrl_port: {}\nprogram:\n  risc0: {{}}\n",
            listener.local_addr()?.port()
        ),
    )?;
    let server = tokio::spawn(async move {
        tokio::time::timeout(Duration::from_secs(5), async move {
            let mut command = None;
            for method in ["HEAD", "POST"] {
                let (stream, _) = listener.accept().await?;
                let mut stream = BufReader::new(stream);
                let mut line = String::new();
                stream.read_line(&mut line).await?;
                assert!(line.starts_with(&format!("{method} ")), "{line}");
                let mut length = 0;
                loop {
                    line.clear();
                    anyhow::ensure!(stream.read_line(&mut line).await? > 0, "missing headers");
                    if line.trim().is_empty() {
                        break;
                    }
                    if let Some(value) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                        length = value.trim().parse::<usize>()?;
                    }
                }
                let mut body = vec![0; length];
                stream.read_exact(&mut body).await?;
                let response = if method == "POST" {
                    command = Some(serde_json::from_slice::<serde_json::Value>(&body)?);
                    "served by selected node"
                } else {
                    ""
                };
                stream
                    .get_mut()
                    .write_all(
                        format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{response}",
                            response.len()
                        )
                        .as_bytes(),
                    )
                    .await?;
                stream.get_mut().shutdown().await?;
            }
            Ok::<_, anyhow::Error>(command.unwrap())
        })
        .await?
    });
    let cwd = temp.path().to_path_buf();
    let output = tokio::task::spawn_blocking(move || {
        run(
            &cwd,
            &[
                "--config",
                "config.yaml",
                "--name",
                "operator",
                "--otel",
                "HTTP://LOCALHOST:4317",
                "wallet",
                "get",
            ],
            &[],
        )
    })
    .await??;
    let command = server.await??;
    assert_eq!(success(output), "served by selected node");
    assert_eq!(command["command"], "WalletGet");
    assert_eq!(command["name"], "operator");
    assert_eq!(command["config"], "config.yaml");
    assert_eq!(command["otel"], "http://localhost:4317/");
    assert!(!temp.path().join(".interfold").exists());
    Ok(())
}
