// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use anyhow::{bail, Result};
use reqwest::Client;
use std::env;
use std::time::Duration;
use tracing::{error, trace};

use crate::helpers::termtable::print_table;

use super::nodes::{spawn_detached_process, Action, ProcessStatus, Query, SERVER_ADDRESS};

pub async fn get_status() -> Result<Query> {
    let client = Client::new();
    let htres = client
        .get(format!("http://{}/status", SERVER_ADDRESS))
        .send()
        .await?;
    let res: Query = htres.json::<Query>().await?;
    Ok(res)
}

pub async fn send_action(action: &Action) -> Result<Query> {
    let client = Client::new();
    let htres = client
        .post(format!("http://{}/command", SERVER_ADDRESS))
        .json(action)
        .send()
        .await?;
    let res = htres.json::<Query>().await?;

    trace!("{:?}", res);

    if let Query::Failure { message } = res.clone() {
        error!("{}", message);
    }

    Ok(res)
}

pub async fn terminate() -> Result<()> {
    send_action(&Action::Terminate).await?;
    Ok(())
}

pub async fn start(id: &str) -> Result<()> {
    send_action(&Action::Start { id: id.to_owned() }).await?;
    Ok(())
}

pub async fn stop(id: &str) -> Result<()> {
    send_action(&Action::Stop { id: id.to_owned() }).await?;
    Ok(())
}

pub async fn restart(id: &str) -> Result<()> {
    send_action(&Action::Restart { id: id.to_owned() }).await?;
    Ok(())
}

pub async fn status(id: &str) -> Result<()> {
    let status = get_status().await?;
    if let Query::Status { status } = status {
        let state = status.processes.get(id).unwrap_or(&ProcessStatus::Stopped);
        println!("{:?}", state);
    }

    Ok(())
}

pub async fn ps() -> Result<()> {
    let status = get_status().await;
    let rows: Vec<Vec<String>> = if let Ok(Query::Status { status }) = &status {
        status
            .processes
            .iter()
            .map(|(k, v)| vec![k.to_string(), format!("{:?}", v)])
            .collect()
    } else {
        vec![]
    };

    print_table(&["PROCESS", "STATUS"], &rows);
    if let Ok(Query::Status { status }) = &status {
        if let Some(config_file) = &status.config_file {
            println!("config: {config_file}");
        }
    }

    Ok(())
}

pub async fn is_ready() -> Result<bool> {
    let Ok(Query::Status { status: _ }) = get_status().await else {
        return Ok(false);
    };

    Ok(true)
}

/// Refuse to drive a daemon that was launched from a different config file.
///
/// The control socket is a fixed loopback port shared by every checkout on the machine, and
/// node ids such as `cn1` are the documented defaults, so `nodes stop cn1` from one repo
/// would otherwise stop `cn1` in whichever swarm happens to own the port. Daemons that
/// predate the `config_file` field are accepted so an upgrade cannot lock an operator out.
pub async fn ensure_same_swarm(config_file: &std::path::Path) -> Result<()> {
    let Query::Status { status } = get_status().await? else {
        bail!("Swarm client is not ready. Did you forget to call `interfold nodes up`?");
    };
    let Some(daemon_config) = status.config_file else {
        return Ok(());
    };
    let mine = config_file.display().to_string();
    if daemon_config != mine {
        bail!(
            "A swarm is already running on {SERVER_ADDRESS} for a different config.\n  \
             running: {daemon_config}\n  yours:   {mine}\n\
             Run `interfold nodes down` from that config first, or use it for this command."
        );
    }
    Ok(())
}

pub async fn start_daemon(
    verbose: u8,
    maybe_config_string: &Option<String>,
    exclude: &[String],
) -> Result<()> {
    if is_ready().await? {
        tracing::warn!("Daemon is already running");
        return Ok(());
    }

    let interfold_bin = env::current_exe()?.display().to_string();

    let mut args = vec![];
    args.push("nodes".to_string());
    args.push("daemon".to_string());
    if let Some(config_string) = maybe_config_string {
        args.push("--config".to_string());
        args.push(config_string.to_string());
    }

    if verbose > 0 {
        args.push(format!("-{}", "v".repeat(verbose as usize))); // -vvv
    }

    if !exclude.is_empty() {
        args.push("--exclude".to_string());
        args.push(exclude.join(","));
    }

    // Start and forget. The daemon must outlive this CLI process, so it is spawned detached:
    // holding no handle means nothing kills it when this function returns. Readiness is
    // confirmed through the socket rather than through the child handle.
    let mut child = spawn_detached_process(&interfold_bin, args).await?;

    // A daemon that dies immediately (port taken, bad config, missing binary) otherwise looks
    // like a success: the CLI reports "started" and exits, and the operator finds out only when
    // the next command cannot reach the socket.
    if tokio::time::timeout(DAEMON_START_TIMEOUT, wait_until_ready())
        .await
        .is_err()
    {
        // Report the child's own exit status when it has one; it is the actionable detail.
        if let Ok(Some(status)) = child.try_wait() {
            bail!("Daemon exited during startup with {status}");
        }
        let _ = child.kill().await;
        bail!(
            "Daemon did not become ready on {SERVER_ADDRESS} within {}s",
            DAEMON_START_TIMEOUT.as_secs()
        );
    }

    tracing::info!("Daemon started successfully");

    Ok(())
}

/// How long `nodes up --detach` waits for the daemon to answer on its socket.
const DAEMON_START_TIMEOUT: Duration = Duration::from_secs(10);

/// Poll the daemon socket until it accepts a connection.
///
/// `is_ready` reports a refused connection as `Ok(false)` rather than an error, so a daemon that
/// is still binding its port is indistinguishable from one that never will be. The caller bounds
/// this loop with [`DAEMON_START_TIMEOUT`].
async fn wait_until_ready() {
    while !is_ready().await.unwrap_or(false) {
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}
