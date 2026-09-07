// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use anyhow::{bail, Result};
use reqwest::Client;
use std::env;
use tracing::{error, trace};

use crate::helpers::termtable::print_table;

use super::nodes::{spawn_process, Action, ProcessStatus, Query, SERVER_ADDRESS};

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

    // Start and forget
    spawn_process(&interfold_bin, args).await?;

    tracing::info!("Daemon started successfully");

    Ok(())
}
