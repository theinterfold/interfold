// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Round-opener CLI (CRISP `cli/`): drives the running server's API.
//!
//!   cli [--server http://127.0.0.1:8095] open [--clients clients.json] [--norm-bound 2.5] [--min-clients 3] [--duration 300]
//!   cli rounds
//!   cli round <e3_id>
//!   cli evaluate <e3_id>

use ckks_fedavg::server::rounds::{demo_params, get_mock_clients};
use clap::{Parser, Subcommand};
use std::io::{Read, Write};

#[derive(Parser)]
#[command(about = "CKKS federated-averaging round-opener CLI")]
struct Cli {
    #[arg(long, default_value = "http://127.0.0.1:8095")]
    server: String,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Open a round with a client list + bound (defaults to the 5 anvil dev clients, `B = 2.5`,
    /// at least 3 clients).
    Open {
        #[arg(long)]
        clients: Option<String>,
        #[arg(long)]
        norm_bound: Option<f64>,
        #[arg(long)]
        min_clients: Option<usize>,
        #[arg(long)]
        duration: Option<u64>,
    },
    Rounds,
    Round {
        e3_id: String,
    },
    Evaluate {
        e3_id: String,
    },
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Open {
            clients,
            norm_bound,
            min_clients,
            duration,
        } => {
            let clients: Vec<String> = match clients {
                Some(path) => serde_json::from_str(&std::fs::read_to_string(path)?)?,
                None => get_mock_clients(),
            };
            let mut params = demo_params();
            if let Some(b) = norm_bound {
                params.norm_bound = b;
            }
            if let Some(m) = min_clients {
                params.min_clients = m;
            }
            let body = serde_json::json!({
                "clients": clients,
                "d": params.d,
                "normBound": params.norm_bound,
                "minClients": params.min_clients,
                "durationSecs": duration,
            });
            println!(
                "{}",
                http(
                    "POST",
                    &format!("{}/rounds/request", cli.server),
                    Some(body.to_string())
                )?
            );
        }
        Cmd::Rounds => println!("{}", http("GET", &format!("{}/rounds", cli.server), None)?),
        Cmd::Round { e3_id } => println!(
            "{}",
            http("GET", &format!("{}/rounds/{e3_id}", cli.server), None)?
        ),
        Cmd::Evaluate { e3_id } => println!(
            "{}",
            http(
                "POST",
                &format!("{}/rounds/{e3_id}/evaluate", cli.server),
                Some("{}".into())
            )?
        ),
    }
    Ok(())
}

/// Minimal blocking HTTP/1.1 over std (the server is local; no reqwest dependency).
fn http(
    method: &str,
    url: &str,
    body: Option<String>,
) -> Result<String, Box<dyn std::error::Error>> {
    let url = url
        .strip_prefix("http://")
        .ok_or("only http:// URLs are supported")?;
    let (host, path) = url
        .split_once('/')
        .map(|(h, p)| (h, format!("/{p}")))
        .unwrap_or((url, "/".into()));
    let mut stream = std::net::TcpStream::connect(host)?;
    let body = body.unwrap_or_default();
    write!(
        stream,
        "{method} {path} HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )?;
    let mut response = String::new();
    stream.read_to_string(&mut response)?;
    let (head, body) = response
        .split_once("\r\n\r\n")
        .ok_or("malformed HTTP response")?;
    let status = head.lines().next().unwrap_or_default();
    if !status.contains(" 200") {
        return Err(format!("{status}: {body}").into());
    }
    Ok(body.to_string())
}
