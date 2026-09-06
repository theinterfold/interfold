// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Round-opener CLI (CRISP `cli/`): drives the running server's API.
//!
//!   cli [--server http://127.0.0.1:8094] open [--weights 0.5,-0.25,1,0.125] [--dao 0x.. --dao 0x..] [--duration 300]
//!   cli rounds
//!   cli round <e3_id>
//!   cli evaluate <e3_id>
//!   cli result <e3_id>

use ckks_treasury::server::rounds::{get_mock_daos, get_mock_weights};
use clap::{Parser, Subcommand};
use std::io::{Read, Write};

#[derive(Parser)]
#[command(about = "CKKS private treasury-risk round-opener CLI")]
struct Cli {
    #[arg(long, default_value = "http://127.0.0.1:8094")]
    server: String,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Open a round (defaults: the fixture weights and anvil #6, #7, #8 as the DAOs).
    Open {
        /// Four comma-separated public weights in [-1, 1].
        #[arg(long)]
        weights: Option<String>,
        /// A registered DAO address (repeat; at least two).
        #[arg(long = "dao")]
        daos: Vec<String>,
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
    Result {
        e3_id: String,
    },
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Open {
            weights,
            daos,
            duration,
        } => {
            let weights: Vec<f64> = match weights {
                Some(w) => w
                    .split(',')
                    .map(|s| s.trim().parse::<f64>())
                    .collect::<Result<_, _>>()?,
                None => get_mock_weights().to_vec(),
            };
            let daos = if daos.is_empty() {
                get_mock_daos()
            } else {
                daos
            };
            let body = serde_json::json!({
                "weights": weights,
                "daos": daos,
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
        Cmd::Result { e3_id } => println!(
            "{}",
            http(
                "GET",
                &format!("{}/rounds/{e3_id}/result", cli.server),
                None
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
