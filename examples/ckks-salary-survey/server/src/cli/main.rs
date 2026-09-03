// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Admin CLI against a running server: create a round, wait for its public
//! key, relay a `submission.json`, evaluate, and poll results.
//!
//! ```text
//! cli --api http://127.0.0.1:8091 create-round [--duration 120]
//! cli --api ... wait-pubkey --e3-id 3 [--timeout 900]
//! cli --api ... submit --e3-id 3 --file submission.json
//! cli --api ... evaluate --e3-id 3
//! cli --api ... wait-results --e3-id 3 [--timeout 600]
//! ```

use std::time::{Duration, Instant};

use clap::{Parser, Subcommand};
use serde_json::Value;

#[derive(Parser)]
#[command(about = "CKKS salary-survey admin CLI")]
struct Cli {
    #[arg(long, default_value = "http://127.0.0.1:8091")]
    api: String,
    #[arg(long, default_value = "")]
    admin_key: String,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    CreateRound {
        #[arg(long)]
        duration: Option<u64>,
    },
    WaitPubkey {
        #[arg(long)]
        e3_id: String,
        #[arg(long, default_value_t = 900)]
        timeout: u64,
    },
    Submit {
        #[arg(long)]
        e3_id: String,
        #[arg(long)]
        file: String,
    },
    Evaluate {
        #[arg(long)]
        e3_id: String,
    },
    WaitResults {
        #[arg(long)]
        e3_id: String,
        #[arg(long, default_value_t = 600)]
        timeout: u64,
    },
    Round {
        #[arg(long)]
        e3_id: String,
    },
}

fn http(method: &str, url: &str, body: Option<&Value>, admin_key: &str) -> Result<Value, String> {
    // Zero-dependency HTTP via curl keeps the CLI tiny (the server is the
    // component under test; this is an operator convenience).
    let mut args = vec!["-s".to_string(), "-X".into(), method.into(), url.into()];
    if let Some(b) = body {
        args.extend([
            "-H".into(),
            "content-type: application/json".into(),
            "-d".into(),
            b.to_string(),
        ]);
    }
    if !admin_key.is_empty() {
        args.extend(["-H".into(), format!("x-admin-key: {admin_key}")]);
    }
    let out = std::process::Command::new("curl")
        .args(&args)
        .output()
        .map_err(|e| format!("curl: {e}"))?;
    let text = String::from_utf8_lossy(&out.stdout);
    serde_json::from_str(&text).map_err(|e| format!("bad JSON from {url}: {e}: {text}"))
}

fn main() -> Result<(), String> {
    let cli = Cli::parse();
    let api = cli.api.trim_end_matches('/');
    match cli.command {
        Command::CreateRound { duration } => {
            let body = serde_json::json!({ "duration_secs": duration });
            let v = http(
                "POST",
                &format!("{api}/rounds"),
                Some(&body),
                &cli.admin_key,
            )?;
            println!("{v}");
            if let Some(id) = v.get("e3_id").and_then(Value::as_str) {
                println!("E3_ID={id}");
            }
        }
        Command::WaitPubkey { e3_id, timeout } => {
            let t = Instant::now();
            loop {
                let v = http("GET", &format!("{api}/rounds/{e3_id}/pubkey"), None, "")?;
                if v.get("public_key_hex").is_some() {
                    println!("{}", v);
                    println!("PUBKEY_READY after {:.1?}", t.elapsed());
                    break;
                }
                if t.elapsed() > Duration::from_secs(timeout) {
                    return Err("timed out waiting for the committee public key".into());
                }
                std::thread::sleep(Duration::from_secs(3));
            }
        }
        Command::Submit { e3_id, file } => {
            let text = std::fs::read_to_string(&file).map_err(|e| e.to_string())?;
            let submission: Value = serde_json::from_str(&text).map_err(|e| e.to_string())?;
            let body = serde_json::json!({ "submission": submission });
            let v = http(
                "POST",
                &format!("{api}/rounds/{e3_id}/submit"),
                Some(&body),
                "",
            )?;
            println!("{v}");
            if v.get("error").is_some() {
                return Err("submission rejected".into());
            }
        }
        Command::Evaluate { e3_id } => {
            let v = http(
                "POST",
                &format!("{api}/rounds/{e3_id}/evaluate"),
                None,
                &cli.admin_key,
            )?;
            println!("{v}");
            if v.get("error").is_some() {
                return Err("evaluation failed".into());
            }
        }
        Command::WaitResults { e3_id, timeout } => {
            let t = Instant::now();
            loop {
                let v = http("GET", &format!("{api}/rounds/{e3_id}"), None, "")?;
                if let Some(r) = v.get("results").filter(|r| !r.is_null()) {
                    println!("{r}");
                    println!("RESULTS_READY after {:.1?}", t.elapsed());
                    break;
                }
                if t.elapsed() > Duration::from_secs(timeout) {
                    return Err("timed out waiting for results".into());
                }
                std::thread::sleep(Duration::from_secs(3));
            }
        }
        Command::Round { e3_id } => {
            let v = http("GET", &format!("{api}/rounds/{e3_id}"), None, "")?;
            println!("{}", serde_json::to_string_pretty(&v).unwrap_or_default());
        }
    }
    Ok(())
}
