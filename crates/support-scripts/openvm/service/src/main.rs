// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! The OpenVM proving service for this project's E3 program.
//!
//! Serves the same `POST /run_compute` as the development runner, and answers with a real OpenVM
//! receipt. The worker, its configuration and the deadlines come from the environment that
//! `interfold program start` sets; see `e3_openvm_host::WorkerConfig`.

use anyhow::{Context, Result};
use e3_openvm_host::{ComputeDomain, Prover, WorkerConfig};
use e3_program_server::E3ProgramServer;
use std::sync::Arc;
use std::time::Duration;

fn env_or<T: std::str::FromStr>(name: &str, default: T) -> Result<T> {
    match std::env::var(name) {
        Ok(value) if !value.is_empty() => value
            .parse()
            .map_err(|_| anyhow::anyhow!("{name} has an invalid value")),
        _ => Ok(default),
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let prover = Arc::new(Prover::start(WorkerConfig::from_env()?).await?);

    let bind = env_or("OPENVM_BIND_ADDR", "127.0.0.1:13151".to_string())?;
    let (host, port) = bind
        .rsplit_once(':')
        .context("OPENVM_BIND_ADDR must be host:port")?;
    let port: u16 = port
        .parse()
        .context("OPENVM_BIND_ADDR has an invalid port")?;

    let server = E3ProgramServer::builder(move |job| {
        let prover = Arc::clone(&prover);
        async move {
            let domain = ComputeDomain {
                chain_id: job.domain.chain_id,
                verifying_contract: job.domain.verifying_contract,
                e3_id: job.domain.e3_id,
                encryption_scheme_id: job.domain.encryption_scheme_id,
                committee_public_key_hash: job.domain.committee_public_key_hash,
            };
            prover
                .prove(
                    job.inputs,
                    job.published,
                    domain,
                    e3_user_program::fhe_processor,
                    e3_user_program::policy(),
                )
                .await
        }
    })
    .with_host(host)
    .with_port(port)
    .with_max_concurrent_jobs(env_or("MAX_CONCURRENT_COMPUTATIONS", 1)?)
    .with_max_request_bytes(env_or("OPENVM_MAX_REQUEST_BYTES", 128 * 1024 * 1024)?)
    .with_body_timeout(Duration::from_secs(env_or(
        "OPENVM_BODY_TIMEOUT_SECS",
        120,
    )?))
    .build()?;

    server.run().await
}
