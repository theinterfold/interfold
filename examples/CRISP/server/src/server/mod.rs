// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

mod access_log;
mod app_data;
mod data_availability;
mod database;
mod indexer;
mod log_repo;
mod models;
mod payloads;
mod program_server_request;
mod rate_limit;
mod read_cache;
mod repo;
mod routes;
pub mod rpc;
pub mod token_holders;

use std::fmt::Display;
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use actix_cors::Cors;
use actix_web::{web, App, HttpServer};
use app_data::AppData;
use data_availability::AvailabilityService;
pub use database::compact_database;
use database::SledDB;
use e3_sdk::indexer::SharedStore;
use eyre::OptionExt;
use log::{error, info, warn};
use repo::CrispE3Repository;
use tokio::sync::RwLock;
use tokio::time::{sleep, Instant};

use crate::config::CONFIG;
use crate::logger::init_logger;

const RESTART_DELAY_MIN: Duration = Duration::from_secs(1);
const RESTART_DELAY_MAX: Duration = Duration::from_secs(60);

/// Run `task` until it returns `Ok`. An error or a panic is logged at `error!` and the task starts
/// again after a delay that doubles from 1 s to 60 s, and starts over at 1 s after a run that
/// lasted longer than the cap. Without this, a worker that fails once stays dead while the process
/// keeps serving HTTP as if it were healthy.
async fn supervise<F, Fut, E>(name: &'static str, mut task: F)
where
    F: FnMut() -> Fut + Send + 'static,
    Fut: Future<Output = Result<(), E>> + Send + 'static,
    E: Display + Send + 'static,
{
    let mut delay = RESTART_DELAY_MIN;
    loop {
        let started = Instant::now();
        let failure = match tokio::spawn(task()).await {
            Ok(Ok(())) => return,
            Ok(Err(error)) => format!("failed: {error:#}"),
            Err(panic) => format!("panicked: {panic}"),
        };
        if started.elapsed() >= RESTART_DELAY_MAX {
            delay = RESTART_DELAY_MIN;
        }
        error!("The {name} {failure}; restarting in {delay:?}");
        sleep(delay).await;
        delay = (delay * 2).min(RESTART_DELAY_MAX);
    }
}

// Keep RPC transports responsive while an indexer task validates encrypted inputs or serializes
// a large round record. A single-thread runtime can miss WebSocket heartbeats during that work.
#[tokio::main]
pub async fn start() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    init_logger();

    CONFIG.validate_rpc_chain().await?;

    let pathdb = std::env::current_dir()?.join("database/server");
    let pathdb = pathdb.to_str().ok_or_eyre("Path could not be determined")?;
    let sled_db = SledDB::new(pathdb)?;
    let round_ids = sled_db.round_ids()?;
    let disk = sled_db.clone();
    let availability = Arc::new(AvailabilityService::new(&sled_db.db, &CONFIG)?);
    availability.validate_onchain_configuration().await?;
    tokio::spawn(supervise("data-availability worker", {
        let availability = Arc::clone(&availability);
        move || {
            let availability = Arc::clone(&availability);
            async move { availability.run().await }
        }
    }));
    let db = SharedStore::new(Arc::new(RwLock::new(sled_db)));

    // Move the ballots that an older release kept inside each round record to keys of their own,
    // before the indexer and the routes read the rounds. A failure stops the start: a round with
    // ballots left in its record cannot be read. No input changes yet, so a change that a stop cut
    // short also counts as finished here, and the input cache can serve its round again.
    for e3_id in round_ids {
        let mut round = CrispE3Repository::new(db.clone(), &e3_id);
        round
            .move_inline_ciphertexts(|| Ok(disk.sync_to_disk()?))
            .await
            .map_err(|error| eyre::eyre!("[e3_id={e3_id}] Could not move the ballots: {error}"))?;
        // The round is read from the store either way, so a failure here is not fatal.
        if let Err(error) = round.settle_input_generation().await {
            warn!("[e3_id={e3_id}] Could not settle the input generation: {error:#}");
        }
    }

    indexer::spawn_recovery_tasks(db.clone(), Arc::clone(&availability));
    tokio::spawn(supervise("indexer", {
        let db = db.clone();
        let availability = Arc::clone(&availability);
        move || indexer::run_indexer(db.clone(), Arc::clone(&availability))
    }));

    let bind_addr = std::env::var("CRISP_BIND_ADDR").unwrap_or_else(|_| "0.0.0.0:4000".to_owned());
    // Built once, outside the factory closure: the closure runs per worker, and a per-worker
    // limiter would multiply every window by the worker count.
    let rate_limiter = web::Data::new(rate_limit::RateLimiter::new());
    // Separate window, separate type: the relay's 10-a-minute limit would make the read routes
    // useless, and actix keys `app_data` by type so one type can only ever be one limiter.
    let chain_rate_limiter = web::Data::new(rate_limit::ChainRateLimiter::with_trust(
        CONFIG.trust_proxy_headers,
    ));
    let server = HttpServer::new(move || {
        let cors = Cors::default()
            .allow_any_origin()
            .allowed_methods(vec!["GET", "POST", "OPTIONS"])
            .allow_any_header()
            .supports_credentials()
            .max_age(3600);

        App::new()
            .wrap(cors)
            .wrap(access_log::access_logger())
            .app_data(web::Data::new(AppData::new(db.clone())))
            .app_data(web::Data::from(availability.clone()))
            .app_data(rate_limiter.clone())
            .app_data(chain_rate_limiter.clone())
            .configure(routes::setup_routes)
    })
    .bind(&bind_addr)?;

    info!("'crisp-server' listening on http://{bind_addr}");

    server.run().await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::supervise;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Arc;

    /// A worker that fails or panics is started again instead of staying dead, and a clean return
    /// ends the supervision.
    #[tokio::test(start_paused = true)]
    async fn a_failed_or_panicking_task_is_restarted() {
        let runs = Arc::new(AtomicU32::new(0));
        supervise("test task", {
            let runs = Arc::clone(&runs);
            move || {
                let run = runs.fetch_add(1, Ordering::SeqCst);
                async move {
                    match run {
                        0 => panic!("first run panics"),
                        1 => Err("second run fails"),
                        _ => Ok(()),
                    }
                }
            }
        })
        .await;
        assert_eq!(runs.load(Ordering::SeqCst), 3);
    }
}
