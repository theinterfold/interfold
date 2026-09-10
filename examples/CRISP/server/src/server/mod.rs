// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

mod app_data;
mod data_availability;
mod database;
mod indexer;
mod log_repo;
mod models;
mod program_server_request;
mod rate_limit;
mod read_cache;
mod repo;
mod routes;
pub mod token_holders;

use std::sync::Arc;

use actix_cors::Cors;
use actix_web::{middleware::Logger, web, App, HttpServer};
use app_data::AppData;
use data_availability::AvailabilityService;
use database::SledDB;
use e3_sdk::indexer::SharedStore;
use eyre::OptionExt;
use indexer::start_indexer;
use tokio::sync::RwLock;

use crate::config::CONFIG;
use crate::logger::init_logger;

#[actix_web::main]
pub async fn start() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    init_logger();

    let pathdb = std::env::current_dir()?.join("database/server");
    let pathdb = pathdb.to_str().ok_or_eyre("Path could not be determined")?;
    let sled_db = SledDB::new(pathdb)?;
    let availability = Arc::new(AvailabilityService::new(&sled_db.db, &CONFIG)?);
    availability.validate_onchain_configuration().await?;
    let availability_worker = Arc::clone(&availability);
    tokio::spawn(async move {
        if let Err(error) = availability_worker.run().await {
            eprintln!("Data-availability worker stopped: {error}");
        }
    });
    let db = SharedStore::new(Arc::new(RwLock::new(sled_db)));

    // New indexer
    // Parsed once here rather than per request: the same list bounds what the indexer watches and
    // what the read routes will serve, and those two must not be able to disagree.
    let index_contracts: Vec<String> = CONFIG
        .index_contracts
        .as_deref()
        .unwrap_or("")
        .split(',')
        .map(|entry| entry.trim().to_string())
        .filter(|entry| !entry.is_empty())
        .collect();

    let index_log_contracts: Vec<String> = CONFIG
        .index_log_contracts
        .as_deref()
        .unwrap_or("")
        .split(',')
        .map(|entry| entry.trim().to_string())
        .filter(|entry| !entry.is_empty())
        .collect();

    tokio::spawn({
        let db = db.clone();
        let availability = availability.clone();
        let index_contracts = index_contracts.clone();
        let index_log_contracts = index_log_contracts.clone();
        async move {
            if let Err(e) = start_indexer(
                &CONFIG.ws_rpc_url,
                &CONFIG.interfold_address,
                &CONFIG.ciphernode_registry_address,
                &CONFIG.e3_program_address,
                db.clone(),
                availability,
                &CONFIG.private_key,
                CONFIG.index_start_block,
                CONFIG.index_chunk_size,
                &index_contracts,
                &index_log_contracts,
            )
            .await
            {
                eprintln!("Listener failed: {:?}", e);
            }
        }
    });

    let bind_addr = "0.0.0.0:4000";
    let db_clone = db.clone();
    let availability_clone = availability.clone();
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
            .wrap(Logger::new(r#"%a "%r" %s %b %T"#))
            .app_data(web::Data::new(AppData::new(db_clone.clone())))
            .app_data(web::Data::from(availability_clone.clone()))
            .app_data(rate_limiter.clone())
            .app_data(chain_rate_limiter.clone())
            .configure(routes::setup_routes)
    })
    .bind(bind_addr)?;

    println!("'crisp-server' listening on http://{}", bind_addr);

    server.run().await?;

    Ok(())
}
