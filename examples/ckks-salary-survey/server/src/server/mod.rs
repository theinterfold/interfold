// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! The coordinator process: sled store + chain indexer + auto-evaluator +
//! HTTP API (CRISP's `server` shape).

pub mod app_data;
pub mod chain;
pub mod database;
pub mod evaluator;
pub mod indexer;
pub mod models;
pub mod repo;
pub mod routes;

use std::sync::Arc;
use std::time::Duration;

use actix_cors::Cors;
use actix_web::{middleware::Logger, web, App, HttpServer};
use e3_sdk::indexer::SharedStore;
use log::{error, info};
use tokio::sync::RwLock;

use crate::config::CONFIG;
use app_data::AppData;
use chain::Chain;
use database::SledDB;

#[actix_web::main]
pub async fn start() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let db = SledDB::new(&CONFIG.database_path)?;
    let store = SharedStore::new(Arc::new(RwLock::new(db.clone())));

    let chain = Chain::connect(
        &CONFIG.http_rpc_url,
        &CONFIG.private_key,
        &CONFIG.e3_program_address,
        &CONFIG.interfold_address,
        &CONFIG.fee_token_address,
    )
    .await?;
    info!(
        "salary-survey server: program {} relayer {:#x} relin keys {}",
        CONFIG.e3_program_address, chain.wallet, CONFIG.relin_key_dir
    );

    tokio::spawn({
        let store = store.clone();
        async move {
            let cfg = indexer::IndexerConfig {
                ws_rpc_url: CONFIG.ws_rpc_url.clone(),
                interfold_address: CONFIG.interfold_address.clone(),
                registry_address: CONFIG.ciphernode_registry_address.clone(),
                program_address: CONFIG.e3_program_address.clone(),
                private_key: CONFIG.private_key.clone(),
            };
            if let Err(e) = indexer::start_indexer(cfg, store).await {
                error!("indexer failed: {e:?}");
            }
        }
    });

    tokio::spawn(evaluator::run_auto_evaluator(
        store.clone(),
        db.clone(),
        chain.clone(),
        CONFIG.relin_key_dir.clone(),
        Duration::from_secs(5),
    ));

    let bind_addr = CONFIG.bind_addr.clone();
    let server = HttpServer::new(move || {
        let cors = Cors::default()
            .allow_any_origin()
            .allowed_methods(vec!["GET", "POST", "OPTIONS"])
            .allow_any_header()
            .max_age(3600);
        App::new()
            .wrap(cors)
            .wrap(Logger::new(r#"%a "%r" %s %b %T"#))
            .app_data(web::JsonConfig::default().limit(64 * 1024 * 1024))
            .app_data(web::Data::new(AppData {
                store: store.clone(),
                db: db.clone(),
                chain: chain.clone(),
            }))
            .configure(routes::setup_routes)
    })
    .bind(&bind_addr)?;
    println!("'ckks-salary-survey' server listening on http://{bind_addr}");
    server.run().await?;
    Ok(())
}
