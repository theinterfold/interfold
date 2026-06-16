// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

mod app_data;
mod database;
mod indexer;
mod models;
mod program_server_request;
mod repo;
mod routes;
pub mod token_holders;

use std::sync::Arc;

use actix_cors::Cors;
use actix_web::{middleware::Logger, web, App, HttpServer};
use app_data::AppData;
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
    let db = SharedStore::new(Arc::new(RwLock::new(SledDB::new(pathdb)?)));

    // New indexer
    tokio::spawn({
        let db = db.clone();
        async move {
            if let Err(e) = start_indexer(
                &CONFIG.ws_rpc_url,
                &CONFIG.interfold_address,
                &CONFIG.ciphernode_registry_address,
                &CONFIG.e3_program_address,
                db.clone(),
                &CONFIG.private_key,
            )
            .await
            {
                eprintln!("Listener failed: {:?}", e);
            }
        }
    });

    let bind_addr = "0.0.0.0:4000";
    let db_clone = db.clone();
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
            .configure(routes::setup_routes)
    })
    .bind(bind_addr)?;

    println!("'crisp-server' listening on http://{}", bind_addr);

    server.run().await?;

    Ok(())
}
