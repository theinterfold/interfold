// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use actix_web::{web, App, HttpResponse, HttpServer, Responder};
use anyhow::*;
use serde::Deserialize;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::info;

use crate::nodes::nodes::Query;

use super::{
    log_buffer::LogBuffer,
    nodes::{Action, SERVER_ADDRESS},
    process_manager::ProcessManager,
};

// ─── Handlers ─────────────────────────────────────────────────────────────────

pub async fn handle_command(
    manager: web::Data<Arc<Mutex<ProcessManager>>>,
    cmd: web::Json<Action>,
) -> impl Responder {
    let cmd: Action = cmd.into_inner();
    async fn process_cmd(
        cmd: Action,
        manager: web::Data<Arc<Mutex<ProcessManager>>>,
    ) -> Result<()> {
        info!("RECEIVED COMMAND! {:?}", cmd);
        match cmd {
            Action::Start { id } => {
                manager.lock().await.start(&id).await?;
            }
            Action::Stop { id } => {
                manager.lock().await.stop(&id).await?;
            }
            Action::Restart { id } => {
                manager.lock().await.restart(&id).await?;
            }
            Action::StopAll => {
                manager.lock().await.stop_all().await?;
            }
            Action::StartAll => {
                manager.lock().await.start_all().await?;
            }
            Action::Terminate => {
                manager.lock().await.terminate().await;
            }
        };

        Ok(())
    }

    match process_cmd(cmd, manager).await {
        std::result::Result::Ok(_) => HttpResponse::Ok().json(Query::Success),
        // Maybe we should make this an error response code?
        std::result::Result::Err(err) => HttpResponse::Ok().json(Query::Failure {
            message: err.to_string(),
        }),
    }
}

pub async fn status(manager: web::Data<Arc<Mutex<ProcessManager>>>) -> impl Responder {
    HttpResponse::Ok().json(Query::Status {
        status: manager.lock().await.list().await,
    })
}

#[derive(Deserialize)]
pub struct LogsQuery {
    /// Filter by node name; omit or pass "all" to get all nodes merged.
    pub node: Option<String>,
    /// Return only lines with seq >= this value (polling cursor).
    pub seq: Option<u64>,
    /// Maximum number of lines to return (server-capped at 1 000).
    pub limit: Option<usize>,
}

pub async fn logs_recent(
    log_buffer: web::Data<Arc<LogBuffer>>,
    query: web::Query<LogsQuery>,
) -> impl Responder {
    let lines = log_buffer
        .recent(
            query.node.as_deref(),
            query.seq.unwrap_or(0),
            query.limit.unwrap_or(500),
        )
        .await;
    HttpResponse::Ok()
        .insert_header(("Access-Control-Allow-Origin", "*"))
        .json(lines)
}

pub async fn logs_nodes(log_buffer: web::Data<Arc<LogBuffer>>) -> impl Responder {
    let nodes = log_buffer.nodes().await;
    HttpResponse::Ok()
        .insert_header(("Access-Control-Allow-Origin", "*"))
        .json(nodes)
}

// ─── Server ───────────────────────────────────────────────────────────────────

pub async fn server(manager: Arc<Mutex<ProcessManager>>, log_buffer: Arc<LogBuffer>) -> Result<()> {
    info!("Swarm server available at http://{}", SERVER_ADDRESS);
    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(manager.clone()))
            .app_data(web::Data::new(log_buffer.clone()))
            .route("/command", web::post().to(handle_command))
            .route("/status", web::get().to(status))
            .route("/logs/recent", web::get().to(logs_recent))
            .route("/logs/nodes", web::get().to(logs_nodes))
    })
    .workers(1)
    .bind(SERVER_ADDRESS)?
    .run()
    .await?;
    Ok(())
}
