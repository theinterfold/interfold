// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use actix_web::{web, App, HttpResponse, HttpServer, Responder};
use anyhow::*;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::info;

use crate::nodes::nodes::Query;

use super::{
    nodes::{Action, SERVER_ADDRESS},
    process_manager::ProcessManager,
};

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

pub async fn server(manager: Arc<Mutex<ProcessManager>>) -> Result<()> {
    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(manager.clone()))
            .route("/command", web::post().to(handle_command))
            .route("/status", web::get().to(status))
    })
    .workers(1)
    .bind(SERVER_ADDRESS)?
    .run()
    .await?;
    Ok(())
}
