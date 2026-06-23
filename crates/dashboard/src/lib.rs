// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

mod projection;
mod updates;

use actix_web::{
    get,
    http::header::{self, CacheControl, CacheDirective},
    middleware, web, App, HttpResponse, HttpServer, Responder,
};
use anyhow::{Context, Result};
use e3_ciphernode_builder::global_eventstore_cache::EventStoreReader;
use e3_config::chain_config::ChainConfig;
use e3_events::{
    AggregateId, CorrelationId, EventContextSeq, EventStoreQueryBy, EventStoreQueryResponse, SeqAgg,
};
use e3_logger::LogCollector;
use e3_net::NetworkStatus;
use e3_utils::actix::channel as actix_toolbox;
use projection::TelemetryProjection;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    str::FromStr,
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::sync::Mutex;
use tracing::info;

const INDEX_HTML: &str = include_str!("../assets/index.html");
const APP_JS: &str = include_str!("../assets/app.js");
const APP_CSS: &str = include_str!("../assets/app.css");
const INTERFOLD_LOGO: &str = include_str!("../assets/interfold.svg");
const PAGE_SIZE: u64 = 2_000;

#[derive(Clone, Debug, Serialize)]
pub struct DashboardChain {
    pub id: u64,
    pub name: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct DashboardRuntime {
    pub node_name: String,
    pub address: String,
    pub peer_id: String,
    pub quic_port: u16,
    pub dashboard_port: u16,
    pub version: String,
    pub chains: Vec<DashboardChain>,
}

#[derive(Clone)]
pub struct DashboardState {
    runtime: DashboardRuntime,
    eventstore: EventStoreReader,
    aggregate_ids: Arc<Vec<usize>>,
    network: NetworkStatus,
    projection: Arc<Mutex<ProjectionState>>,
    chain_configs: Arc<Vec<ChainConfig>>,
    operator_status: Arc<Mutex<OperatorStatusCache>>,
    updates: updates::UpdateService,
}

struct ProjectionState {
    cursors: HashMap<usize, u64>,
    projection: TelemetryProjection,
}

#[derive(Clone, Debug, Default, Serialize)]
struct OperatorStatusSnapshot {
    chains: Vec<e3_evm::OperatorChainStatus>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    updated_at_ms: u64,
}

#[derive(Default)]
struct OperatorStatusCache {
    refreshed_at: Option<Instant>,
    snapshot: OperatorStatusSnapshot,
}

impl DashboardState {
    pub fn new(
        runtime: DashboardRuntime,
        eventstore: EventStoreReader,
        aggregate_ids: Vec<usize>,
        network: NetworkStatus,
        chain_configs: Vec<ChainConfig>,
    ) -> Self {
        let mut aggregate_ids = aggregate_ids;
        aggregate_ids.sort_unstable();
        aggregate_ids.dedup();
        let projection = TelemetryProjection::new(runtime.address.clone());
        let update_service = updates::UpdateService::new(runtime.version.clone());
        Self {
            runtime,
            eventstore,
            aggregate_ids: Arc::new(aggregate_ids),
            network,
            projection: Arc::new(Mutex::new(ProjectionState {
                cursors: HashMap::new(),
                projection,
            })),
            chain_configs: Arc::new(chain_configs),
            operator_status: Arc::new(Mutex::new(OperatorStatusCache::default())),
            updates: update_service,
        }
    }

    async fn refresh(&self) -> Result<()> {
        let mut state = self.projection.lock().await;
        for aggregate in self.aggregate_ids.iter().copied() {
            loop {
                let since = state.cursors.get(&aggregate).copied().unwrap_or(0);
                let page = self.fetch_page(aggregate, since).await?;
                if page.is_empty() {
                    break;
                }
                let event_count = page.len();
                let next = page
                    .iter()
                    .map(EventContextSeq::seq)
                    .max()
                    .unwrap_or(since)
                    .saturating_add(1);
                for event in page {
                    state.projection.apply(event);
                }
                state.cursors.insert(aggregate, next);
                if event_count < PAGE_SIZE as usize {
                    break;
                }
            }
        }
        Ok(())
    }

    async fn fetch_page(
        &self,
        aggregate: usize,
        since: u64,
    ) -> Result<Vec<e3_events::InterfoldEvent>> {
        let (recipient, response) = actix_toolbox::oneshot::<EventStoreQueryResponse>();
        let query = EventStoreQueryBy::<SeqAgg>::new(
            CorrelationId::new(),
            HashMap::from([(AggregateId::new(aggregate), since)]),
            recipient,
        )
        .with_limit(PAGE_SIZE);
        self.eventstore.seq().do_send(query);
        let response = tokio::time::timeout(Duration::from_secs(5), response)
            .await
            .context("EventStore dashboard query timed out")??;
        Ok(response.into_events())
    }

    async fn refresh_operator_status(&self) -> OperatorStatusSnapshot {
        let mut cache = self.operator_status.lock().await;
        if cache
            .refreshed_at
            .is_some_and(|updated| updated.elapsed() < Duration::from_secs(15))
        {
            return cache.snapshot.clone();
        }

        let operator = match alloy::primitives::Address::from_str(&self.runtime.address) {
            Ok(operator) => operator,
            Err(error) => {
                cache.snapshot.error = Some(format!("invalid operator address: {error}"));
                return cache.snapshot.clone();
            }
        };
        let mut chains = Vec::new();
        let mut errors = Vec::new();
        let queries = self
            .chain_configs
            .iter()
            .filter(|chain| chain.enabled.unwrap_or(true))
            .map(|chain| async move {
                (
                    chain.name.clone(),
                    tokio::time::timeout(
                        Duration::from_secs(8),
                        e3_evm::fetch_operator_status(chain, operator),
                    )
                    .await,
                )
            });
        for (chain_name, result) in futures::future::join_all(queries).await {
            match result {
                Ok(Ok(status)) => chains.push(status),
                Ok(Err(error)) => errors.push(format!("{chain_name}: {error}")),
                Err(_) => errors.push(format!("{chain_name}: RPC query timed out")),
            }
        }
        cache.refreshed_at = Some(Instant::now());
        cache.snapshot = OperatorStatusSnapshot {
            chains,
            error: (!errors.is_empty()).then(|| errors.join("; ")),
            updated_at_ms: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|duration| duration.as_millis() as u64)
                .unwrap_or(0),
        };
        cache.snapshot.clone()
    }
}

#[get("/api/updates")]
async fn release_updates(state: web::Data<DashboardState>) -> impl Responder {
    HttpResponse::Ok().json(state.updates.snapshot().await)
}

#[derive(Serialize)]
struct DashboardSnapshot {
    node: DashboardRuntime,
    network: e3_net::NetworkSnapshot,
    protocol: projection::ProtocolOverview,
    operator: OperatorStatusSnapshot,
    e3s: Vec<projection::E3Summary>,
    recent_events: Vec<projection::EventView>,
}

#[get("/api/snapshot")]
async fn snapshot(state: web::Data<DashboardState>) -> impl Responder {
    match state.refresh().await {
        Ok(()) => {
            let operator = state.refresh_operator_status().await;
            let projection = state.projection.lock().await;
            HttpResponse::Ok().json(DashboardSnapshot {
                node: state.runtime.clone(),
                network: state.network.snapshot(),
                protocol: projection.projection.overview(),
                operator,
                e3s: projection.projection.summaries(),
                recent_events: projection.projection.recent_events(40),
            })
        }
        Err(error) => api_error(error),
    }
}

#[derive(Deserialize)]
struct E3Query {
    e3_id: String,
}

#[get("/api/e3")]
async fn e3_trace(state: web::Data<DashboardState>, query: web::Query<E3Query>) -> impl Responder {
    match state.refresh().await {
        Ok(()) => {
            let projection = state.projection.lock().await;
            match projection.projection.trace(&query.e3_id) {
                Some(trace) => HttpResponse::Ok().json(trace),
                None => HttpResponse::NotFound().json(serde_json::json!({
                    "error": format!("unknown E3 {}", query.e3_id),
                })),
            }
        }
        Err(error) => api_error(error),
    }
}

#[derive(Deserialize)]
struct EventsQuery {
    limit: Option<usize>,
}

#[get("/api/events")]
async fn protocol_events(
    state: web::Data<DashboardState>,
    query: web::Query<EventsQuery>,
) -> impl Responder {
    match state.refresh().await {
        Ok(()) => {
            let projection = state.projection.lock().await;
            HttpResponse::Ok().json(serde_json::json!({
                "events": projection
                    .projection
                    .recent_events(query.limit.unwrap_or(500).min(2_000)),
            }))
        }
        Err(error) => api_error(error),
    }
}

#[derive(Deserialize)]
struct LogsQuery {
    since: Option<u64>,
    limit: Option<usize>,
    level: Option<String>,
    target: Option<String>,
    text: Option<String>,
}

#[get("/api/logs")]
async fn logs(query: web::Query<LogsQuery>) -> impl Responder {
    match LogCollector::global() {
        Some(collector) => HttpResponse::Ok().json(collector.query(
            query.since,
            query.limit,
            query.level.as_deref(),
            query.target.as_deref(),
            query.text.as_deref(),
        )),
        None => HttpResponse::Ok().json(serde_json::json!({
            "entries": [],
            "next_cursor": 0,
            "oldest_cursor": 0,
            "total_stored": 0,
        })),
    }
}

async fn index() -> impl Responder {
    HttpResponse::Ok()
        .insert_header((header::CONTENT_TYPE, "text/html; charset=utf-8"))
        .insert_header(CacheControl(vec![CacheDirective::NoCache]))
        .body(INDEX_HTML)
}

async fn app_js() -> impl Responder {
    static_asset("text/javascript; charset=utf-8", APP_JS)
}

async fn app_css() -> impl Responder {
    static_asset("text/css; charset=utf-8", APP_CSS)
}

async fn logo() -> impl Responder {
    static_asset("image/svg+xml", INTERFOLD_LOGO)
}

fn static_asset(content_type: &'static str, body: &'static str) -> HttpResponse {
    HttpResponse::Ok()
        .insert_header((header::CONTENT_TYPE, content_type))
        .insert_header(CacheControl(vec![
            CacheDirective::Public,
            CacheDirective::MaxAge(31_536_000),
        ]))
        .body(body)
}

fn api_error(error: anyhow::Error) -> HttpResponse {
    HttpResponse::ServiceUnavailable().json(serde_json::json!({
        "error": error.to_string(),
    }))
}

/// Serve the node-operator dashboard. It binds to loopback because the API
/// exposes detailed protocol payloads and is intentionally unauthenticated.
pub async fn start_dashboard(port: u16, state: DashboardState) -> std::io::Result<()> {
    let address = ("127.0.0.1", port);
    info!(port, "node dashboard listening on http://127.0.0.1:{port}");
    HttpServer::new(move || {
        App::new()
            .wrap(middleware::Compress::default())
            .app_data(web::Data::new(state.clone()))
            .service(snapshot)
            .service(e3_trace)
            .service(protocol_events)
            .service(logs)
            .service(release_updates)
            .route("/", web::get().to(index))
            .route("/assets/app.js", web::get().to(app_js))
            .route("/assets/app.css", web::get().to(app_css))
            .route("/assets/interfold.svg", web::get().to(logo))
            .route("/interfold.svg", web::get().to(logo))
            .default_service(web::get().to(index))
    })
    .bind(address)?
    .run()
    .await
}
