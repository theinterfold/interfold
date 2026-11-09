// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! The Prometheus metrics endpoint of a node.
//!
//! It is a separate listener from the dashboard. It serves aggregate numbers only, never event
//! payloads or logs, so an operator can bind it to an interface that a scraper outside a container
//! can reach. Each scrape reads the same sources as `/api/snapshot`, so the values cannot drift
//! from what the dashboard shows, and builds a fresh registry, so a chain or an E3 status that no
//! longer exists leaves no stale series.

use crate::{
    projection::{E3Phase, E3Summary, ProtocolOverview},
    DashboardRuntime, DashboardState, OperatorStatusSnapshot,
};
use actix_web::{dev::Server, get, http::header, web, App, HttpResponse, HttpServer, Responder};
use e3_evm::ChainIngestion;
use e3_net::NetworkSnapshot;
use e3_task_pool::TaskPoolLoad;
use prometheus_client::{
    encoding::text::encode,
    metrics::{family::Family, gauge::Gauge, info::Info},
    registry::Registry,
};
use std::{net::SocketAddr, sync::atomic::AtomicU64};
use tracing::{info, warn};

const CONTENT_TYPE: &str = "application/openmetrics-text; version=1.0.0; charset=utf-8";
/// The E3 statuses of the dashboard projection.
const E3_STATUSES: [&str; 4] = ["active", "degraded", "failed", "complete"];

type Labels = Vec<(&'static str, String)>;
type FloatGauge = Gauge<f64, AtomicU64>;

/// Everything that one scrape reports, read before rendering so that rendering is pure.
pub(crate) struct MetricsInput<'a> {
    pub runtime: &'a DashboardRuntime,
    pub network: NetworkSnapshot,
    pub operator: OperatorStatusSnapshot,
    /// `None` when the EventStore could not be read in this scrape.
    pub protocol: Option<(ProtocolOverview, Vec<E3Summary>)>,
    pub ingestion: Vec<ChainIngestion>,
    pub expected_chains: usize,
    /// `None` for a node without a compute pool, such as a bootstrap node.
    pub compute: Option<TaskPoolLoad>,
}

impl DashboardState {
    async fn metrics_input(&self) -> MetricsInput<'_> {
        let protocol = match self.refresh().await {
            Ok(()) => {
                let projection = self.projection.lock().await;
                Some((
                    projection.projection.overview(),
                    projection.projection.summaries(),
                ))
            }
            Err(error) => {
                warn!(%error, "metrics scrape could not read the EventStore");
                None
            }
        };
        MetricsInput {
            runtime: &self.runtime,
            network: self.network.snapshot(),
            operator: self.refresh_operator_status().await,
            protocol,
            ingestion: self.ingestion.snapshot(),
            expected_chains: self
                .chain_configs
                .iter()
                .filter(|chain| chain.enabled.unwrap_or(true))
                .count(),
            compute: self.task_pool.as_ref().map(e3_task_pool::TaskPool::load),
        }
    }
}

/// A gauge without labels.
fn gauge(registry: &mut Registry, name: &str, help: &str, value: i64) {
    let metric = Gauge::<i64>::default();
    metric.set(value);
    registry.register(name, help, metric);
}

/// A gauge family whose series the caller sets.
fn family<M>(registry: &mut Registry, name: &str, help: &str) -> Family<Labels, M>
where
    M: prometheus_client::metrics::TypedMetric
        + prometheus_client::encoding::EncodeMetric
        + Default
        + std::fmt::Debug
        + Send
        + Sync
        + 'static,
{
    let metric = Family::<Labels, M>::default();
    registry.register(name, help, metric.clone());
    metric
}

fn chain_label(chain_id: u64) -> Labels {
    vec![("chain_id", chain_id.to_string())]
}

/// A token amount that the chain returned as a decimal string. Large amounts lose precision,
/// which is acceptable for monitoring. `None` leaves the series out instead of reporting `NaN`.
fn amount(value: &str) -> Option<f64> {
    value.parse().ok()
}

/// A count that the chain returned as a decimal string. `None` leaves the series out.
fn count(value: &str) -> Option<i64> {
    value.parse().ok()
}

pub(crate) fn render(input: &MetricsInput<'_>) -> String {
    let mut registry = Registry::with_prefix("interfold");
    let runtime = input.runtime;

    registry.register(
        "node",
        "Identity and version of the running node",
        Info::new(vec![
            ("version", runtime.version.clone()),
            ("name", runtime.node_name.clone()),
            ("address", runtime.address.clone()),
            ("peer_id", runtime.peer_id.clone()),
        ]),
    );

    let network = &input.network;
    gauge(
        &mut registry,
        "peers_connected",
        "Connected libp2p peers",
        network.connected_peers.len() as i64,
    );
    gauge(
        &mut registry,
        "peers_configured",
        "Configured libp2p peers",
        network.configured_peers as i64,
    );
    gauge(
        &mut registry,
        "peers_gossip_subscribed",
        "Peers subscribed to the protocol gossip topic",
        network.gossip_subscribed_peers as i64,
    );
    gauge(
        &mut registry,
        "network_error",
        "1 if the transport reports an error",
        i64::from(network.last_error.is_some()),
    );

    render_operator(&mut registry, &input.operator, input.expected_chains);
    render_ingestion(&mut registry, &input.ingestion, input.expected_chains);

    gauge(
        &mut registry,
        "eventstore_read_up",
        "1 if this scrape read the EventStore; the E3 metrics are absent otherwise",
        i64::from(input.protocol.is_some()),
    );
    if let Some((overview, summaries)) = &input.protocol {
        render_protocol(&mut registry, overview, summaries);
    }

    if let Some(load) = input.compute {
        gauge(
            &mut registry,
            "compute_jobs_capacity",
            "ZK and TrBFV jobs that the compute pool runs at once",
            load.capacity as i64,
        );
        gauge(
            &mut registry,
            "compute_jobs_admitted",
            "ZK and TrBFV jobs that the compute pool admitted, queued inside it or running",
            load.admitted as i64,
        );
        gauge(
            &mut registry,
            "compute_jobs_waiting",
            "ZK and TrBFV jobs that wait for admission to the compute pool",
            load.waiting as i64,
        );
        gauge(
            &mut registry,
            "compute_jobs_retrying",
            "ZK and TrBFV jobs that wait out a retry delay after a failure",
            load.retrying as i64,
        );
    }

    let mut body = String::new();
    // Writing to a String cannot fail.
    let _ = encode(&mut body, &registry);
    body
}

fn render_operator(registry: &mut Registry, operator: &OperatorStatusSnapshot, expected: usize) {
    // A node without an enabled chain has nothing to read, which is not a failed read.
    gauge(
        registry,
        "operator_status_up",
        "1 if the latest read of the operator state succeeded on every enabled chain",
        i64::from(operator.error.is_none() && operator.chains.len() == expected),
    );
    if operator.updated_at_ms > 0 {
        gauge(
            registry,
            "operator_status_updated_timestamp_seconds",
            "Unix time of the latest read of the operator state; the node reads it at most every 15 s",
            (operator.updated_at_ms / 1000) as i64,
        );
    }
    if operator.chains.is_empty() {
        return;
    }
    let registered = family::<Gauge>(
        registry,
        "operator_registered",
        "1 if the operator is registered in the BondingRegistry",
    );
    let active = family::<Gauge>(
        registry,
        "operator_active",
        "1 if the BondingRegistry marks the operator active",
    );
    let eligible = family::<Gauge>(
        registry,
        "operator_eligible",
        "1 if sortition can select the operator for a new committee, after the admission cooldown and policy",
    );
    let exit_pending = family::<Gauge>(
        registry,
        "operator_exit_pending",
        "1 if the operator has an exit in the queue",
    );
    let tickets = family::<Gauge>(
        registry,
        "operator_tickets_available",
        "Sortition tickets available to the operator",
    );
    let ticket_balance = family::<FloatGauge>(
        registry,
        "operator_ticket_balance",
        "Ticket balance of the operator, in token base units",
    );
    let bond = family::<FloatGauge>(
        registry,
        "operator_bond",
        "Ciphernode bond of the operator, in token base units",
    );
    let registered_nodes = family::<Gauge>(
        registry,
        "registry_registered_nodes",
        "Operators registered on the chain",
    );
    let active_nodes = family::<Gauge>(
        registry,
        "registry_active_nodes",
        "Active operators on the chain",
    );
    for chain in &operator.chains {
        let labels = chain_label(chain.chain_id);
        registered
            .get_or_create(&labels)
            .set(i64::from(chain.operator_registered));
        active
            .get_or_create(&labels)
            .set(i64::from(chain.operator_active));
        // An unknown eligibility has no series, so it does not read as "not eligible".
        if let Some(value) = chain.operator_eligible {
            eligible.get_or_create(&labels).set(i64::from(value));
        }
        exit_pending
            .get_or_create(&labels)
            .set(i64::from(chain.exit_in_progress));
        for (metric, value) in [
            (&tickets, &chain.available_tickets),
            (&registered_nodes, &chain.registered_nodes),
            (&active_nodes, &chain.active_nodes),
        ] {
            if let Some(value) = count(value) {
                metric.get_or_create(&labels).set(value);
            }
        }
        for (metric, value) in [
            (&ticket_balance, &chain.ticket_balance),
            (&bond, &chain.ciphernode_bond),
        ] {
            if let Some(value) = amount(value) {
                metric.get_or_create(&labels).set(value);
            }
        }
    }
}

fn render_ingestion(registry: &mut Registry, ingestion: &[ChainIngestion], expected: usize) {
    gauge(
        registry,
        "chain_readers_expected",
        "Chain readers that the node started; a reader without a successful read has no chain_* series",
        expected as i64,
    );
    if ingestion.is_empty() {
        return;
    }
    let head = family::<Gauge>(
        registry,
        "chain_head_block",
        "Chain head at the latest successful read of the chain reader",
    );
    let cursor = family::<Gauge>(
        registry,
        "chain_cursor_block",
        "Last block whose logs the chain reader delivered",
    );
    let polled = family::<Gauge>(
        registry,
        "chain_polled_timestamp_seconds",
        "Unix time of the latest successful read of the chain head",
    );
    let progressed = family::<Gauge>(
        registry,
        "chain_progressed_timestamp_seconds",
        "Unix time of the latest read at which the chain head or the cursor moved",
    );
    for chain in ingestion {
        let labels = chain_label(chain.chain_id);
        head.get_or_create(&labels).set(chain.head as i64);
        cursor.get_or_create(&labels).set(chain.cursor as i64);
        polled.get_or_create(&labels).set(chain.polled_at as i64);
        progressed
            .get_or_create(&labels)
            .set(chain.progressed_at as i64);
    }
}

fn render_protocol(registry: &mut Registry, overview: &ProtocolOverview, summaries: &[E3Summary]) {
    gauge(
        registry,
        "e3_active",
        "E3s that still need this node, including failed E3s for a day after the failure",
        overview.e3_active as i64,
    );
    let by_status = family::<Gauge>(registry, "e3s", "E3s that this node observed, by status");
    for status in E3_STATUSES {
        let count = summaries
            .iter()
            .filter(|summary| summary.status == status)
            .count();
        by_status
            .get_or_create(&vec![("status", status.to_owned())])
            .set(count as i64);
    }
    let by_phase = family::<Gauge>(
        registry,
        "e3_in_progress",
        "Active and degraded E3s that this node observed, by current phase",
    );
    for phase in E3Phase::ALL {
        let count = summaries
            .iter()
            .filter(|summary| {
                summary.current_phase == phase
                    && (summary.status == "active" || summary.status == "degraded")
            })
            .count();
        by_phase
            .get_or_create(&vec![("phase", phase.id().to_owned())])
            .set(count as i64);
    }
    if overview.chains.is_empty() {
        return;
    }
    let rewards = family::<Gauge>(
        registry,
        "operator_rewards_credited",
        "E3 rewards that the operator earned as a committee member",
    );
    for chain in &overview.chains {
        rewards
            .get_or_create(&chain_label(chain.chain_id))
            .set(chain.rewards_credited.len() as i64);
    }
}

#[get("/metrics")]
async fn metrics(state: web::Data<DashboardState>) -> impl Responder {
    let input = state.metrics_input().await;
    HttpResponse::Ok()
        .insert_header((header::CONTENT_TYPE, CONTENT_TYPE))
        .body(render(&input))
}

/// Bind `GET /metrics` to `address` and return the server to await, with the bound address. The
/// bind happens here, not when the server runs, so that a caller can report an address in use
/// instead of announcing an endpoint that does not exist. Unlike the dashboard it may bind any
/// interface, because it serves aggregate numbers only. It is unauthenticated, so bind it to a
/// private interface.
pub fn metrics_server(
    address: SocketAddr,
    state: DashboardState,
) -> std::io::Result<(Server, SocketAddr)> {
    let server = HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(state.clone()))
            .service(metrics)
    })
    // One worker: a scrape is short, and the node needs its threads for protocol work.
    .workers(1)
    .bind(address)?;
    let bound = server.addrs().first().copied().unwrap_or(address);
    info!(address = %bound, "node metrics listening on http://{bound}/metrics");
    Ok((server.run(), bound))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DashboardChain;
    use e3_event_system::EventSystem;
    use e3_evm::{IngestionProgress, IngestionStatus, OperatorChainStatus};
    use e3_evm_config::ChainConfig;
    use e3_net::NetworkStatus;
    use e3_task_pool::TaskPool;

    /// A state that reads an empty in-memory EventStore.
    fn state(chains: Vec<ChainConfig>) -> DashboardState {
        let eventstore = EventSystem::in_mem()
            .eventstore_reader()
            .expect("in-memory EventStore");
        DashboardState::new(
            runtime(),
            eventstore,
            vec![0],
            NetworkStatus::default(),
            chains,
        )
    }

    /// Bind a listener on a free loopback port and run it.
    fn serve(state: DashboardState) -> (actix_web::dev::ServerHandle, SocketAddr) {
        let (server, address) =
            metrics_server("127.0.0.1:0".parse().unwrap(), state).expect("bind");
        let handle = server.handle();
        actix_web::rt::spawn(server);
        (handle, address)
    }

    async fn scrape(address: SocketAddr, path: &str) -> reqwest::Response {
        reqwest::get(format!("http://{address}{path}"))
            .await
            .expect("request")
    }

    /// The listener serves only `/metrics`, as OpenMetrics, and a second listener on the same
    /// address fails when it binds, so the caller does not announce an endpoint that is not there.
    #[actix_web::test]
    async fn an_address_in_use_fails_when_it_binds() {
        let state = state(Vec::new());
        let (handle, address) = serve(state.clone());

        let response = scrape(address, "/metrics").await;
        assert_eq!(response.status(), 200);
        assert_eq!(
            response.headers()[reqwest::header::CONTENT_TYPE],
            CONTENT_TYPE
        );
        assert!(response.text().await.unwrap().ends_with("# EOF\n"));
        assert_eq!(scrape(address, "/api/snapshot").await.status(), 404);

        assert!(metrics_server(address, state).is_err());
        handle.stop(true).await;
    }

    fn chain_config(name: &str, enabled: bool) -> ChainConfig {
        serde_json::from_value(serde_json::json!({
            "name": name,
            "enabled": enabled,
            // Nothing listens on port 1, so the operator read fails at once.
            "rpc_url": "http://127.0.0.1:1",
            "contracts": {
                "interfold": "0x9fE46736679d2D9a65F0992F2272dE9f3c7fa6e0",
                "ciphernode_registry": "0xCf7Ed3AccA5a467e9e704C703E8D87F634fB0Fc9",
                "bonding_registry": "0xDc64a140Aa3E981100a9becA4E685f962f0cF6C9",
            },
        }))
        .expect("chain config")
    }

    /// A scrape reports the state that the CLI wires in: the chain readers' progress, the compute
    /// pool, and the enabled chains only.
    #[actix_web::test]
    async fn a_scrape_reports_the_state_that_the_cli_wires_in() {
        let ingestion = IngestionStatus::default();
        ingestion.record(
            IngestionProgress {
                chain_id: 1,
                head: 120,
                cursor: 110,
            },
            1_700_000_000,
        );
        let state = state(vec![chain_config("one", true), chain_config("two", false)])
            .with_ingestion_status(ingestion)
            .with_task_pool(Some(TaskPool::new(1, 3)));
        let (handle, address) = serve(state);

        let body = scrape(address, "/metrics").await.text().await.unwrap();

        assert_eq!(value(&body, "interfold_chain_readers_expected"), "1");
        assert_eq!(
            value(&body, "interfold_chain_head_block{chain_id=\"1\"}"),
            "120"
        );
        assert_eq!(value(&body, "interfold_compute_jobs_capacity"), "3");
        assert_eq!(value(&body, "interfold_eventstore_read_up"), "1");
        // The enabled chain's RPC refuses the connection, so that chain has no operator series.
        assert_eq!(value(&body, "interfold_operator_status_up"), "0");
        assert!(!body.contains("interfold_operator_active{"), "{body}");
        handle.stop(true).await;
    }

    fn runtime() -> DashboardRuntime {
        DashboardRuntime {
            node_name: "cn1".to_owned(),
            address: "0x6073000000000000000000000000000000000001".to_owned(),
            peer_id: "12D3KooWPeer".to_owned(),
            quic_port: 9091,
            dashboard_port: 9092,
            version: "0.20.0".to_owned(),
            chains: vec![DashboardChain {
                id: 1,
                name: "mainnet".to_owned(),
            }],
        }
    }

    fn operator_chain(eligible: Option<bool>) -> OperatorChainStatus {
        OperatorChainStatus {
            chain_id: 1,
            chain_name: "mainnet".to_owned(),
            registered_nodes: "42".to_owned(),
            active_nodes: "40".to_owned(),
            operator_registered: true,
            operator_active: true,
            operator_eligible: eligible,
            exit_in_progress: false,
            ticket_balance: "8000000000000000000000".to_owned(),
            available_tickets: "8".to_owned(),
            ciphernode_bond: "32000000000000000000000".to_owned(),
            bond_owner: "0x0000000000000000000000000000000000000002".to_owned(),
        }
    }

    fn input(runtime: &DashboardRuntime) -> MetricsInput<'_> {
        MetricsInput {
            runtime,
            network: NetworkSnapshot {
                configured_peers: 3,
                ..NetworkSnapshot::default()
            },
            operator: OperatorStatusSnapshot {
                chains: vec![operator_chain(Some(true))],
                error: None,
                updated_at_ms: 1_700_000_000_500,
            },
            protocol: None,
            ingestion: vec![ChainIngestion {
                chain_id: 1,
                head: 25_000_100,
                cursor: 25_000_088,
                polled_at: 1_700_000_000,
                progressed_at: 1_699_999_990,
            }],
            expected_chains: 1,
            compute: Some(TaskPoolLoad {
                capacity: 2,
                admitted: 2,
                waiting: 5,
                retrying: 1,
            }),
        }
    }

    /// The value of the one series of `name` with `labels`, for example `{chain_id="1"}`.
    fn value(body: &str, series: &str) -> String {
        body.lines()
            .find_map(|line| line.strip_prefix(&format!("{series} ")))
            .unwrap_or_else(|| panic!("no series {series} in:\n{body}"))
            .to_owned()
    }

    #[test]
    fn a_scrape_reports_the_operator_the_chain_readers_and_the_compute_pool() {
        let runtime = runtime();
        let body = render(&input(&runtime));

        assert!(body.ends_with("# EOF\n"), "{body}");
        assert!(body.contains("interfold_node_info{version=\"0.20.0\",name=\"cn1\",address=\"0x6073000000000000000000000000000000000001\",peer_id=\"12D3KooWPeer\"} 1"), "{body}");
        assert_eq!(value(&body, "interfold_peers_configured"), "3");
        assert_eq!(value(&body, "interfold_peers_connected"), "0");
        assert_eq!(value(&body, "interfold_operator_status_up"), "1");
        assert_eq!(
            value(&body, "interfold_operator_status_updated_timestamp_seconds"),
            "1700000000"
        );
        assert_eq!(
            value(&body, "interfold_operator_active{chain_id=\"1\"}"),
            "1"
        );
        assert_eq!(
            value(&body, "interfold_operator_eligible{chain_id=\"1\"}"),
            "1"
        );
        assert_eq!(
            value(
                &body,
                "interfold_operator_tickets_available{chain_id=\"1\"}"
            ),
            "8"
        );
        assert_eq!(
            value(&body, "interfold_operator_bond{chain_id=\"1\"}"),
            "3.2e22"
        );
        assert_eq!(
            value(&body, "interfold_chain_cursor_block{chain_id=\"1\"}"),
            "25000088"
        );
        assert_eq!(
            value(
                &body,
                "interfold_chain_progressed_timestamp_seconds{chain_id=\"1\"}"
            ),
            "1699999990"
        );
        assert_eq!(value(&body, "interfold_chain_readers_expected"), "1");
        assert_eq!(value(&body, "interfold_compute_jobs_waiting"), "5");
        assert_eq!(value(&body, "interfold_compute_jobs_retrying"), "1");
        // Without an EventStore read, the E3 metrics are absent rather than zero.
        assert_eq!(value(&body, "interfold_eventstore_read_up"), "0");
        assert!(!body.contains("interfold_e3_active"), "{body}");
    }

    /// A failed eligibility read has no series, so an alert on `operator_eligible == 0` does not
    /// fire for an RPC error, which `operator_status_up` reports instead.
    #[test]
    fn an_unknown_eligibility_has_no_series() {
        let runtime = runtime();
        let mut input = input(&runtime);
        input.operator.chains = vec![operator_chain(None)];
        input.operator.error = Some("mainnet: RPC query timed out".to_owned());

        let body = render(&input);

        assert!(!body.contains("interfold_operator_eligible{"), "{body}");
        assert_eq!(value(&body, "interfold_operator_status_up"), "0");
    }

    /// The `phase` label is the name that `/api/snapshot` serializes.
    #[test]
    fn phase_labels_match_the_api() {
        for phase in E3Phase::ALL {
            assert_eq!(serde_json::to_value(phase).unwrap(), phase.id());
        }
    }

    /// A value that does not parse leaves its series out, so a comparison does not meet `NaN`.
    #[test]
    fn an_unparsable_value_has_no_series() {
        let runtime = runtime();
        let mut input = input(&runtime);
        input.operator.chains[0].ciphernode_bond = "not a number".to_owned();

        let body = render(&input);

        assert!(!body.contains("interfold_operator_bond{"), "{body}");
        assert!(!body.contains("NaN"), "{body}");
        assert_eq!(
            value(
                &body,
                "interfold_operator_tickets_available{chain_id=\"1\"}"
            ),
            "8"
        );
    }

    /// A node without an enabled chain reads nothing, so its operator status is up, not failed.
    #[test]
    fn a_node_without_an_enabled_chain_reports_the_operator_status_as_up() {
        let runtime = runtime();
        let mut input = input(&runtime);
        input.operator.chains = Vec::new();
        input.expected_chains = 0;

        let body = render(&input);

        assert_eq!(value(&body, "interfold_operator_status_up"), "1");
        assert!(!body.contains("interfold_operator_active{"), "{body}");
    }

    /// With two enabled chains and a failed read on one, only the chain that was read has
    /// `operator_*` series: the failed chain has none, so a value alert on it stays silent during
    /// the outage, and `operator_status_up` reports the failure instead.
    #[test]
    fn a_chain_whose_operator_read_fails_has_no_operator_series() {
        let runtime = runtime();
        let mut input = input(&runtime);
        input.operator.error = Some("sepolia: RPC query timed out".to_owned());

        let body = render(&input);

        assert_eq!(value(&body, "interfold_operator_status_up"), "0");
        assert_eq!(
            value(&body, "interfold_operator_active{chain_id=\"1\"}"),
            "1"
        );
        assert!(!body.contains("chain_id=\"11155111\""), "{body}");
    }

    #[test]
    fn e3s_are_counted_by_status_and_by_the_phase_of_those_in_progress() {
        let runtime = runtime();
        let summary = |status: &str, phase: E3Phase| E3Summary {
            e3_id: "1:0".to_owned(),
            chain_id: 1,
            status: status.to_owned(),
            canonical_stage: None,
            current_phase: phase,
            event_count: 0,
            error_count: 0,
            warning_count: 0,
            committee_size: 0,
            first_seen_us: 0,
            last_seen_us: 0,
        };
        let mut input = input(&runtime);
        input.protocol = Some((
            ProtocolOverview {
                chains: Vec::new(),
                e3_total: 3,
                e3_active: 1,
                e3_completed: 1,
                e3_failed: 0,
                e3_degraded: 1,
                events_observed: 0,
            },
            vec![
                summary("active", E3Phase::DkgShares),
                summary("degraded", E3Phase::DkgShares),
                summary("complete", E3Phase::Settlement),
            ],
        ));

        let body = render(&input);

        assert_eq!(value(&body, "interfold_eventstore_read_up"), "1");
        assert_eq!(value(&body, "interfold_e3_active"), "1");
        assert_eq!(value(&body, "interfold_e3s{status=\"complete\"}"), "1");
        assert_eq!(value(&body, "interfold_e3s{status=\"failed\"}"), "0");
        assert_eq!(
            value(&body, "interfold_e3_in_progress{phase=\"dkg_shares\"}"),
            "2"
        );
        assert_eq!(
            value(&body, "interfold_e3_in_progress{phase=\"settlement\"}"),
            "0"
        );
    }
}
