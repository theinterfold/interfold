# e3-dashboard

## Purpose

Read-only node-operator dashboard with an embedded web UI and JSON endpoints. It projects durable
event history and network status; it does not participate in protocol decisions.

## Map

| Location                             | Responsibility                                                                 |
| ------------------------------------ | ------------------------------------------------------------------------------ |
| [`lib.rs`](src/lib.rs)               | HTTP routes, aggregate cursors, runtime state, and cached operator RPC status. |
| [`projection.rs`](src/projection.rs) | Event-to-E3/committee/reward views and protocol summaries.                     |
| [`updates.rs`](src/updates.rs)       | Release metadata and version comparison.                                       |
| [`assets/`](assets)                  | Embedded browser UI, scripts, styles, and logo.                                |

Requests advance the projection from each aggregate's EventStore cursor, then serialize the view.
Network and operational logs come from separate collectors. Operator RPC status and release metadata
are cached independently of durable history.

## Serve a dashboard

Construct `DashboardState::new(runtime, eventstore, aggregate_ids, network, chain_configs)` and
await `start_dashboard(port, state)` in an Actix runtime. `DashboardRuntime` contains node identity,
ports, version, and displayed chains; use the ciphernode handle's event-store reader, aggregate IDs,
and network status for the remaining runtime inputs. The CLI's
[startup integration](../cli/src/start.rs) supplies these from the running node.

Open `http://127.0.0.1:<port>/`. The server deliberately binds loopback: its API is unauthenticated
and exposes detailed operational/protocol data.

## HTTP API

- `GET /api/snapshot`: node/network overview, protocol state, operator status, E3 summaries, and
  recent events.
- `GET /api/e3?e3_id=...`: a projected request trace; unknown requests return 404.
- `GET /api/events?limit=...`: recent protocol events (up to 2,000).
- `GET /api/logs?since=...&limit=...&level=...&target=...&text=...`: operational log cursor query.
- `GET /api/updates`: cached release information.

Event projections refresh by per-aggregate sequence cursor. Operator chain status uses timed, cached
RPC calls; errors/stale diagnostic state are not canonical chain authority. Logs come from the
bounded [logger collector](../logger/README.md), separately from durable event history.

## Tests

Run `cargo test --locked -p e3-dashboard` after preparing the
[EVM build prerequisites](../evm/README.md). Projection tests do not require a live public chain.

Inline [`projection.rs`](src/projection.rs) tests feed synthetic histories into summaries/traces;
[`updates.rs`](src/updates.rs) tests release/version handling. These do not exercise a browser or
authenticate the HTTP service. [AGENTS.md](AGENTS.md) describes projection changes.
