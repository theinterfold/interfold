# e3-daemon-server

## Purpose

Loopback command transport between the local CLI and an already-running node. The crate transports
serialized commands and text output; callers own command authorization and execution.

## Map and request flow

[`src/lib.rs`](src/lib.rs) contains discovery, the client, loopback accept loop, and content-length
parser. The CLI serializes a command; the daemon's supplied handler turns the body into output,
returned as text and emitted through `Console`. Command parsing and allowed operations remain in the
CLI, not this transport.

## Client and server

- `connect_daemon(Option<&AppConfig>).await` probes the configured control port and returns
  `Option<ServerInfo>`. Reachability is not authenticated daemon identity.
- `run_on_daemon(out, server, command).await` POSTs a serializable command, propagates HTTP
  failures, and writes response lines to an `e3_console::Console`.
- `start_daemon_server(port, handler).await` binds `127.0.0.1` and passes each request body's string
  to an asynchronous handler returning `anyhow::Result<String>`.

The server accepts non-Send handlers and uses `spawn_local`: run it inside an Actix/local-task
context, not an ordinary multi-thread Tokio task alone. The CLI's
[socket setup](../cli/src/start.rs) demonstrates the complete local command handler; allowed remote
command conversions are in [cli.rs](../cli/src/cli.rs).

## Transport limits

There is no authentication or TLS. Keep the control socket local. Its manual HTTP parser supports
content-length framing, not arbitrary chunked requests, and is not a general-purpose HTTP server
with framework body/time limits. Handler errors become HTTP 500 responses.

Use [program-server](../program-server/README.md) for the separate computation-job HTTP API.

## Tests

`cargo check --locked -p e3-daemon-server --tests` checks its callback/transport types without a
live node. There are currently no dedicated crate test functions. The
[CLI startup handler](../cli/src/start.rs) is the integration point for exercising allowed commands
and output forwarding. See [AGENTS.md](AGENTS.md) for transport-change constraints.
