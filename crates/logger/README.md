# e3-logger

## Purpose

Passive protocol summaries and bounded operational diagnostics. Durable protocol history stays in
the EventStore; this logger does not provide replay or acknowledged event delivery.

## Map

| Location                                   | Responsibility                                                                         |
| ------------------------------------------ | -------------------------------------------------------------------------------------- |
| [`logger.rs`](src/logger.rs)               | Passive event subscriber and protocol-specific summary formatting.                     |
| [`tracing_layer.rs`](src/tracing_layer.rs) | Structured event/span capture, field-name redaction, and telemetry metadata filtering. |
| [`log_collector.rs`](src/log_collector.rs) | Bounded cursor-ordered entries and rotating JSONL output.                              |

Protocol events are observed from the bus; operational tracing records flow through the subscriber
layer into the collector. Dashboard queries read retained collector entries, not the journal. File
output is a diagnostic sink alongside that in-memory view.

## Attach logging

`attach_protocol_logger(name, bus)` subscribes a `SimpleLogger<InterfoldEvent>` to summarize
protocol events. `EventLogging` supports other event types. For operational `tracing` output,
initialize `LogCollector::init(node_name, optional_jsonl_path)` and add `OperationalLogLayer` to the
application's tracing subscriber. The CLI's [telemetry setup](../cli/src/helpers/telemetry.rs)
demonstrates subscriber/OpenTelemetry wiring.

The collector is process-global and keeps the first initialization. It retains up to 20,000 entries
in memory; optional JSONL output rotates at 25 MiB with four rotated files. `LogCollector::global()`
retrieves the initialized instance and `flush()` flushes its writer. Failure to open the diagnostic
file does not create protocol authority or replace the event log.

## Query and privacy

`query(since, limit, level, target, text)` returns `LogQueryResult` with entries, next/oldest
cursors, and total retained count. Cursors are collector sequence numbers, not durable event
sequences; older entries may have been evicted. The [dashboard](../dashboard/README.md) exposes this
via `/api/logs` separately from its EventStore-backed protocol view.

Field-name-based redaction filters sensitive fields and inherited spans. OpenTelemetry has its own
metadata filter; one sibling tracing layer cannot sanitize another layer's output. Neither filter
can make arbitrary secret text in a message safe. Do not log raw secrets, plaintext, credentials, or
entire cryptographic payloads.

For CLI verbosity and collector endpoints see the
[workspace debugging guide](../README.md#debugging).

## Tests

Run `cargo test --locked -p e3-logger`. Inline tests cover protocol summary/severity formatting,
inherited span fields and redaction, bounded retention, and filter/cursor queries. No node,
collector service, or chain is required. CLI telemetry tests cover the composed tracing subscriber
separately. See [AGENTS.md](AGENTS.md) for passive-observation/privacy change rules.
