# e3-logger

## Purpose

Bounded operational diagnostics. Durable protocol history stays in the node's journal; this logger
does not provide replay or acknowledged event delivery.

## Map

| Location                                   | Responsibility                                                                         |
| ------------------------------------------ | -------------------------------------------------------------------------------------- |
| [`tracing_layer.rs`](src/tracing_layer.rs) | Structured event/span capture, field-name redaction, and telemetry metadata filtering. |
| [`log_collector.rs`](src/log_collector.rs) | Bounded cursor-ordered entries and rotating JSONL output.                              |

Operational tracing records flow through the subscriber layer into the collector. File output is a
diagnostic sink alongside the collector's in-memory view.

## Attach logging

For operational `tracing` output, initialize `LogCollector::init(node_name, optional_jsonl_path)`
and add `OperationalLogLayer` to the application's tracing subscriber. The CLI's
[telemetry setup](../../cli/src/helpers/telemetry.rs) demonstrates subscriber/OpenTelemetry wiring.

The collector is process-global and keeps the first initialization. It retains up to 20,000 entries
in memory; optional JSONL output rotates at 25 MiB with four rotated files. `LogCollector::global()`
retrieves the initialized instance and `flush()` flushes its writer. Failure to open the diagnostic
file does not create protocol authority.

## Query and privacy

`query(since, limit, level, target, text)` returns `LogQueryResult` with entries, next/oldest
cursors, and total retained count. Cursors are collector sequence numbers, not durable event
sequences; older entries may have been evicted.

Field-name-based redaction filters sensitive fields and inherited spans. OpenTelemetry has its own
metadata filter; one sibling tracing layer cannot sanitize another layer's output. Neither filter
can make arbitrary secret text in a message safe. Do not log raw secrets, plaintext, credentials, or
entire cryptographic payloads.

For CLI verbosity and collector endpoints see the
[workspace debugging guide](../../README.md#debugging).

## Tests

Run `cargo test --locked -p e3-logger`. Inline tests cover inherited span fields and redaction,
bounded retention, and filter/cursor queries. No node, collector service, or chain is required. CLI
telemetry tests cover the composed tracing subscriber separately. See [AGENTS.md](AGENTS.md) for
passive-observation/privacy change rules.
