# Diagnostics

Passive operational observation of a running node shares this family: bounded logging and a
read-only operator dashboard. Each member remains an independently importable package in the root
Cargo workspace; this directory is not a package or nested workspace.

- [logger](logger/README.md) (package `e3-logger`) summarizes protocol events from the bus, captures
  structured tracing with field-name redaction, and retains bounded, cursor-ordered entries with
  optional rotating JSONL output.
- [dashboard](dashboard/README.md) (package `e3-dashboard`) serves a loopback-only, unauthenticated
  web UI and JSON API that project durable event history, network status, cached operator status,
  and the logger's retained entries.

## Observation boundary

Members observe; they never decide, publish, or replay protocol effects, and their failures must not
acquire protocol authority or reorder events. Two histories stay distinct:

- **Durable event history** is the EventStore, assembled by
  [event-system](../state/event-system/README.md) and governed by
  [persistence and replay](../../docs/architecture/persistence-and-replay.md). The dashboard reads
  it through per-aggregate sequence cursors.
- **Diagnostic entries** are the logger collector's sequence numbers. The queried view is in memory
  and bounded, and the optional JSONL file rotates, so they are neither a replay log nor a delivery
  guarantee.

Redaction is field-name based and cannot make arbitrary message text safe; the dashboard's API
exposes detailed operational data and must stay on loopback until it has access control.

Command output stays in [console](../console/README.md). The
[local daemon](../ciphernode/daemon-server/README.md) transports CLI commands to a running node, and
the [CLI](../cli/README.md) executes them and wires telemetry. The dashboard's browser UI source is
the [node dashboard package](../../packages/interfold-node/README.md), which builds into
`dashboard/assets/`.

Checkout-relative paths for this family's members start with `crates/diagnostics/`. Use the
[workspace setup](../README.md#setup-and-checks), the [debugging guide](../README.md#debugging), and
each member's checks.
