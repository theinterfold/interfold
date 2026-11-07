# Diagnostics

Passive operational observation of a running node lives in this family. Each member remains an
independently importable package in the root Cargo workspace; this directory is not a package or
nested workspace.

- [logger](logger/README.md) (package `e3-logger`) captures structured tracing with field-name
  redaction and retains bounded, cursor-ordered entries with optional rotating JSONL output.

## Observation boundary

Members observe; they never decide, publish, or replay protocol effects, and their failures must not
acquire protocol authority or reorder events. The node's durable history is its
[journal](../state/journal/). Diagnostic entries are the logger collector's sequence numbers: the
queried view is in memory and bounded, and the optional JSONL file rotates, so they are neither a
replay log nor a delivery guarantee.

Redaction is field-name based and cannot make arbitrary message text safe.

Command output stays in [console](../console/README.md). The
[local daemon](../ciphernode/daemon-server/README.md) transports CLI commands to a running node, and
the [CLI](../cli/README.md) executes them and wires telemetry.

Checkout-relative paths for this family's members start with `crates/diagnostics/`. Use the
[workspace setup](../README.md#setup-and-checks), the [debugging guide](../README.md#debugging), and
each member's checks.
