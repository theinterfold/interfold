# e3-console

## Purpose

Injectable, cloneable command output for stdout, an asynchronous writer, or a captured channel. This
lets the same CLI command print locally or return its output through the daemon. Protocol and
structured operational logging belong in [e3-logger](../logger/README.md).

## Map and output lifecycle

[`src/lib.rs`](src/lib.rs) contains `Console`, `log!`, and `ConsoleHandle`. A cloneable sender feeds
either a caller-owned receiver or a Tokio writer task. Closing every sender lets that task drain;
the handle then joins it. No protocol actor or global tracing subscriber is involved.

## Capture command output

Inside an async Tokio context:

```rust
use e3_console::{log, Console};

let (out, mut messages) = Console::channel();
log!(out, "node {} ready", "cn1");
assert_eq!(messages.recv().await.unwrap(), "node cn1 ready");
```

`Console::stdout()` and `Console::writer(async_writer)` return a `ConsoleHandle`. Pass
`handle.writer()` to commands, drop every cloned `Console` when finished, then await
`handle.flush()` to drain the task. Holding another sender while awaiting flush prevents channel
closure and can wait indefinitely.

Writer mode adds one newline per message and flushes at closure. Channel mode returns message
strings without adding framing. Sends and writer failures are best-effort, and the queue is
unbounded: this is not acknowledged delivery or a backpressure mechanism.

## Tests

`cargo check --locked -p e3-console --tests` checks the crate and test-target compilation without
external services; it currently has no dedicated test functions. The channel example above is a
capture pattern for command tests. The [daemon](../daemon-server/README.md) and
[CLI](../cli/README.md) are concrete consumers. See [AGENTS.md](AGENTS.md) for framing and drain
constraints.
