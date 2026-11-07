# e3-entrypoint

This crate owns the operations around a node's processes and their safety checks. The node's
protocol and state live in [e3-node](../node/) and its crates; the CLI owns validation, reset, and
purge.

- Acquire and retain the process fence before opening state. Lock-file contents are diagnostics, not
  proof of ownership; dropping the guard releases the actual advisory lock.
- Managed children get SIGTERM, then SIGKILL after the grace period. Keep kill-on-drop and
  partial-start cleanup.

Use the [README tests](README.md#tests). Use temporary node directories for fence regressions; never
use an operator's populated state as a fixture.
