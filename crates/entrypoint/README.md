# Node operations and entrypoints

## Purpose

This crate turns CLI configuration into node startup and manages local multi-process nodes. Protocol
decisions remain in their domain crates; the ciphernode builder owns composition/startup
dependencies.

## Map

| Location                                                                                                                                | Responsibility                                                                                 |
| --------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------- |
| [`start/`](src/start)                                                                                                                   | Configured full/bootstrap startup and its deadline/ingestion expectations.                     |
| [`fence.rs`](src/fence.rs), [`store_record.rs`](src/store_record.rs)                                                                    | Process ownership lock and durable-store discovery records.                                    |
| [`nodes/`](src/nodes)                                                                                                                   | Managed-node clients/daemon, process supervision, and start/stop/status operations.            |
| [`nodes/purge/`](src/nodes/purge), [`nodes/state_guard.rs`](src/nodes/state_guard.rs), [`nodes/reset_data.rs`](src/nodes/reset_data.rs) | Destructive-operation facts/plans/effects, active-state guards, and identity-preserving reset. |
| [`validate.rs`](src/validate.rs)                                                                                                        | Offline schema, log, snapshot, and repair checks.                                              |
| [`actor_panics.rs`](src/actor_panics.rs)                                                                                                | First-panic signal for the thread running the node's actors.                                   |
| [`wallet/`](src/wallet), [`password/`](src/password), [`net/`](src/net)                                                                 | Local identity/password/peer operations delegated by CLI commands.                             |

The CLI resolves `AppConfig` and calls these library operations. Startup composes the node through
the builder; managed-node operations wrap child processes rather than creating a second protocol
runtime. Offline commands inspect state under the same ownership fences.

## Usage

Use [the CLI](../cli/README.md) for `interfold start`, `interfold nodes --help`, or
`interfold node validate --help`. Library callers use the exported operation modules in
[`lib.rs`](src/lib.rs); [`start/start.rs`](src/start/start.rs) is the configured builder recipe. Do
not invoke reset/purge on a populated directory merely to try the API: those commands are
destructive and can refuse active keyshare or pending slash state.

## Process and state ownership

Start acquires the process fence and opens/decrypts the intended identity before constructing the
node. Bootstrap and full roles cannot reuse one populated directory: their reader sets share chain
cursors. [Persistence](../../docs/architecture/persistence-and-replay.md) owns role/schema
admission, and
[upgrades](../../docs/architecture/upgrades.md#controlled-state-reset-never-directory-deletion) owns
identity-preserving reset and the limits of purge/store discovery.

`node validate` is read-only by default. Repair is limited to verified uncommitted tails and derived
membership/history mismatches, not indexed corruption, unknown schemas, or recovery of lost secrets.

Managed children receive SIGTERM first and may use the node shutdown deadline plus five seconds
(currently 65 seconds), then SIGKILL. Output forwarding drains for up to five more seconds before
abort. Child handles use kill-on-drop; partial-start failure cleans children already started, and
cleanup failure yields a nonzero supervisor exit. Exited state is restartable by an operator action,
not reported as Started. There is no persisted desired-state or automatic unexpected-exit restart
policy. Detached daemon launch outlives its CLI launcher; managed-child containment is different.

The CLI installs `ActorPanics::watch()` before actors start. It records the first panic on that
thread; the CLI uses the normal shutdown barrier and exits unsuccessfully after receiving it. Panics
on other threads remain with their owners, and library callers do not acquire this monitoring
automatically.

## Tests

Use `cargo test --locked -p e3-entrypoint` with the
[shared prerequisites](../test-helpers/README.md); schema/startup tests may need Foundry/Anvil.
Inline tests cover fencing, child cleanup, validation, and identity setup. The [`tests/`](tests)
targets exercise purge/reset guards and old/corrupt snapshot/schema cases. The integration suite
owns multi-process restart/shutdown scenarios. Supervisor cleanup tests do not prove all detached
application tasks have drained. [`actor_panic_stop.rs`](tests/actor_panic_stop.rs) checks the
actor-thread filter and panic signal, not the CLI's full shutdown/exit path. The CLI owns production
monitoring. See [AGENTS.md](AGENTS.md) for safety-boundary change rules.
