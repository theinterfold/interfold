# Node operations and entrypoints

## Purpose

The operations the CLI runs around a node's processes: the process fence, the node password, and the
`interfold nodes` manager for local multi-node setups. The node itself is [e3-node](../node/); the
CLI owns validation, reset, and purge of its state.

## Map

| Location                    | Responsibility                                                                      |
| --------------------------- | ----------------------------------------------------------------------------------- |
| [`fence.rs`](src/fence.rs)  | Process ownership lock.                                                             |
| [`nodes/`](src/nodes)       | Managed-node clients/daemon, process supervision, and start/stop/status operations. |
| [`password/`](src/password) | Setting and deleting the node password.                                             |

## Usage

Use [the CLI](../../cli/README.md) for `interfold start` and `interfold nodes --help`.

## Process and state ownership

`interfold start` acquires the process fence before it opens the node's state.

Managed children receive SIGTERM first and get 65 seconds to stop, then SIGKILL. Output forwarding
drains for up to five more seconds before abort. Child handles use kill-on-drop; partial-start
failure cleans children already started, and cleanup failure yields a nonzero supervisor exit.
Exited state is restartable by an operator action, not reported as Started. There is no persisted
desired-state or automatic unexpected-exit restart policy. Detached daemon launch outlives its CLI
launcher; managed-child containment is different.

## Tests

Run `cargo test --locked -p e3-entrypoint`. Inline tests cover fencing and child cleanup. The
[integration scenario](../../../tests/integration/README.md) owns multi-process restart and
shutdown. Supervisor cleanup tests do not prove all detached application tasks have drained. See
[AGENTS.md](AGENTS.md) for safety-boundary change rules.
