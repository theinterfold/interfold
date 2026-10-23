# e3-program-runner

## Purpose

Serves a project's E3 processor and input policy through an unproved development mode or the OpenVM
proving service. A separate project runner keeps HTTP/server dependencies out of its guest.

## Map

| Location                                             | Responsibility                                                  |
| ---------------------------------------------------- | --------------------------------------------------------------- |
| [lib.rs](src/lib.rs)                                 | `run`, argument validation, and runtime/mode dispatch.          |
| [dev.rs](src/dev.rs)                                 | Native computation with a mock-proof envelope.                  |
| [openvm.rs](src/openvm.rs)                           | Worker-verified OpenVM computation through the HTTP server.     |
| [CLI program support](../cli/src/program_support.rs) | Project compile/start, environment forwarding, and cache purge. |

## Project integration

The project's `runner/` crate links its own `program/` and calls:

```rust
fn main() -> anyhow::Result<()> {
    e3_program_runner::run(e3_user_program::fhe_processor, e3_user_program::policy())
}
```

Use [the template runner](../../templates/default/runner) or
[CRISP's runner](https://github.com/theinterfold/CRISP/tree/main/runner) as the complete Cargo
recipe. The binary accepts `dev` or `openvm`; a missing, unknown, or non-UTF-8 mode is a usage
error. Both modes preserve the project's policy and published metadata.

From a generated project root, `interfold program compile --dev` builds `program-runner`, and
`interfold program start --dev` runs its development mode. Without `--dev`, configuration selects
the mode; OpenVM is the default. OpenVM compilation builds the guest, keys, receipt identity, worker
configuration, and runner through the CLI's embedded
[compile script](../cli/scripts/openvm-compile.sh). OpenVM start runs the release-profile runner.

Worker/setup paths in `program.openvm` must be absolute. The CLI forwards them as `OPENVM_*`
environment variables and defaults `OPENVM_PROVER_CONFIG` to the project's
`.interfold/caches/openvm/prover.json`. The service checks its worker before accepting jobs.

## Compatibility and limits

Projects using `.interfold/support` must remove that directory and its Cargo workspace members, then
add the template's `runner/` crate. The CLI refuses the legacy layout rather than executing cached
scripts. A new project's first Cargo build can update its rewritten Git dependency lockfile.

Development output is explicitly unproved; it is not a fallback for failed OpenVM work. Neither mode
adds authentication or durable job admission to [e3-program-server](../program-server/README.md).
See [encrypted computation](../../docs/architecture/encrypted-computation.md) for receipt identity,
policy, and input-root contracts.

## Tests

Run `cargo test --locked -p e3-program-runner` after the
[shared prerequisites](../test-helpers/README.md). Inline tests cover mode admission and
mock-envelope encoding. CLI dispatch tests live in `e3-cli`; generated-project and real OpenVM
service/contract checks exercise different boundaries. [AGENTS.md](AGENTS.md) describes editing
hazards.
