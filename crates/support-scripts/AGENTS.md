# e3-support-scripts

This crate dispatches project compile/start scripts; the child runner packages are project
templates, not root workspace members. Their nearest instructions describe project-context checks.

- Resolve scripts from the consuming project's `.interfold/support` directory. Running the library
  in this repository is not equivalent to running a generated project with its user program.
- OpenVM is the default; unproved development mode requires an explicit flag/configuration. Validate
  removed backend settings before dispatch instead of silently migrating execution mode.
- Keep worker paths absolute and forward the selected backend/setup environment to both compile and
  start. Receipt identity, worker configuration, and deployment consumers must share one path.
- Update source templates here, not copied project caches. `interfold init` rewrites dependencies;
  copied projects may need a first unlocked build to refresh their lockfile's sources.
- Cache purge removes the project's `.interfold/caches`; it must not broaden into support sources or
  operator identity/state directories.

Run `cargo test --locked -p e3-support-scripts` for backend dispatch. Script integration needs a
disposable generated project and the [OpenVM prerequisites](../openvm-prover/README.md); host unit
tests do not compile a guest, prepare keys, or prove a round.
