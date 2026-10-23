# e3-program-runner

This library serves a project's processor and policy. The project's `runner/` binary supplies them;
the CLI owns project compile/start commands. [README.md](README.md) owns setup and modes.

- Preserve `with_published` and one caller-selected policy through computation and proving.
  Development mock envelopes remain ABI-compatible but are not cryptographic receipts.
- OpenVM must check its worker before accepting jobs and retain the full computation domain. Never
  fall back to dev mode after a proof, resource, or worker error.
- Keep HTTP body/concurrency/callback limits and explicit worker paths. This service adds neither
  authentication nor durable job admission; deployment must supply those boundaries.
- Keep server dependencies out of the project's guest by retaining the separate runner crate.
  `program_support.rs` owns CLI environment forwarding and rejects legacy `.interfold/support`.

Run `cargo test --locked -p e3-program-runner` with shared build prerequisites. Exercise changed
processor/policy plumbing in a generated project; real receipt changes need prepared service and
contract acceptance, not just the mock-envelope test.
