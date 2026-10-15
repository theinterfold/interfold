# e3-support-scripts-openvm

This excluded template wires the project's processor/policy into the HTTP service and native OpenVM
host. It runs in the consuming project's workspace, not the root Rust workspace.

- Preserve the full request computation domain when constructing `ComputeDomain`; omitting fields
  weakens the journal's replay binding even when native ciphertext computation still succeeds.
- Start/check the prover before accepting jobs. Backend selection and timeouts belong to
  `WorkerConfig`; the service must not replace failed proofs with development output.
- The user-program relative path is intentionally project-layout dependent. Change the template,
  then exercise a copied/linked project instead of rewriting it for root `cargo -p` convenience.
- Preserve explicit request/concurrency/body limits and loopback defaults. The HTTP boundary has no
  authentication or durable queue; a real runner does not add those properties.

Use root `pnpm openvm service-check` for the linked CRISP project, or
`cargo check -p e3-support-scripts-openvm` in a prepared generated project. Real startup/proving
needs pinned OpenVM tooling, prepared worker configuration, and keys from the
[OpenVM README](../../../openvm-prover/README.md); the first project build may refresh its lockfile.
