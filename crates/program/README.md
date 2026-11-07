# Program

Application execution shares this family: the E3 program's Secure Process, its host/guest framing
for OpenVM proving, the worker that proves the guest, and the service that runs a project's program.
Each member except the OpenVM worker remains an independently importable package in the root Cargo
workspace; this directory is not a package or nested workspace. Folder names drop the repeated
"program", so `server` and `runner` differ from their package names.

- [compute-provider](compute-provider/Readme.md) (package `e3-compute-provider`): the streaming
  two-pass Secure Process, input policies, input-root construction, and result commitments, shared
  by the native host and the guest.
- [openvm-types](openvm-types/README.md) (package `e3-openvm-types`): the guest input stream and the
  public `ComputeJournal`, whose ABI words a Solidity verifier checks.
- [openvm-host](openvm-host/README.md) (package `e3-openvm-host`): computes the expected journal
  natively and requires a separate OpenVM worker to prove and verify it.
- [openvm-prover](openvm-prover/README.md) (package `interfold-openvm-prover`): that worker, a CPU
  or CUDA process that proves the project guest and verifies the proof against the journal.
- [server](server/README.md) (package `e3-program-server`): the HTTP boundary (`/run_compute`,
  `/health`) with bounded admission and webhook delivery.
- [runner](runner/README.md) (package `e3-program-runner`): the `dev` and `openvm` modes that a
  generated project's `runner/` binary calls with its own processor and policy.

## Boundaries

These crates run a project's computation over published ciphertexts. They are not the ciphernode's
ZK and TrBFV scheduling: no ciphernode crate depends on them. The application's own server posts
jobs to the program service, so the application, not the node operator, deploys and secures it.

The OpenVM worker is an excluded Cargo workspace with its own pinned SDK. A generated project's
`program/` and `runner/` share its root workspace, and `guest/` is a workspace of its own, so the
guest never links the HTTP or worker dependencies. The template reaches these crates by
checkout-relative path, and `interfold init` pins them to the release's git revision through the
[initializer](../init/README.md)'s folder list, which must name every checkout-relative dependency
of the template. The worker is the exception: no template manifest depends on it, so
`interfold init` does not pin it. A project runs the separately built binary that
`program.openvm.prover_bin` or `prover_bin_cuda` names.

The guest's executable commitment (`appExeCommit`) is not independent of where it was built. OpenVM
v2.0.2 does not remap source paths, so the executable embeds the absolute paths of the checkout and
of `CARGO_HOME`. Moving a member therefore changes the template guest's commitment, as does building
from another directory. Compare commitments only between builds from the same paths; the
[compute-provider verification guide](../../docs/pages/build/e3-program/verify-compute-provider.mdx)
describes the rebuild.

Host/guest parity, journal binding, and the contract checks are in
[encrypted computation](../../docs/architecture/encrypted-computation.md). A new guest or journal
layout is a new verifier deployment; follow the
[upgrade decision](../../docs/architecture/upgrades.md) first.

Checkout-relative paths for this family's members start with `crates/program/`. Use the
[workspace setup](../README.md#setup-and-checks) and each member's checks.
