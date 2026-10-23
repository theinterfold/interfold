# OpenVM repository tasks

## Purpose

`pnpm openvm <task> [arguments]` dispatches cross-workspace CLI, prover and service tasks,
forwarding arguments and exit status. Run without a task for the task list. Projects created with
`interfold init` use `interfold program compile` and `interfold program start` instead. The
[CRISP repository](https://github.com/theinterfold/CRISP) owns its guest, program runner and
scenarios.

## Map

- [`run.sh`](run.sh): dispatches commands to the appropriate Rust workspace.
- [`run.test.mjs`](run.test.mjs): tests arguments, target-directory overrides, and exit propagation.
- [`provenance.ts`](provenance.ts): records artifact, worker, and deployed receipt identity.

## Setup and usage

Follow the [OpenVM worker setup](../../crates/openvm-prover/README.md) for pinned tooling and
artifacts. For example, `pnpm openvm prover-check` checks the independent worker workspace, while
`pnpm openvm service-test` tests the root workspace's service crates. The root Node dependencies are
required for provenance's contract/RPC helpers.

## Guest provenance

`pnpm provenance:manifest --project <checkout>` records the source commit, lockfile digests, guest
configuration, proving artifacts, KZG parameters, and application commitments. `--project` is
required: it names the project checkout whose guest the worker configuration describes. With
`--prover`, it checks the worker's configured identity. With an RPC, it checks protocol-to-receipt
binding, application commitments, and deployed Halo2 runtime against the checked artifact, without
sending transactions.

```sh
pnpm provenance:manifest --project <project-checkout>
pnpm provenance:manifest --project <project-checkout> --config <worker.json> --prover <worker-binary> --rpc <url> --verifier <protocol-verifier-address> --out manifest.json
```

Missing fields produce `"complete": false`; a release manifest must be complete. Artifact digests,
application commitments, and receipt identity establish different bindings, not source
reproducibility or audit coverage. Follow the full
[verification procedure](../../docs/pages/build/e3-program/verify-compute-provider.mdx).

## Tests

`pnpm test:scripts` checks dispatch and argument/exit-status forwarding without compiling a guest.
`pnpm openvm prover-test` and `pnpm openvm service-test` run the worker and service crate tests.

**Gap:** no Interfold CI job runs the accelerated OpenVM guest paths (`e3-safe/openvm`,
`openvm-hashes`, `crisp_fhe_optimized`); the `openvm_guest` job only builds the template guest. Only
the CRISP repository's CI runs the real guest against the host journal, after CRISP pins a published
Interfold release. A guest/host journal parity regression on `main` can therefore ship.
