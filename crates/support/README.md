# OpenVM compute service

The support service runs the Secure Process and returns a verified OpenVM receipt. It runs on the
operator's machine. It does not require a proving-market account, payment wallet, or program upload.

The normal path is:

`CRISP server → POST /run_compute → OpenVM worker → HTTP callback → ciphertext publication`

The program server does not submit the publication transaction. CRISP verifies the callback,
publishes the ciphertext to its data-availability layer, and submits the resulting reference.
Both the protocol verifier and the application verifier must accept the compute proof.

## Components

- `app/`: the HTTP service, request admission, computation scheduling, and callback delivery.
- `host/`: native computation, worker execution, journal comparison, and proof-envelope encoding.
- `types/`: requests, callbacks, proof domains, guest inputs, and the nine-word journal.
- `program/`: the canonical CRISP processor and input policy, shared with the native host.
- `openvm/guest/`: the guest that proves the computation and reveals the journal digest.
- `openvm/prover/`: the separate worker that generates and verifies the EVM proof.

These are isolated Cargo workspaces. Use the root `pnpm openvm` commands to select them.

## Configure and start

Follow [the OpenVM build instructions](openvm/README.md) to prepare the worker, guest, proving
keys, verifier artifact, and worker configuration.

Set these deployment-local absolute paths in `interfold.config.yaml`:

```yaml
program:
  dev: false
  openvm:
    repository: ${OPENVM_REPOSITORY}
    prover_bin: ${OPENVM_PROVER_BIN}
    prover_config: ${OPENVM_PROVER_CONFIG}
```

Then run:

```sh
interfold program compile
interfold program start
```

`compile` builds the native HTTP service. It does not regenerate the guest or proving keys.
`start` validates the configured worker and artifacts before it accepts requests. Missing
configuration is an error. There is no automatic unproved fallback.

The CRISP reference guest uses CRISP's input policy. Another E3 program needs a host and guest
built against its own processor and policy. The contract, host, and guest must derive the same
input leaves, selected inputs, parameter hash, and journal.

## HTTP interface

The listener defaults to `127.0.0.1:13151`. Set `OPENVM_BIND_ADDR` to change it.

- `GET /health` and `HEAD /health` report service health.
- `POST /run_compute` accepts the existing program-server request. It contains the full E3 domain,
  BFV parameters, indexed ciphertexts, published commitments and metadata, and a callback URL.
- The immediate response acknowledges processing. It is not a proof or a publication receipt.

A successful callback contains `status: "completed"`, `e3_id`, `ciphertext`,
`ciphertext_commitment`, and `proof`. Binary fields use hexadecimal encoding.
A failed callback contains `status: "failed"`, `e3_id`, and `error`.

The proof envelope contains the seal, parameter hash, and input root. The seal contains the
Halo2 proof and all nine journal words. See [the receipt format](openvm/README.md#contract-migration).

The service admits one active computation by default. Jobs are in memory. A service restart can lose an
accepted job. Operators must reconcile interrupted jobs and failed callback delivery.
Use authenticated admission control and a deployment-specific callback policy. Do not expose
the unrestricted listener to the Internet.

## Container

From the repository root:

```sh
bash crates/support/scripts/build.sh
```

The container builds the native service, not the GPU worker. Mount the worker, its runtime
libraries, its configuration, and its proving artifacts. Provide GPU access for a CUDA worker.
Keep the service and worker on a compatible operating system. The CLI runs the configured local
service directly and does not pull a container image.

## Verification

```sh
pnpm openvm service-test
pnpm openvm contract-test
```

Use `pnpm openvm proof-test` for an externally supplied real proof.
Use `pnpm openvm service-e2e` for the live HTTP workflow on an isolated local chain.
[The OpenVM instructions](openvm/README.md#checks) list the required inputs and test boundaries.

An explicit `program.dev: true` selects an unproved development runner. That runner is not
OpenVM and cannot pass a real receipt verifier.
