# OpenVM proving

OpenVM replaces RISC Zero and Boundless. Each project proves its own E3 program: the guest and the
proving service link the project's `program/` crate, so the guest, the native host and the contract
use one processor and one input policy. This is a new guest and verifier deployment, not an upgrade
of an existing receipt. Existing deployment records and legacy RISC Zero contracts stay unchanged.

## Pieces

| Piece                                  | What it is                                                                 |
| -------------------------------------- | -------------------------------------------------------------------------- |
| `guest/` in the project                | The OpenVM guest. Its own workspace, built with `cargo openvm`             |
| `.interfold/support/openvm/service`    | The proving service: `e3-program-server` with `e3-openvm-host` as runner   |
| `.interfold/support/openvm/compile`    | Builds the guest, keys, receipt identity, worker configuration and service |
| `.interfold/support/openvm/start`      | Starts the service                                                         |
| `interfold-openvm-prover` (this crate) | The worker. A separate process, in a CPU build and a CUDA build            |

`interfold init` copies the service folder and pins the guest's Interfold crates to the template's
commit. In this repository, `templates/default` and `examples/CRISP` link the folder from
`crates/support-scripts/openvm`.

The guest reads the round one item at a time: a header, every ciphertext in index order, then the
ciphertexts the policy selected, again in index order. It keeps a hash of each ciphertext from the
first pass and refuses a second-pass ciphertext that differs. Only one ciphertext is in guest memory
at a time, so the guest's 512 MiB does not bound the round. The worker holds the whole input stream
twice, about eight times the round's binary size, and the request body limit applies to the
hex-encoded round.

## Prerequisites

- Rust 1.91.1, and `cargo-openvm` v2.0.2 with its guest toolchain:
  `cargo install --locked --git https://github.com/openvm-org/openvm.git --tag v2.0.2 cargo-openvm`.
- The Halo2 proving key, KZG parameters and EVM verifier from `cargo openvm setup`, in `~/.openvm`
  by default. Verify their provenance and checksums before use.
- For a GPU: the CUDA toolkit and driver, and `nvcc` on `PATH` when building the CUDA worker.

## Build the workers

From the repository root:

```sh
pnpm openvm prover-build                    # CPU: target/openvm/prover/release/interfold-openvm-prover
CARGO_TARGET_DIR=target/openvm/prover-cuda \
  pnpm openvm prover-build --features cuda  # CUDA build, in its own target directory
```

The CUDA build links the CUDA runtime dynamically, so it starts only where the CUDA libraries are
installed, and it stops at startup when it cannot open a GPU. Keep the two builds apart; a project
may configure both. On a machine without a GPU, configure the CPU worker: `compile` runs `prepare`
with it.

## Configure the project

In `interfold.config.yaml`, with absolute paths local to the machine:

```yaml
program:
  dev: false
  openvm:
    prover_bin: /opt/openvm/interfold-openvm-prover # the CPU worker
    prover_bin_cuda: /opt/openvm/interfold-openvm-prover-cuda # optional
    backend: auto # auto, cpu or cuda
    # setup_dir: /home/me/.openvm         # what `cargo openvm setup` wrote
```

With `backend: auto` the service runs the CUDA worker's `probe` at startup. When that opens a GPU,
the CUDA worker proves; when there is no CUDA worker, no GPU, or no driver, the CPU worker proves
and the service logs why. `backend: cuda` refuses to start without a working GPU, and `backend: cpu`
never tries one.

## Compile, deploy and start

```sh
interfold program compile
```

This builds `guest/`, generates its application key, runs the worker's `prepare` for the aggregation
key and receipt identity, writes the worker configuration (`OPENVM_PROVER_CONFIG`, or
`.interfold/caches/openvm/prover.json`), and builds the service. `start` and the deploys read the
same path. The keys are regenerated only when the guest executable or `guest/openvm.toml` changes.
The receipt identity is in `.interfold/caches/openvm/prepared/identity.json`.

Deploy the contracts next. The template and CRISP deploys read the identity and verifier artifact
from that `prover.json` unless `OPENVM_APP_EXE_COMMIT`, `OPENVM_APP_VM_COMMIT`, and either
`OPENVM_VERIFIER_ARTIFACT` with `OPENVM_VERIFIER_SHA256` or `OPENVM_HALO2_VERIFIER` with
`OPENVM_HALO2_RUNTIME_CODE_HASH` are set. A rebuilt guest has a new identity and needs a new
verifier.

```sh
interfold program start
```

The service picks its worker, then runs the worker's `check`. That loads the application,
aggregation and Halo2 keys and both KZG parameter files, verifies the verifier artifact's digest,
and recomputes the identity from the executable, before any request is accepted.

## Worker commands

| Command                                                                       | Purpose                                            |
| ----------------------------------------------------------------------------- | -------------------------------------------------- |
| `prepare <app.pk> <guest.vmexe> <new-dir>`                                    | Aggregation key and `identity.json`                |
| `write-config <out.json> <app.pk> <guest.vmexe> <prepared> <setup> <segment>` | The configuration below                            |
| `probe`                                                                       | Succeeds only for a CUDA build with a GPU          |
| `check <config.json>`                                                         | Loads and checks every artifact                    |
| `execute <config.json> <input> <journal>`                                     | Runs the guest without proving; checks the journal |
| `prove <config.json> <input> <journal> <new-seal>`                            | Proves and verifies one round                      |
| `verify <config.json> <proof.json> <journal> <new-seal>`                      | Verifies an existing proof                         |

`prove` reads the guest input items the host wrote, proves the application, aggregates it, generates
the Halo2 EVM proof, and verifies it with the configured EVM verifier against the expected journal
and both application commitments before it writes a seal. There is no fake-proof mode.

| Configuration field    | Value                                                          |
| ---------------------- | -------------------------------------------------------------- |
| `app_pk`               | The guest application proving key                              |
| `executable`           | The guest VM executable                                        |
| `aggregation_pk`       | The aggregation key from `prepare`                             |
| `halo2_pk`             | The Halo2 proving key                                          |
| `halo2_params_dir`     | The KZG parameter directory                                    |
| `verifier_artifact`    | The EVM verifier bytecode JSON                                 |
| `verifier_sha256`      | Its SHA-256 digest, lowercase hexadecimal                      |
| `app_commit`           | The `app_commit` object from `identity.json`                   |
| `segment_memory_bytes` | The proving segment memory limit (`compile` defaults to 8 GiB) |

## Service settings

| Variable                      | Default           | Meaning                                       |
| ----------------------------- | ----------------- | --------------------------------------------- |
| `OPENVM_BIND_ADDR`            | `127.0.0.1:13151` | Listener                                      |
| `OPENVM_MAX_REQUEST_BYTES`    | 128 MiB           | Largest `/run_compute` body                   |
| `OPENVM_BODY_TIMEOUT_SECS`    | 120               | Time an admitted request has to send its body |
| `MAX_CONCURRENT_COMPUTATIONS` | 1                 | Rounds proved at once                         |
| `OPENVM_CHECK_TIMEOUT_SECS`   | 1800              | Deadline for the startup `check`              |
| `OPENVM_PROVE_TIMEOUT_SECS`   | 86400             | Deadline for one proof; the worker is stopped |

A request is admitted before its body is read, and a request beyond capacity gets 429. Jobs are in
memory: a restart loses accepted jobs, and operators must reconcile them. Callbacks are retried with
backoff on server errors, timeouts and rate limits. Run the service behind authenticated admission
control, and do not expose it to the Internet.

`POST /run_compute` and the callback formats are those of the development runner. The proof envelope
is `abi.encode(bytes seal, bytes32 paramsHash, bytes32 inputRoot)`.

## Receipt format

The guest reveals SHA-256 of nine consecutive 32-byte ABI words:

1. Chain ID
2. Interfold address
3. Full uint256 E3 ID
4. Encryption scheme ID
5. Committee public-key hash
6. Ciphertext output hash
7. SAFE ciphertext commitment
8. Parameter hash
9. Input root

The seal is `abi.encode(uint8(1), bytes(halo2ProofData))`, 1,856 bytes. It does not repeat the
journal: the proof's only public value is the journal digest, which the contracts recompute.

The receipt identity binds the Halo2 verifier address, the executable commitment and the VM
commitment. The protocol BFV verifier and the program's verifier must use the same identity, and
both verification calls stay mandatory. Rounds keep their request-time verifier snapshot and must
drain before a live migration. The historical RISC Zero activation scripts do not activate OpenVM.
The compute path is unaudited.

## CRISP checks

From the repository root:

```sh
pnpm openvm service-test   # host, types, Secure Process and program server
pnpm openvm contract-test  # receipt and journal contracts
```

`pnpm openvm proof-test` verifies an externally supplied proof on an in-memory chain. It needs
`OPENVM_TEST_IDENTITY`, `OPENVM_TEST_JOURNAL`, `OPENVM_TEST_VERIFIER`,
`OPENVM_TEST_VERIFIER_SHA256`, and `OPENVM_TEST_PROOF` (proof JSON) or `OPENVM_TEST_SEAL` (worker
seal).

`pnpm openvm service-e2e` runs a live round: CRISP input submission and indexing, the running OpenVM
service, the callback, and ciphertext publication. It needs an isolated loopback RPC with chain ID
31337 (use Anvil for long rounds) and a running service started with `pnpm openvm service-start`
after `pnpm openvm compile`. Build the CRISP server with `pnpm openvm crisp-server-build --release`
and generate secure-8192 ballots with `pnpm openvm fixture <count> <new-directory>`. Set:

| Variable                      | Meaning                                                    |
| ----------------------------- | ---------------------------------------------------------- |
| `LOCAL_RPC_URL`               | Isolated loopback EVM RPC                                  |
| `OPENVM_E2E_FIXTURE`          | Directory the fixture command wrote                        |
| `OPENVM_E2E_SERVER`           | Absolute path to the CRISP server binary                   |
| `OPENVM_E2E_OUTPUT`           | New directory for the report and logs                      |
| `OPENVM_E2E_PROGRAM_URL`      | The running service, reachable from CRISP                  |
| `OPENVM_E2E_CALLBACK_URL`     | CRISP URL reachable from the service                       |
| `OPENVM_E2E_LOCAL_SERVER_URL` | Local CRISP listener; defaults to `http://127.0.0.1:14000` |
| `OPENVM_TEST_IDENTITY`        | The `identity.json` the worker was prepared with           |
| `OPENVM_TEST_VERIFIER`        | The verifier bytecode JSON the worker uses                 |
| `OPENVM_TEST_VERIFIER_SHA256` | Its SHA-256 digest                                         |

The test deploys real OpenVM receipt and protocol verifiers, rejects a changed proof, and checks the
tally and settlement. Randomness, DKG proofs, ballot proofs and census, data availability, and
threshold-decryption proofs are local mocks, so it is a real compute-proof test, not a fully
cryptographic E3 round. Keep reports, inputs, keys and proofs out of the repository.
