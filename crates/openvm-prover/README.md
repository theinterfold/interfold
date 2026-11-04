# OpenVM proving

## Purpose

OpenVM replaces RISC Zero and Boundless. Each project proves its own E3 program: the guest and the
project's `runner/` link the project's `program/` crate, so the guest, the native host and the
contract use one processor and one input policy. This is a new guest and verifier deployment, not an
upgrade of an existing receipt. Existing deployment records and legacy RISC Zero contracts stay
unchanged.

## Source map

This worker is an excluded, independent Cargo workspace. [`src/main.rs`](src/main.rs) owns command
parsing plus bounded artifact/input loading, SDK construction, native guest execution,
proving/verification, and seal encoding. [`stages.rs`](src/stages.rs) owns staged proving and native
proof admission; [`checkpoint.rs`](src/checkpoint.rs) owns local checkpoint files and manifests.
`Config` binds artifact paths/checksums and application identity; `verify` checks the expected
journal; `read_items` adapts the shared stream into OpenVM stdin. [`Cargo.toml`](Cargo.toml) pins
this worker's SDK/features independently of the runtime workspace; use the Rust/OpenVM toolchains
listed under prerequisites below.

The host starts a checked CPU/CUDA worker per operation. The worker executes/proves the project
guest, aggregates into an EVM proof, verifies it against the supplied journal/commitments, then
writes the seal. The following map shows how this process fits the consuming project.

## Pieces

| Piece                                  | What it is                                                                                            |
| -------------------------------------- | ----------------------------------------------------------------------------------------------------- |
| `guest/` in the project                | The OpenVM guest. Its own workspace, built with `cargo openvm`                                        |
| `runner/` in the project               | The `program-runner` binary. `program-runner openvm` is the proving service (`crates/program-runner`) |
| `interfold-openvm-prover` (this crate) | The worker. A separate process, in a CPU build and a CUDA build                                       |

The proving service is `e3-program-server` with `e3-openvm-host` as runner. `interfold init` pins
the guest's Interfold crates to the template's commit. `interfold program compile` runs
`crates/cli/scripts/openvm-compile.sh`, which builds the guest, keys, receipt identity, worker
configuration and `program-runner`. `interfold program start` runs `program-runner openvm` with
`cargo run --release`. In this repository, `templates/default` has a `runner/` crate that calls
`e3_program_runner::run`.

The guest reads the round one item at a time: a header, every ciphertext in index order, then the
ciphertexts the policy selected, again in index order. It keeps a hash of each ciphertext from the
first pass and refuses a second-pass ciphertext that differs. Only one ciphertext is in guest memory
at a time, so the guest's 512 MiB does not bound the round. The worker holds the whole input stream
twice, about eight times the round's binary size, and the request body limit applies to the
hex-encoded round.

## Prerequisites

- Rust 1.91.1, and `cargo-openvm` v2.0.2 with its guest toolchain:
  `cargo install --locked --git https://github.com/openvm-org/openvm.git --tag v2.0.2 cargo-openvm`.
- The Halo2 proving key, KZG parameters and EVM verifier from `cargo openvm setup --evm`, in
  `~/.openvm` by default. Verify their provenance and checksums before use.
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
    # setup_dir: /home/me/.openvm         # what `cargo openvm setup --evm` wrote
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
`.interfold/caches/openvm/prover.json`), and builds `program-runner`. `start` and the deploys read
the same path. The keys are regenerated only when the guest executable or `guest/openvm.toml`
changes. The receipt identity is in `.interfold/caches/openvm/prepared/identity.json`.

Deploy the contracts next. The template deploy reads the identity and verifier artifact from that
`prover.json` unless `OPENVM_APP_EXE_COMMIT`, `OPENVM_APP_VM_COMMIT`, and either
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

| Command                                                                       | Purpose                                               |
| ----------------------------------------------------------------------------- | ----------------------------------------------------- |
| `prepare <app.pk> <guest.vmexe> <new-dir>`                                    | Aggregation key and `identity.json`                   |
| `write-config <out.json> <app.pk> <guest.vmexe> <prepared> <setup> <segment>` | The configuration below                               |
| `probe`                                                                       | Succeeds only for a CUDA build with a GPU             |
| `check <config.json>`                                                         | Loads and checks every artifact                       |
| `execute <config.json> <input> <journal>`                                     | Runs the guest without proving; checks the journal    |
| `prove <config.json> <input> <journal> <new-seal>`                            | Proves and verifies one round                         |
| `prove-app <config.json> <input> <journal> <new-dir>`                         | Saves a verified application STARK                    |
| `aggregate-stark <config.json> <app-dir> <journal> <new-dir>`                 | Saves a verified aggregate STARK                      |
| `prove-root <config.json> <aggregate-dir> <journal> <new-dir>`                | Saves a verified root STARK                           |
| `compress-root <config.json> <root-dir> <journal> <new-seal>`                 | Verifies and compresses a saved root into an EVM seal |
| `verify <config.json> <proof.json> <journal> <new-seal>`                      | Verifies an existing proof                            |

`prove` reads the guest input items the host wrote, proves the application, aggregates it, generates
the Halo2 EVM proof, and verifies it with the configured EVM verifier against the expected journal
and both application commitments before it writes a seal. There is no fake-proof mode.

### Save and resume completed stages

For long runs, use separate stages instead of `prove`:

```sh
interfold-openvm-prover prove-app CONFIG INPUT JOURNAL NEW_APP_DIR
interfold-openvm-prover aggregate-stark CONFIG NEW_APP_DIR JOURNAL NEW_AGGREGATE_DIR
interfold-openvm-prover prove-root CONFIG NEW_AGGREGATE_DIR JOURNAL NEW_ROOT_DIR
interfold-openvm-prover compress-root CONFIG NEW_ROOT_DIR JOURNAL NEW_SEAL
```

Each stage saves its result only after native verification. A later command checks the saved proof
again against the independently derived application identity and the exact 288-byte journal. File
hashes detect corruption; they never replace proof verification. Only `compress-root` loads the
Halo2 key and KZG parameters, and only its EVM-verified output is a seal. It releases recursive
prover state before loading compression setup.

If a stage fails or is interrupted, restart that stage with a new output path and the last complete
checkpoint. Earlier stages need not run again. This does not resume inside an unfinished stage or
make a successful uninterrupted proof faster. The HTTP service still uses `prove` and keeps jobs in
memory; it does not automatically recover these checkpoints.

Outputs must be new paths with existing parent directories on a filesystem supporting hard links and
directory synchronization. Before proving, the worker checks private file creation, hard-link
publication and synchronization using temporary paths; it never publishes a probe at the final
output path. This detects unsupported or unwritable destinations early, but cannot prevent later
disk exhaustion, storage failures or permission changes. A checkpoint directory contains:

- Application: `app.proof` in the pinned SDK's bitcode format.
- Aggregate: `aggregate.json` in `VersionedVmStarkProof` format and `metadata.bin` in the SDK codec.
- Root: `root.bin` in the SDK codec.
- Each directory: `manifest.json`, published last after synchronizing the files. A directory without
  a complete manifest cannot be resumed. Existing files are never replaced; retain incomplete
  directories for diagnosis and choose a new output path.

The manifest binds format version 1, the exact OpenVM revision, stage, application commitments,
journal SHA-256, application key/executable/aggregation key/verifier hashes, and proof-file hashes.
Default import limits are 4 GiB for application proofs and 256 MiB for aggregate/root proofs.
`OPENVM_CHECKPOINT_MAX_PROOF_BYTES` overrides the proof import limit with a positive decimal byte
count on the receiving host. Manifest and metadata limits remain 64 KiB and 64 bytes. These are
serialized-file limits, not bounds on decoded memory or proving time. Use OS/container memory and
time limits for jobs supplied by others; this CLI does not provide a sandbox or public upload API.

Import limits never discard a locally generated, verified result: the worker saves its complete
checkpoint even when its size exceeds the receiving limit. Increase that limit only on a host with
enough memory to resume. Application proofs larger than 2 GiB occur in real workloads. Checkpoints
consume disk, and incomplete outputs are retained; operators must budget disk space and clean up
unneeded attempts.

Checkpoint members must be regular files. On Unix the worker refuses symlinks and special files,
including FIFOs, and creates directories/files with modes 0700/0600. Keep the directory tree under
operator control. Aggregate JSON and root/metadata encoding stream to disk while hashing; the pinned
bitcode application serializer still needs an in-memory proof buffer.

To move a completed stage to another host, copy the whole checkpoint directory, journal, and
matching artifacts. Paths in the destination config may differ, but artifact bytes and application
identity must match. Halo2 setup stays independently trusted and the final proof must pass the
configured EVM verifier. Keep checkpoints and keys outside Git.

This adds an opt-in local format. Guest computation, circuit parameters, receipt bytes, deployed
verifiers, service APIs and protocol release counters do not change. Existing `prove` and `verify`
commands keep their behavior. An older worker cannot read the new checkpoint directories; rollback
uses its existing `prove` command with the original inputs and artifacts.

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
drain before a live migration. The compute path is unaudited.

## Tests

From the repository root, `pnpm openvm prover-check` checks the independent worker and
`pnpm openvm prover-test` runs stream/seal/probe and checkpoint failure-case tests using the pinned
toolchain and prerequisites above. Root `cargo -p interfold-openvm-prover` cannot select this
workspace. Those tests do not prepare keys or generate receipts. Real execution/proving/contract
acceptance uses the prepared workflows below. [AGENTS.md](AGENTS.md) covers worker/artifact changes.

For a small reproducer from checked-in source, use
[real checkpoint qualification](tests/checkpoints/README.md). It builds a pinned public digest
guest, generates all four stages, relocates checkpoints, resumes from a completed root, runs the
five genuine-proof tests and checks actual contract acceptance. The expensive steps are opt-in and
keep generated artifacts outside tracked source.

## Checks

From the repository root:

```sh
pnpm openvm service-test   # host, types, program server and program runner
```

The CRISP repository, https://github.com/theinterfold/CRISP, owns the live OpenVM round test for the
CRISP program. Keep reports, inputs, keys and proofs out of the repository.

Three ignored tests reverify independently generated native proofs. `OPENVM_APP_FIXTURE` names a
directory containing `app.pk`, `guest.vmexe`, `app.proof` and `journal.bin` (288 bytes).
`OPENVM_AGGREGATE_FIXTURE` names one containing `config.json`, `aggregate.json` and `journal.bin`.
`OPENVM_ROOT_FIXTURE` names one containing `config.json`, `root.bin` and `journal.bin`, with the
configuration pointing at matching prepared artifacts. These tests do not generate a new receipt or
load Halo2 keys. Run each explicitly on a host with sufficient free resources:

```sh
OPENVM_APP_FIXTURE=/absolute/app-fixture \
  pnpm openvm prover-test real_application_checkpoint -- --ignored --test-threads=1
OPENVM_AGGREGATE_FIXTURE=/absolute/aggregate-fixture \
  pnpm openvm prover-test real_aggregate_checkpoint -- --ignored --test-threads=1
OPENVM_ROOT_FIXTURE=/absolute/root-fixture \
  pnpm openvm prover-test real_root_checkpoint -- --ignored --test-threads=1
```

A complete qualification also runs all four commands in separate processes and verifies the final
seal through the prepared contract flow. Native proof tests and unit tests do not establish that
Halo2 compression fits a particular machine or that CUDA has been exercised.

The separate `real_evm_receipt` ignored test accepts `OPENVM_EVM_FIXTURE` containing `config.json`,
`proof.json`, `journal.bin` and the expected `seal.bin`. It verifies a genuine receipt with the
configured EVM verifier, requires byte-identical seal encoding, and rejects a changed proof,
journal, application identity and verifier digest. It does not generate a new Halo2 proof:

```sh
OPENVM_EVM_FIXTURE=/absolute/evm-fixture \
  pnpm openvm prover-test real_evm_receipt -- --ignored --test-threads=1
```

The lightweight `real_checkpoint_encodings` ignored test checks the streaming aggregate/root formats
against independently generated fixtures without constructing a prover or loading Halo2. It needs
both fixture directories above, with `metadata.bin` also present in the aggregate directory. It
checks format compatibility, file integrity, and early rejection of an unrelated journal, not native
proof validity:

```sh
OPENVM_AGGREGATE_FIXTURE=/absolute/aggregate-fixture \
OPENVM_ROOT_FIXTURE=/absolute/root-fixture \
  pnpm openvm prover-test real_checkpoint_encodings -- --ignored --test-threads=1
```
