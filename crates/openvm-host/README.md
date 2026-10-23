# e3-openvm-host

## Purpose

Native adapter for proving an E3 program's Secure Process through a separate OpenVM worker. It
computes the result/journal natively, writes guest input, then requires the worker to prove and
verify the expected journal before accepting the seal. The OpenVM SDK lives in the
[independent worker workspace](../openvm-prover/README.md), not this crate.

## Map and proving lifecycle

[`src/lib.rs`](src/lib.rs) contains the host adapter: `WorkerConfig` resolves paths/deadlines,
backend selection probes CUDA, `Prover` checks artifacts and manages job processes, and native
execution writes the input stream/journal. `encode_compute_proof` builds the Solidity envelope.

Startup selects/checks a worker. Each job runs the Secure Process natively, records the expected
journal and two-pass inputs, invokes the worker with a deadline, then reads its verified seal. Job
directories are temporary; they are not a durable accepted-work queue.

## Configure a worker

`WorkerConfig::from_env()` reads existing absolute paths:

- `OPENVM_PROVER_BIN`: CPU worker;
- `OPENVM_PROVER_BIN_CUDA`: optional CUDA worker;
- `OPENVM_PROVER_CONFIG`: required worker/artifact configuration.

At least one worker is required. `OPENVM_BACKEND=auto|cpu|cuda` selects execution: `auto` probes
configured CUDA and may fall back to CPU; explicit `cuda` fails if unavailable.
`OPENVM_CHECK_TIMEOUT_SECS` and `OPENVM_PROVE_TIMEOUT_SECS` bound artifact checks and proving
(defaults: 30 minutes and 24 hours). Prepare pinned tooling, guest artifacts, and keys through the
[worker setup guide](../openvm-prover/README.md) before starting.

## Prove a computation

`Prover::start(config).await` selects/checks the worker and artifacts before accepting jobs.
`prove(inputs, published, domain, processor, policy).await` returns `(proof_envelope, ciphertext)`
bytes. Use the same processor/policy in native and guest execution. `ComputeDomain` binds chain,
verifying contract, E3, encryption scheme, and committee key; it is not optional metadata. The
[project service](../program-runner/src/openvm.rs) is a complete caller.

The worker must verify against the expected `ComputeJournal`; exit success alone is not a receipt
contract. `encode_compute_proof` constructs the Solidity envelope and checks seal length.
Deadlines/cancellation stop the worker process group on Unix rather than leaving a proving child
behind. Resource failures never select a mock proof.

## Tests

Run `cargo test --locked -p e3-openvm-host`. Inline fake-worker tests cover backend selection,
envelope bytes, deadlines, and wrapper-child cleanup without preparing OpenVM keys. Real host/guest
parity and proof acceptance are separate [OpenVM workflows](../openvm-prover/README.md). See
[AGENTS.md](AGENTS.md) for process/verification change rules.
