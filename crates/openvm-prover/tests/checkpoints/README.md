# Real checkpoint qualification

This opt-in CPU workflow builds a small public digest guest and generates fresh proofs. It tests the
worker's proof, journal, identity and checkpoint boundaries, not FHE auction logic. No proofs, keys
or prepared artifacts belong in Git. Run each phase in a separate process; `root` ends at a
completed checkpoint and `compress` starts from its relocated copy.

## Prerequisites

Use [the worker's pinned prerequisites](../../README.md#prerequisites): Rust 1.91.1, `cargo-openvm`
v2.0.2 and its `nightly-2026-01-18` guest toolchain with `rust-src`, and an existing, independently
trusted setup containing `halo2.pk`, `params/` and `halo2/src/v2.0-base/verifier.bytecode.json`.
This workflow does not download or establish trust in compression setup. It requires Python 3.9+ and
a filesystem supporting hard links and directory synchronization. The `--out` parent must exist and
`--out` itself must be new.

Budget at least 32 GiB RAM for compression and sufficient disk for compiler outputs and setup. The
earlier small-guest run took roughly 12 minutes for proving after setup/builds and sampled 25.6 GiB
compression process-group RSS. These are observations, not resource limits or speedup claims. Use a
separate machine when other proofs need the local machine's resources.

## Build and test

From the repository root, with Rust 1.91.1 selected, first run the same default profile and test
concurrency as the CPU CI job:

```sh
cargo test --locked --manifest-path crates/openvm-prover/Cargo.toml
pnpm openvm prover-build
```

Then choose absolute paths. Keep `CARGO_TARGET_DIR` consistent with the release build so the fixture
tests reuse it. The output can live under the repository's ignored `target/` directory or outside
the checkout.

```sh
export CARGO_TARGET_DIR="$PWD/target/openvm/prover"
checkpoint_worker="$CARGO_TARGET_DIR/release/interfold-openvm-prover"
checkpoint_output="$PWD/target/openvm/checkpoint-qualification"
checkpoint_setup="$HOME/.openvm"

python3 crates/openvm-prover/tests/checkpoints/run.py prepare \
  --worker "$checkpoint_worker" --out "$checkpoint_output" --setup "$checkpoint_setup"
python3 crates/openvm-prover/tests/checkpoints/run.py root \
  --worker "$checkpoint_worker" --out "$checkpoint_output"
```

`prepare` copies the checked-in guest source/lockfile to the output directory, builds it with
`OPENVM_BUILD_LOCKED=1`, prepares keys/configuration, and checks execution parity. `root` generates
the application, aggregate and root proofs in separate worker processes. It copies the application
and root checkpoints plus their matching artifacts to new directories and uses the relocated
configuration. The native verifiers authenticate each imported proof; copy checksums alone are not
proof verification.

End that process/session after `root` completes, then resume in a fresh process:

```sh
python3 crates/openvm-prover/tests/checkpoints/run.py compress \
  --worker "$checkpoint_worker" --out "$checkpoint_output"
python3 crates/openvm-prover/tests/checkpoints/run.py verify \
  --worker "$checkpoint_worker" --out "$checkpoint_output"
```

`compress` publishes the EVM-verified seal from the relocated root. `verify` runs another worker's
verification, requires identical seal bytes, and explicitly invokes all five ignored genuine-proof
tests, including their corruption/journal/identity rejection cases. The receipt JSON is
reconstructed from the existing pinned seal encoding, then cryptographically verified. There is no
mock receipt. The phases intentionally require fresh output paths; after a partially failed phase,
keep the outputs for diagnosis and use a new qualification directory or resume the last complete
checkpoint with the documented worker commands.

This tests a planned stop at a complete root and movement between directories. It does not test an
abrupt power cut, automatic HTTP recovery or two physical proving machines.

## Actual contract acceptance

Install the repository's Node dependencies with `pnpm install --frozen-lockfile`, using a Node
version supported by Hardhat 3 and the pnpm version pinned in the root package configuration. This
focused test uses the existing Hardhat local network and deployment helper, deploys the prepared
Halo2 bytecode and unchanged receipt adapter, accepts the fresh seal, and rejects changed
proof/journal/image/executable inputs:

```sh
OPENVM_CHECKPOINT_FIXTURE="$checkpoint_output/evm" \
  pnpm --filter @interfold/contracts test --network hardhat \
  test/Deployment/OpenVmCheckpoint.spec.ts
```

Without that environment variable the suite is skipped. With it, missing files or invalid proofs
fail the test. It does not submit transactions to a public chain or run a prover.

## CUDA qualification

The CPU workflow above does not establish CUDA compatibility. On a host with the supported CUDA
toolkit/driver and NVIDIA GPU, compile separately and check the device:

```sh
CARGO_TARGET_DIR=target/openvm/prover-cuda \
  cargo build --locked --release --manifest-path crates/openvm-prover/Cargo.toml --features cuda
target/openvm/prover-cuda/release/interfold-openvm-prover probe
```

Run the genuine-fixture tests with that feature and its separate target directory before claiming
GPU checkpoint verification. A successful build alone is not a CUDA runtime or cross-backend proof
test. AMD graphics cards cannot run this CUDA backend.
