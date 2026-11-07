# e3-zk-prover

## Purpose

Noir witness/proof execution, verification, recursive folding, and artifact installation for
ciphernode protocol proofs. This is separate from the
[OpenVM computation worker](../../openvm-prover/README.md). Static bounds/layouts belong in
[e3-zk-config](../config/README.md), and production input preparation/encoding belongs in
[e3-zk-witness](../witness/README.md).

Import circuit identities/variants from `e3-zk-config`; this crate's re-exports do not define a
second owner. The node's [jobs](../../ciphernode/jobs/) call this library to prove and verify.

## Map

| Location                                                                     | Responsibility                                                                                  |
| ---------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------- |
| [`backend/`](src/backend), [`config.rs`](src/config.rs)                      | Version/checksum admission, downloads, transactional artifact installation, and backend status. |
| [`witness.rs`](src/witness.rs), [`prover.rs`](src/prover.rs)                 | Noir execution and bounded/deadlined Barretenberg subprocesses.                                 |
| [`circuits/`](src/circuits), [`traits.rs`](src/traits.rs)                    | Each circuit's `Provable` preparation, and the recursive folds under `circuits/aggregation/`.   |
| [`proof.rs`](src/proof.rs), [`node_fold_public.rs`](src/node_fold_public.rs) | The `Proof` that proving returns, and the node fold's aggregated commitments.                   |
| [`tests/`](tests)                                                            | Prepared local, recursive-fold, and network/download suites.                                    |

## Backend and public API

`ZkBackend::new(bb_path, circuits_dir, work_dir)` takes this crate's `BBPath` and artifact/work
paths. `BBPath::Default` selects a managed, version-checked binary; `Custom` retains an
operator-managed binary. Application composition translates resolved paths and the custom-binary
setting into this backend-owned choice. `check_status().await` reports setup state;
`ensure_installed().await` prepares required tools/artifacts and may download/install them.
Version/checksum requirements come from [versions.json](versions.json). `with_bb_timeout` bounds
each proving process.

`ZkProver::new(&backend)` executes proof generation and verification. Select the matching artifact
directory with `resolve_artifacts_dir(preset, committee)` and use the explicit variant methods where
needed. Verification returns `Result<bool, ZkError>`: infrastructure failure is distinct from
completed invalid verification. `CompiledCircuit`, `WitnessGenerator`, and `input_map` expose
compiled-circuit loading and witness generation (using `noirc_abi::InputMap`) without defining
another circuit parameter table.

`Provable::Config` carries each circuit's concrete configuration into preparation. The node's jobs
build it from their BFV parameter owner; C6/C7 reuse it across ciphertext indices. User encryption
prepares from one exact ciphertext and its encryption intermediates, not a second encryption.

## Before running Cargo

`build.rs` runs `scripts/build_fixtures.sh` even for checks. With nargo and required artifacts
available, it compiles the dummy Noir fixture and rewrites tracked fixture JSON using jq. If
required circuit artifacts are absent and bb is available, it can run
`pnpm install --frozen-lockfile` and `pnpm build:circuits` in a separate target directory. Missing
nargo/bb can skip preparation; a successful Cargo command does not establish matching artifacts.

For **compile-only** work:

```sh
E3_ZK_PROVER_SKIP_FIXTURE_BUILD=1 cargo check --locked -p e3-zk-prover --tests
```

This skips fixture preparation only. It neither skips proof tests nor supplies valid artifacts.

## Tests

`cargo test --locked -p e3-zk-prover --lib` runs native/unit suites after the preparation above.
Backend tests cover local archives/install rollback; prover tests use fake processes for
timeout/error classification; witness tests execute the dummy compiled circuit. These have different
external requirements from the explicitly selected real-proof suites below.

### Real-proof tests

Prepare pinned nargo and bb, jq, pnpm/workspace dependencies, and circuits/VKs matching the active
preset and committee through the
[circuit build guide](../../../scripts/circuits/README.md#circuit-builder). Then use root
`pnpm rust:test:proofs` for the explicitly selected ignored proof suites. The `integration-tests`
feature gates the separate network/download integration target; enabling it alone is not evidence of
proof execution. Placeholder proofs in test runs are never a production fallback.

See [proof statements](../../../docs/architecture/proof-statements.md) and
[artifact compatibility](../../../docs/architecture/circuit-artifacts.md) for required cross-layer
acceptance. Witness generation, process success, checksum matching, and verified statements are
different results. See [AGENTS.md](AGENTS.md) for proof-plan, verification-outcome, and artifact
change rules.
